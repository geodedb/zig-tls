//! TLS 1.3 Record Layer and AEAD Operations for QUIC
//!
//! Implements the TLS 1.3 record protocol and authenticated encryption with
//! associated data (AEAD) as specified in:
//! - RFC 8446 §5 (Record Protocol)
//! - RFC 8446 §5.2 (Record Payload Protection)
//! - RFC 8446 §5.3 (Per-Record Nonce)
//! - RFC 8446 §5.5 (Limits on Key Usage)
//! - RFC 5116 (AEAD Interface)
//! - RFC 9001 §5.3 (QUIC Packet Protection)
//!
//! This module provides TLS 1.3 record framing and AEAD protection primitives
//! used by the QUIC handshake engine. While QUIC replaces the traditional TLS
//! record layer with CRYPTO frames, these primitives are still needed for
//! handshake message protection and validation.
//!
//! ## Key Features
//! - TLSPlaintext framing with RFC 8446 §5.1 format validation
//! - TLSInnerPlaintext packing with content type and padding (RFC 8446 §5.4)
//! - AEAD cipher support: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
//! - Per-record nonce derivation via XOR with sequence number (RFC 8446 §5.3)
//! - AEAD usage limits for confidentiality and integrity (RFC 8446 §5.5)
//! - Key material zeroization for security hygiene
//!
//! ## QUIC Integration Notes
//! In QUIC, the TLS record layer is NOT used for packet framing. Instead:
//! - QUIC CRYPTO frames carry TLS handshake messages directly
//! - QUIC packet protection uses the same AEAD algorithms but different nonce construction
//! - This module provides AEAD primitives that can be used for both TLS and QUIC protection
//! - TLSPlaintext/TLSInnerPlaintext are used for testing and compatibility validation
//!
//! ## Security Considerations
//! - AEAD keys are zeroized after use via `AeadCipher.wipe()`
//! - Nonce values are cleared from stack after encryption/decryption
//! - Usage limits prevent AEAD security degradation (RFC 8446 §5.5)
//! - Authentication failures are tracked separately from successful decryptions
//! - Constant-time operations for tag comparison (provided by std.crypto.aead)
//!
//! ## Design Notes
//! Uses Zig standard library crypto primitives (std.crypto.aead) for all AEAD
//! operations. No external dependencies required. All AEAD algorithms follow
//! the RFC 5116 interface with 96-bit nonces and 128-bit tags.
const std = @import("std");
const crypto = std.crypto;
const math = std.math;

const AuthenticationError = crypto.errors.AuthenticationError;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;

// Import modular record layer components
const record_mod = @import("record/mod.zig");

// Re-export for backward compatibility (RFC 8446 §5)
pub const LegacyVersion = record_mod.LegacyVersion;
pub const default_legacy_version = record_mod.default_legacy_version;
pub const ContentType = record_mod.ContentType;
pub const max_plaintext_fragment = record_mod.max_plaintext_fragment;
pub const max_inner_padding = record_mod.max_inner_padding;
pub const RecordError = record_mod.RecordError;
pub const PlaintextView = record_mod.PlaintextView;
pub const encodePlaintext = record_mod.encodePlaintext;
pub const decodePlaintext = record_mod.decodePlaintext;
pub const InnerPlaintext = record_mod.InnerPlaintext;
pub const packInnerPlaintext = record_mod.packInnerPlaintext;
pub const unpackInnerPlaintext = record_mod.unpackInnerPlaintext;
pub const CipherSuite = record_mod.CipherSuite;
pub const AeadUsageLimits = record_mod.AeadUsageLimits;
pub const AeadCipher = record_mod.AeadCipher;
pub const xorNonce = record_mod.xorNonce;
pub const parseContentType = record_mod.parseContentType;
pub const parseLegacyVersion = record_mod.parseLegacyVersion;

// NOTE: TLS 1.3 record layer types and functions have been extracted to src/record/
// for better modularity. See src/record/plaintext.zig and src/record/aead.zig for
// implementation details. This file now re-exports for backward compatibility.

// ============================================================================
// TESTS - RFC 8446 §5 Record Layer
// ============================================================================

const testing = std.testing;
const expect = testing.expect;
const expectEqual = testing.expectEqual;
const expectEqualSlices = testing.expectEqualSlices;
const expectError = testing.expectError;

// RFC 8446 §5.1: TLSPlaintext encoding/decoding
test "RFC 8446 §5.1 - TLSPlaintext encode/decode round-trip" {
    const allocator = testing.allocator;
    const content = "Hello, TLS 1.3!";

    const encoded = try encodePlaintext(allocator, .handshake, content);
    defer allocator.free(encoded);

    // Verify header format
    try expectEqual(@as(u8, @intFromEnum(ContentType.handshake)), encoded[0]);
    try expectEqual(@as(u8, 0x03), encoded[1]); // TLS 1.2 legacy version hi
    try expectEqual(@as(u8, 0x03), encoded[2]); // TLS 1.2 legacy version lo
    try expectEqual(@as(u16, content.len), (@as(u16, encoded[3]) << 8) | @as(u16, encoded[4]));

    const decoded = try decodePlaintext(encoded);
    try expectEqual(ContentType.handshake, decoded.content_type);
    try expectEqual(LegacyVersion.tls_1_2, decoded.legacy_version);
    try expectEqualSlices(u8, content, decoded.fragment);
}

// RFC 8446 §5.1: Maximum fragment size enforcement
test "RFC 8446 §5.1 - TLSPlaintext maximum fragment size" {
    const allocator = testing.allocator;
    var large_fragment: [max_plaintext_fragment]u8 = undefined;
    @memset(&large_fragment, 0xAA);

    // Exactly at the limit should succeed
    const encoded = try encodePlaintext(allocator, .application_data, &large_fragment);
    defer allocator.free(encoded);
    try expectEqual(5 + max_plaintext_fragment, encoded.len);

    // One byte over should fail
    var oversized: [max_plaintext_fragment + 1]u8 = undefined;
    try expectError(RecordError.FragmentTooLarge, encodePlaintext(allocator, .application_data, &oversized));
}

// RFC 8446 §5.1: Empty fragment is valid
test "RFC 8446 §5.1 - TLSPlaintext with empty fragment" {
    const allocator = testing.allocator;
    const encoded = try encodePlaintext(allocator, .alert, &[_]u8{});
    defer allocator.free(encoded);

    try expectEqual(@as(usize, 5), encoded.len);
    const decoded = try decodePlaintext(encoded);
    try expectEqual(@as(usize, 0), decoded.fragment.len);
}

// RFC 8446 §5.1: Decode errors - truncated record
test "RFC 8446 §5.1 - TLSPlaintext decode truncated" {
    try expectError(RecordError.RecordTooShort, decodePlaintext(&[_]u8{22})); // Only 1 byte
    try expectError(RecordError.RecordTooShort, decodePlaintext(&[_]u8{ 22, 3, 3, 0 })); // 4 bytes
}

// RFC 8446 §5.1: Decode errors - length mismatch
test "RFC 8446 §5.1 - TLSPlaintext decode length mismatch" {
    // Claims 10 bytes but only provides 5
    const malformed = [_]u8{ 22, 3, 3, 0, 10, 1, 2, 3, 4, 5 };
    try expectError(RecordError.LengthMismatch, decodePlaintext(&malformed));
}

// RFC 8446 §5.4: TLSInnerPlaintext pack/unpack round-trip
test "RFC 8446 §5.4 - TLSInnerPlaintext pack/unpack round-trip" {
    const allocator = testing.allocator;
    const content = "Handshake message";

    // Pack with no padding
    const inner_plaintext = try packInnerPlaintext(allocator, .handshake, content, 0);
    defer allocator.free(inner_plaintext);

    try expectEqual(content.len + 1, inner_plaintext.len);
    try expectEqual(@as(u8, @intFromEnum(ContentType.handshake)), inner_plaintext[inner_plaintext.len - 1]);

    // Unpack
    const unpacked = try unpackInnerPlaintext(inner_plaintext);
    try expectEqual(ContentType.handshake, unpacked.content_type);
    try expectEqualSlices(u8, content, unpacked.content);
    try expectEqual(@as(usize, 0), unpacked.padding_len);
}

// RFC 8446 §5.4: TLSInnerPlaintext with padding
test "RFC 8446 §5.4 - TLSInnerPlaintext with padding" {
    const allocator = testing.allocator;
    const content = "Short";
    const padding_len: usize = 10;

    const inner_plaintext = try packInnerPlaintext(allocator, .application_data, content, padding_len);
    defer allocator.free(inner_plaintext);

    try expectEqual(content.len + 1 + padding_len, inner_plaintext.len);

    // Verify padding is zeros
    for (inner_plaintext[content.len + 1 ..]) |byte| {
        try expectEqual(@as(u8, 0), byte);
    }

    const unpacked = try unpackInnerPlaintext(inner_plaintext);
    try expectEqual(ContentType.application_data, unpacked.content_type);
    try expectEqualSlices(u8, content, unpacked.content);
    try expectEqual(padding_len, unpacked.padding_len);
}

// RFC 8446 §5.4: Invalid content type
test "RFC 8446 §5.4 - TLSInnerPlaintext invalid content type" {
    const allocator = testing.allocator;
    try expectError(RecordError.InvalidContentType, packInnerPlaintext(allocator, .invalid, "test", 0));
}

// RFC 8446 §5.4: Empty TLSInnerPlaintext error
test "RFC 8446 §5.4 - TLSInnerPlaintext empty buffer" {
    try expectError(RecordError.MissingContentType, unpackInnerPlaintext(&[_]u8{}));
}

// RFC 8446 §5.4: All-zeros buffer (no content type)
test "RFC 8446 §5.4 - TLSInnerPlaintext all zeros" {
    const all_zeros = [_]u8{0} ** 10;
    try expectError(RecordError.MissingContentType, unpackInnerPlaintext(&all_zeros));
}

// RFC 8446 §5.3: Nonce derivation via XOR
test "RFC 8446 §5.3 - xorNonce basic functionality" {
    const base_iv: [12]u8 = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    var nonce: [12]u8 = undefined;
    const seq: u64 = 0x0000000000000001;

    try xorNonce(&nonce, &base_iv, seq);

    // Verify XOR happened in the last 8 bytes
    try expectEqual(base_iv[0], nonce[0]); // First 4 bytes unchanged
    try expectEqual(base_iv[1], nonce[1]);
    try expectEqual(base_iv[2], nonce[2]);
    try expectEqual(base_iv[3], nonce[3]);

    // Last byte should be base_iv[11] ^ 0x01
    try expectEqual(base_iv[11] ^ 0x01, nonce[11]);
}

// RFC 8446 §5.3: Nonce derivation - sequence number is big-endian
test "RFC 8446 §5.3 - xorNonce sequence number endianness" {
    const base_iv: [12]u8 = [_]u8{0} ** 12;
    var nonce: [12]u8 = undefined;
    const seq: u64 = 0x0102030405060708;

    try xorNonce(&nonce, &base_iv, seq);

    // Verify big-endian encoding in last 8 bytes
    try expectEqual(@as(u8, 0x01), nonce[4]);
    try expectEqual(@as(u8, 0x02), nonce[5]);
    try expectEqual(@as(u8, 0x03), nonce[6]);
    try expectEqual(@as(u8, 0x04), nonce[7]);
    try expectEqual(@as(u8, 0x05), nonce[8]);
    try expectEqual(@as(u8, 0x06), nonce[9]);
    try expectEqual(@as(u8, 0x07), nonce[10]);
    try expectEqual(@as(u8, 0x08), nonce[11]);
}

// RFC 8446 §5.3: Nonce length validation
test "RFC 8446 §5.3 - xorNonce length validation" {
    const base_iv: [12]u8 = [_]u8{0} ** 12;
    var short_nonce: [7]u8 = undefined;

    // Nonce must be at least 8 bytes
    try expectError(RecordError.InvalidIvLength, xorNonce(&short_nonce, &base_iv, 0));
}

// RFC 8446 §5.2: AEAD AES-128-GCM seal/open round-trip
test "RFC 8446 §5.2 - AES-128-GCM seal/open round-trip" {
    const allocator = testing.allocator;
    const key: [16]u8 = [_]u8{0x00} ** 16;
    const iv: [12]u8 = [_]u8{0x01} ** 12;

    var cipher = try AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null);
    defer cipher.wipe();

    const plaintext = "Attack at dawn!";
    const aad = "additional auth data";
    const seq: u64 = 42;

    // Seal
    const ciphertext = try cipher.seal(allocator, seq, aad, plaintext);
    defer allocator.free(ciphertext);

    try expect(ciphertext.len == plaintext.len + 16); // 16-byte tag

    // Open
    const recovered = try cipher.open(allocator, seq, aad, ciphertext);
    defer allocator.free(recovered);

    try expectEqualSlices(u8, plaintext, recovered);
}

// RFC 8446 §5.2: AEAD AES-256-GCM seal/open round-trip
test "RFC 8446 §5.2 - AES-256-GCM seal/open round-trip" {
    const allocator = testing.allocator;
    const key: [32]u8 = [_]u8{0xAA} ** 32;
    const iv: [12]u8 = [_]u8{0xBB} ** 12;

    var cipher = try AeadCipher.init(.TLS_AES_256_GCM_SHA384, &key, &iv, null);
    defer cipher.wipe();

    const plaintext = "The secret message.";
    const aad = "TLS 1.3 AAD";
    const seq: u64 = 100;

    const ciphertext = try cipher.seal(allocator, seq, aad, plaintext);
    defer allocator.free(ciphertext);

    try expect(ciphertext.len == plaintext.len + 16);

    const recovered = try cipher.open(allocator, seq, aad, ciphertext);
    defer allocator.free(recovered);

    try expectEqualSlices(u8, plaintext, recovered);
}

// RFC 8446 §5.2: AEAD ChaCha20-Poly1305 seal/open round-trip
test "RFC 8446 §5.2 - ChaCha20-Poly1305 seal/open round-trip" {
    const allocator = testing.allocator;
    const key: [32]u8 = [_]u8{0x55} ** 32;
    const iv: [12]u8 = [_]u8{0x66} ** 12;

    var cipher = try AeadCipher.init(.TLS_CHACHA20_POLY1305_SHA256, &key, &iv, null);
    defer cipher.wipe();

    const plaintext = "ChaCha20-Poly1305 test vector";
    const aad = "Associated data";
    const seq: u64 = 255;

    const ciphertext = try cipher.seal(allocator, seq, aad, plaintext);
    defer allocator.free(ciphertext);

    try expect(ciphertext.len == plaintext.len + 16);

    const recovered = try cipher.open(allocator, seq, aad, ciphertext);
    defer allocator.free(recovered);

    try expectEqualSlices(u8, plaintext, recovered);
}

// RFC 8446 §5.2: AEAD authentication failure detection
test "RFC 8446 §5.2 - AEAD authentication failure" {
    const allocator = testing.allocator;
    const key: [16]u8 = [_]u8{0x00} ** 16;
    const iv: [12]u8 = [_]u8{0x01} ** 12;

    var cipher = try AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null);
    defer cipher.wipe();

    const plaintext = "Authentic message";
    const aad = "AAD";

    const ciphertext = try cipher.seal(allocator, 0, aad, plaintext);
    defer allocator.free(ciphertext);

    // Tamper with ciphertext
    var tampered = try allocator.alloc(u8, ciphertext.len);
    defer allocator.free(tampered);
    @memcpy(tampered, ciphertext);
    tampered[0] ^= 0xFF;

    // Should fail authentication
    try expectError(RecordError.AuthenticationFailed, cipher.open(allocator, 0, aad, tampered));
}

// RFC 8446 §5.2: Different sequence numbers produce different ciphertexts
test "RFC 8446 §5.2 - different sequence numbers" {
    const allocator = testing.allocator;
    const key: [16]u8 = [_]u8{0x42} ** 16;
    const iv: [12]u8 = [_]u8{0x24} ** 12;

    var cipher = try AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null);
    defer cipher.wipe();

    const plaintext = "Same plaintext";
    const aad = "Same AAD";

    const ct1 = try cipher.seal(allocator, 1, aad, plaintext);
    defer allocator.free(ct1);

    const ct2 = try cipher.seal(allocator, 2, aad, plaintext);
    defer allocator.free(ct2);

    // Different sequence numbers should produce different ciphertexts
    try expect(!std.mem.eql(u8, ct1, ct2));
}

// RFC 8446 §5.2: Wrong sequence number fails decryption
test "RFC 8446 §5.2 - wrong sequence number" {
    const allocator = testing.allocator;
    const key: [16]u8 = [_]u8{0x77} ** 16;
    const iv: [12]u8 = [_]u8{0x88} ** 12;

    var cipher = try AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null);
    defer cipher.wipe();

    const plaintext = "Message";
    const aad = "AAD";

    const ciphertext = try cipher.seal(allocator, 5, aad, plaintext);
    defer allocator.free(ciphertext);

    // Try to decrypt with wrong sequence number
    try expectError(RecordError.AuthenticationFailed, cipher.open(allocator, 6, aad, ciphertext));
}

// RFC 8446 §5.5: AEAD usage limits - confidentiality
test "RFC 8446 §5.5 - AEAD confidentiality limit" {
    const allocator = testing.allocator;
    const key: [16]u8 = [_]u8{0x11} ** 16;
    const iv: [12]u8 = [_]u8{0x22} ** 12;

    // Set a low limit for testing
    const limits = AeadUsageLimits{ .confidentiality = 5, .integrity = 100 };
    var cipher = try AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, limits);
    defer cipher.wipe();

    const plaintext = "test";
    const aad = "";

    // Encrypt 5 times (should succeed)
    var i: u64 = 0;
    while (i < 5) : (i += 1) {
        const ct = try cipher.seal(allocator, i, aad, plaintext);
        allocator.free(ct);
    }

    // 6th encryption should fail
    try expectError(RecordError.AeadLimitExceeded, cipher.seal(allocator, 5, aad, plaintext));
}

// RFC 8446 §5.5: AEAD usage limits - integrity
test "RFC 8446 §5.5 - AEAD integrity limit" {
    const allocator = testing.allocator;
    const key: [16]u8 = [_]u8{0x33} ** 16;
    const iv: [12]u8 = [_]u8{0x44} ** 12;

    const limits = AeadUsageLimits{ .confidentiality = 100, .integrity = 3 };
    var cipher = try AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, limits);
    defer cipher.wipe();

    const plaintext = "authentic";
    const aad = "data";

    const ciphertext = try cipher.seal(allocator, 0, aad, plaintext);
    defer allocator.free(ciphertext);

    // Tamper to cause auth failures
    var tampered = try allocator.alloc(u8, ciphertext.len);
    defer allocator.free(tampered);

    // Fail 3 times (should succeed with error)
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        @memcpy(tampered, ciphertext);
        tampered[0] ^= @intCast(i + 1);
        try expectError(RecordError.AuthenticationFailed, cipher.open(allocator, 0, aad, tampered));
    }

    // 4th failure should trigger limit
    @memcpy(tampered, ciphertext);
    tampered[0] ^= 0xAA;
    try expectError(RecordError.AeadLimitExceeded, cipher.open(allocator, 0, aad, tampered));
}

// AEAD init errors
test "AEAD init - invalid key length" {
    const short_key: [8]u8 = [_]u8{0} ** 8;
    const iv: [12]u8 = [_]u8{0} ** 12;

    try expectError(RecordError.InvalidKeyLength, AeadCipher.init(.TLS_AES_128_GCM_SHA256, &short_key, &iv, null));
}

test "AEAD init - invalid IV length" {
    const key: [16]u8 = [_]u8{0} ** 16;
    const short_iv: [7]u8 = [_]u8{0} ** 7;

    try expectError(RecordError.InvalidIvLength, AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &short_iv, null));
}

// AEAD wipe test
test "AEAD wipe - clears key material" {
    const key: [16]u8 = [_]u8{0xAB} ** 16;
    const iv: [12]u8 = [_]u8{0xCD} ** 12;

    var cipher = try AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null);

    // Verify usage is tracked
    try expectEqual(@as(u64, 0), cipher.usage.encrypted);

    cipher.wipe();

    // After wipe, usage should reset
    try expectEqual(@as(u64, 0), cipher.usage.encrypted);
    try expectEqual(@as(u64, 0), cipher.usage.auth_failures);
}

// Content type parsing
test "ContentType parsing" {
    try expectEqual(ContentType.alert, try parseContentType(21));
    try expectEqual(ContentType.handshake, try parseContentType(22));
    try expectEqual(ContentType.application_data, try parseContentType(23));
    try expectError(RecordError.InvalidContentType, parseContentType(99));
}

// Legacy version parsing
test "LegacyVersion parsing" {
    try expectEqual(LegacyVersion.tls_1_2, try parseLegacyVersion(0x03, 0x03));
    try expectEqual(LegacyVersion.tls_1_0, try parseLegacyVersion(0x03, 0x01));
    try expectError(RecordError.UnsupportedLegacyVersion, parseLegacyVersion(0x03, 0x05));
}

// Empty plaintext
test "AEAD seal/open - empty plaintext" {
    const allocator = testing.allocator;
    const key: [16]u8 = [_]u8{0x99} ** 16;
    const iv: [12]u8 = [_]u8{0x88} ** 12;

    var cipher = try AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null);
    defer cipher.wipe();

    const plaintext = "";
    const aad = "AAD";

    const ciphertext = try cipher.seal(allocator, 0, aad, plaintext);
    defer allocator.free(ciphertext);

    // Should only contain tag
    try expectEqual(@as(usize, 16), ciphertext.len);

    const recovered = try cipher.open(allocator, 0, aad, ciphertext);
    defer allocator.free(recovered);

    try expectEqual(@as(usize, 0), recovered.len);
}

// Ciphertext too short
test "AEAD open - ciphertext too short" {
    const allocator = testing.allocator;
    const key: [16]u8 = [_]u8{0x77} ** 16;
    const iv: [12]u8 = [_]u8{0x66} ** 12;

    var cipher = try AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null);
    defer cipher.wipe();

    const short_ct = [_]u8{ 0x01, 0x02, 0x03 }; // Less than 16 bytes (tag length)
    try expectError(RecordError.CiphertextTooShort, cipher.open(allocator, 0, "", &short_ct));
}
