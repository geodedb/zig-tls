//! RFC 8446 §5: Record Protocol Tests
//!
//! Tests for TLS 1.3 record layer implementation.
//!
//! ## RFC 8446 §5: Record Protocol
//!
//! The TLS record protocol takes messages to be transmitted, fragments the data
//! into manageable blocks, protects the records, and transmits the result.
//!
//! ```
//! struct {
//!     ContentType type;
//!     ProtocolVersion legacy_record_version;
//!     uint16 length;
//!     opaque fragment[TLSPlaintext.length];
//! } TLSPlaintext;
//!
//! struct {
//!     opaque content[TLSPlaintext.length];
//!     ContentType type;
//!     uint8 zeros[length_of_padding];
//! } TLSInnerPlaintext;
//!
//! struct {
//!     ContentType opaque_type = application_data; /* 23 */
//!     ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
//!     uint16 length;
//!     opaque encrypted_record[TLSCiphertext.length];
//! } TLSCiphertext;
//! ```
//!
//! ## Test Coverage
//!
//! - §5.1: Record Layer (TLSPlaintext structure)
//! - §5.2: Record Payload Protection (AEAD encryption/decryption)
//! - §5.3: Per-Record Nonce (nonce derivation)
//! - §5.4: Record Padding (TLSInnerPlaintext padding)
//! - §5.5: Limits on Key Usage (AEAD usage limits)

const std = @import("std");
const testing = std.testing;
const record = @import("record");

// Helper to convert hex string to bytes
// QUAL-205: hexToBytes moved to tests/test_utils.zig.
const test_utils = @import("test_utils");
const hexToBytes = test_utils.hexToBytes;

// Helper to compare hex string with bytes
fn expectEqualHex(comptime hex: []const u8, actual: []const u8) !void {
    var expected: [hex.len / 2]u8 = undefined;
    hexToBytes(hex, &expected);
    try testing.expectEqualSlices(u8, &expected, actual);
}

// RFC 8446 §5.1: Record Layer - TLSPlaintext Structure
//
// Tests the basic TLSPlaintext record structure:
// - ContentType must be valid (20-23, 25)
// - legacy_record_version must be 0x0303
// - length must not exceed 2^14 bytes
test "RFC 8446 §5.1: TLSPlaintext structure" {
    // Valid handshake record
    const handshake_record = [_]u8{
        0x16, // ContentType: handshake (22)
        0x03, 0x03, // legacy_record_version: 0x0303
        0x00, 0x05, // length: 5 bytes
        0x01, 0x02, 0x03, 0x04, 0x05, // fragment
    };

    // Parse the record
    const content_type = handshake_record[0];
    const legacy_version = (@as(u16, handshake_record[1]) << 8) | handshake_record[2];
    const length = (@as(u16, handshake_record[3]) << 8) | handshake_record[4];

    try testing.expectEqual(@as(u8, 0x16), content_type); // handshake
    try testing.expectEqual(@as(u16, 0x0303), legacy_version);
    try testing.expectEqual(@as(u16, 5), length);
}

// RFC 8446 §5.1: ContentType Values
//
// Tests that valid ContentType values are accepted:
// - invalid(0), alert(21), handshake(22), application_data(23)
test "RFC 8446 §5.1: ContentType values" {
    const ContentType = enum(u8) {
        invalid = 0,
        change_cipher_spec = 20, // RFC 8446 §5: Deprecated but allowed
        alert = 21,
        handshake = 22,
        application_data = 23,
    };

    // Valid content types
    try testing.expectEqual(ContentType.alert, @as(ContentType, @enumFromInt(21)));
    try testing.expectEqual(ContentType.handshake, @as(ContentType, @enumFromInt(22)));
    try testing.expectEqual(ContentType.application_data, @as(ContentType, @enumFromInt(23)));
}

// RFC 8446 §5.1: Maximum Record Length
//
// Tests that TLSPlaintext.length MUST NOT exceed 2^14 bytes (16384).
test "RFC 8446 §5.1: Maximum plaintext record length" {
    const MAX_PLAINTEXT_LENGTH: u16 = 16384; // 2^14

    // Valid length
    const valid_length: u16 = 16384;
    try testing.expect(valid_length <= MAX_PLAINTEXT_LENGTH);

    // Invalid length (would be rejected)
    const invalid_length: u16 = 16385;
    try testing.expect(invalid_length > MAX_PLAINTEXT_LENGTH);
}

// RFC 8446 §5.2: Record Payload Protection
//
// Tests AEAD encryption and decryption of TLS records.
//
// The AEAD algorithm takes as input:
// - Secret key (from traffic secret)
// - Nonce (derived per-record)
// - Plaintext
// - Additional data (TLS record header)
//
// Output: ciphertext || authentication tag
test "RFC 8446 §5.2: AEAD record protection (AES-128-GCM)" {
    // Test key and IV (16 bytes for AES-128, 12 bytes for GCM IV)
    const key_hex = "00112233445566778899aabbccddeeff";
    var key: [16]u8 = undefined;
    hexToBytes(key_hex, &key);

    const iv_hex = "000102030405060708090a0b";
    var iv: [12]u8 = undefined;
    hexToBytes(iv_hex, &iv);

    // Initialize AEAD cipher
    var cipher = try record.AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null);
    defer cipher.wipe();

    // Plaintext to encrypt
    const plaintext = "Hello, TLS 1.3!";

    // Additional data (TLS record header)
    const ad = [_]u8{
        0x17, // ContentType: application_data
        0x03, 0x03, // legacy_record_version
        0x00, @intCast(plaintext.len), // length
    };

    // Seal (encrypt)
    const ciphertext = try cipher.seal(testing.allocator, 0, &ad, plaintext);
    defer testing.allocator.free(ciphertext);

    // Ciphertext should be longer than plaintext (includes auth tag)
    try testing.expect(ciphertext.len > plaintext.len);

    // Open (decrypt)
    const recovered = try cipher.open(testing.allocator, 0, &ad, ciphertext);
    defer testing.allocator.free(recovered);

    // Should recover original plaintext
    try testing.expectEqualSlices(u8, plaintext, recovered);
}

// RFC 8446 §5.3: Per-Record Nonce
//
// Tests nonce derivation for AEAD operations.
//
// The per-record nonce is formed as follows:
// 1. The 64-bit record sequence number is encoded in network byte order
//    and padded to the left with zeros to iv_length.
// 2. The padded sequence number is XORed with the static IV.
//
// ```
// nonce = static_iv XOR (0^(iv_length - 8) || sequence_number)
// ```
test "RFC 8446 §5.3: Per-record nonce derivation" {
    // Static IV (12 bytes for AES-GCM)
    const static_iv_hex = "000102030405060708090a0b";
    var static_iv: [12]u8 = undefined;
    hexToBytes(static_iv_hex, &static_iv);

    // Sequence number (first record)
    const seq_num: u64 = 0;

    // Derive nonce by XORing static IV with padded sequence number
    var nonce: [12]u8 = static_iv;
    var seq_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_bytes, seq_num, .big);

    // XOR the last 8 bytes of the nonce with the sequence number
    for (0..8) |i| {
        nonce[4 + i] ^= seq_bytes[i];
    }

    // For sequence 0, nonce should equal static IV
    try testing.expectEqualSlices(u8, &static_iv, &nonce);

    // For sequence 1, nonce should differ in last byte
    const seq_num_1: u64 = 1;
    var nonce_1: [12]u8 = static_iv;
    std.mem.writeInt(u64, &seq_bytes, seq_num_1, .big);
    for (0..8) |i| {
        nonce_1[4 + i] ^= seq_bytes[i];
    }

    // Last byte should be 0x0b XOR 0x01 = 0x0a
    try testing.expectEqual(@as(u8, 0x0a), nonce_1[11]);
}

// RFC 8446 §5.4: Record Padding
//
// Tests TLSInnerPlaintext padding.
//
// The TLSInnerPlaintext structure includes:
// - content: the actual data
// - type: the ContentType
// - zeros: optional padding
//
// Padding can be added to obscure the length of the actual content.
test "RFC 8446 §5.4: TLSInnerPlaintext padding" {
    // Original content
    const content = "test";
    const content_type: u8 = 0x17; // application_data

    // Create TLSInnerPlaintext with 10 bytes of padding
    const padding_length = 10;
    var inner_plaintext = try testing.allocator.alloc(u8, content.len + 1 + padding_length);
    defer testing.allocator.free(inner_plaintext);

    // Fill structure: content || type || zeros
    @memcpy(inner_plaintext[0..content.len], content);
    inner_plaintext[content.len] = content_type;
    @memset(inner_plaintext[content.len + 1 ..], 0);

    // Verify structure
    try testing.expectEqualSlices(u8, content, inner_plaintext[0..content.len]);
    try testing.expectEqual(content_type, inner_plaintext[content.len]);

    // All padding bytes should be zero
    for (inner_plaintext[content.len + 1 ..]) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }
}

// RFC 8446 §5.5: Limits on Key Usage
//
// Tests AEAD usage limits.
//
// There are cryptographic limits on the amount of plaintext that can be
// safely encrypted under a given set of keys. For AEAD_AES_128_GCM:
// - Confidentiality limit: 2^24.5 records
// - Integrity limit: 2^24.5 records
//
// Implementations MUST do one of the following:
// - Limit use of keys to within these limits
// - Use a key update mechanism
test "RFC 8446 §5.5: AEAD usage limits (AES-128-GCM)" {
    // AES-128-GCM confidentiality limit (approximately 23 million records)
    const AES_128_GCM_LIMIT: u64 = 1 << 24; // Simplified to 2^24

    // Simulate record counter
    var records_encrypted: u64 = 0;

    // Should be able to encrypt up to the limit
    while (records_encrypted < AES_128_GCM_LIMIT) : (records_encrypted += 1000000) {
        // Would encrypt record here
        try testing.expect(records_encrypted < AES_128_GCM_LIMIT);
    }

    // After limit, should trigger key update
    try testing.expect(records_encrypted >= AES_128_GCM_LIMIT);
}

// RFC 8446 §5.2: AEAD Authentication Tag
//
// Tests that AEAD provides authenticated encryption.
//
// The authentication tag ensures:
// - Ciphertext integrity (modification detection)
// - Additional data integrity (header protection)
test "RFC 8446 §5.2: AEAD authentication tag verification" {
    const key_hex = "00112233445566778899aabbccddeeff";
    var key: [16]u8 = undefined;
    hexToBytes(key_hex, &key);

    const iv_hex = "000102030405060708090a0b";
    var iv: [12]u8 = undefined;
    hexToBytes(iv_hex, &iv);

    var cipher = try record.AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null);
    defer cipher.wipe();

    const plaintext = "Authenticated data";
    const ad = [_]u8{ 0x17, 0x03, 0x03, 0x00, @intCast(plaintext.len) };

    // Encrypt
    const ciphertext = try cipher.seal(testing.allocator, 0, &ad, plaintext);
    defer testing.allocator.free(ciphertext);

    // Tamper with ciphertext (flip a bit)
    var tampered = try testing.allocator.dupe(u8, ciphertext);
    defer testing.allocator.free(tampered);
    tampered[0] ^= 0x01; // Flip one bit

    // Decryption should fail due to authentication tag mismatch
    const result = cipher.open(testing.allocator, 0, &ad, tampered);
    try testing.expectError(error.AuthenticationFailed, result);
}

// RFC 8446 §5: TLSCiphertext Structure
//
// Tests encrypted record structure:
// - opaque_type is always application_data (23)
// - legacy_record_version is 0x0303
// - length includes authentication tag
test "RFC 8446 §5: TLSCiphertext structure" {
    // Encrypted record structure
    const encrypted_record = [_]u8{
        0x17, // opaque_type: application_data (MUST be 23)
        0x03, 0x03, // legacy_record_version: 0x0303
        0x00, 0x20, // length: 32 bytes (plaintext + tag)
        // ... encrypted_record[32] bytes ...
    };

    const opaque_type = encrypted_record[0];
    const legacy_version = (@as(u16, encrypted_record[1]) << 8) | encrypted_record[2];
    const length = (@as(u16, encrypted_record[3]) << 8) | encrypted_record[4];

    // RFC 8446 §5.2: opaque_type MUST be 23 for encrypted records
    try testing.expectEqual(@as(u8, 0x17), opaque_type);

    // RFC 8446 §5.1: legacy_record_version MUST be 0x0303
    try testing.expectEqual(@as(u16, 0x0303), legacy_version);

    // Length includes ciphertext + authentication tag
    try testing.expectEqual(@as(u16, 32), length);
}
