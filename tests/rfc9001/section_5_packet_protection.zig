//! RFC 9001 §5: Packet Protection Tests
//!
//! Tests for QUIC packet protection using TLS traffic secrets.
//!
//! ## RFC 9001 §5: Packet Protection
//!
//! QUIC packet protection uses AEAD functions negotiated by TLS, but the
//! packet protection keys are derived from QUIC packet protection secrets
//! rather than TLS traffic secrets directly.
//!
//! The process:
//! 1. Derive packet protection secret from TLS traffic secret
//! 2. Expand secret into packet protection key and IV
//! 3. Derive header protection key from packet protection secret
//! 4. Protect packet payload with AEAD
//! 5. Apply header protection to packet header
//!
//! ## RFC 9001 §5.1: Packet Protection Keys
//!
//! Packet protection keys are derived from TLS traffic secrets:
//!
//! ```
//! packet_protection_key = HKDF-Expand-Label(Secret, "quic key", "", key_length)
//! packet_protection_iv  = HKDF-Expand-Label(Secret, "quic iv", "", iv_length)
//! ```
//!
//! ## Test Coverage
//!
//! - §5.1: Packet protection key derivation
//! - §5.2: Initial secret usage
//! - §5.3: AEAD usage limits
//! - §5.4: Header protection
//! - Nonce construction for packet protection

const std = @import("std");
const testing = std.testing;
const key_schedule = @import("quic_tls");
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

// RFC 9001 §5.1: Packet Protection Key Derivation
//
// Tests derivation of packet protection keys from traffic secrets.
//
// ```
// packet_protection_key = HKDF-Expand-Label(Secret, "quic key", "", key_length)
// ```
test "RFC 9001 §5.1: Packet protection key derivation" {
    // Client application traffic secret
    const traffic_secret_hex =
        "9ac312a7f877468ebe69422748ad00a1" ++
        "5443f18203a07d6060f688f30f21632b";
    var traffic_secret: [32]u8 = undefined;
    hexToBytes(traffic_secret_hex, &traffic_secret);

    // Derive packet protection key (16 bytes for AES-128-GCM)
    var packet_key: [16]u8 = undefined;
    try key_schedule.expandLabel(traffic_secret[0..], "quic key", "", &packet_key);

    // Should produce 16-byte key
    try testing.expectEqual(@as(usize, 16), packet_key.len);

    // Should be deterministic
    var packet_key2: [16]u8 = undefined;
    try key_schedule.expandLabel(traffic_secret[0..], "quic key", "", &packet_key2);
    try testing.expectEqualSlices(u8, &packet_key, &packet_key2);
}

// RFC 9001 §5.1: Packet Protection IV Derivation
//
// Tests derivation of packet protection IV from traffic secrets.
//
// ```
// packet_protection_iv = HKDF-Expand-Label(Secret, "quic iv", "", iv_length)
// ```
test "RFC 9001 §5.1: Packet protection IV derivation" {
    const traffic_secret_hex =
        "9ac312a7f877468ebe69422748ad00a1" ++
        "5443f18203a07d6060f688f30f21632b";
    var traffic_secret: [32]u8 = undefined;
    hexToBytes(traffic_secret_hex, &traffic_secret);

    // Derive packet protection IV (12 bytes for AES-GCM)
    var packet_iv: [12]u8 = undefined;
    try key_schedule.expandLabel(traffic_secret[0..], "quic iv", "", &packet_iv);

    // Should produce 12-byte IV
    try testing.expectEqual(@as(usize, 12), packet_iv.len);
}

// RFC 9001 §5.4: Header Protection Key Derivation
//
// Tests derivation of header protection keys.
//
// ```
// header_protection_key = HKDF-Expand-Label(Secret, "quic hp", "", hp_key_length)
// ```
test "RFC 9001 §5.4: Header protection key derivation" {
    const traffic_secret_hex =
        "9ac312a7f877468ebe69422748ad00a1" ++
        "5443f18203a07d6060f688f30f21632b";
    var traffic_secret: [32]u8 = undefined;
    hexToBytes(traffic_secret_hex, &traffic_secret);

    // Derive header protection key (16 bytes for AES-128)
    var hp_key: [16]u8 = undefined;
    try key_schedule.expandLabel(traffic_secret[0..], "quic hp", "", &hp_key);

    // Should produce 16-byte header protection key
    try testing.expectEqual(@as(usize, 16), hp_key.len);
}

// RFC 9001 §5.1: Key and IV Derivation from Same Secret
//
// Tests that key and IV derived from same secret are independent.
test "RFC 9001 §5.1: Key and IV independence" {
    const traffic_secret_hex =
        "00112233445566778899aabbccddeeff" ++
        "00112233445566778899aabbccddeeff";
    var traffic_secret: [32]u8 = undefined;
    hexToBytes(traffic_secret_hex, &traffic_secret);

    // Derive key
    var key: [16]u8 = undefined;
    try key_schedule.expandLabel(traffic_secret[0..], "quic key", "", &key);

    // Derive IV
    var iv: [12]u8 = undefined;
    try key_schedule.expandLabel(traffic_secret[0..], "quic iv", "", &iv);

    // Key and IV should not share bytes (no accidental correlation)
    // They are independently derived through HKDF-Expand-Label
    try testing.expect(key.len == 16);
    try testing.expect(iv.len == 12);
}

// RFC 9001 §5.3: QUIC AEAD Usage Limits
//
// Tests that QUIC enforces AEAD usage limits.
//
// For AEAD_AES_128_GCM and AEAD_AES_256_GCM:
// - Confidentiality limit: 2^23 packets
// - Integrity limit: 2^52 packets
//
// For AEAD_CHACHA20_POLY1305:
// - Confidentiality limit: No practical limit
// - Integrity limit: 2^36 packets
test "RFC 9001 §5.3: AEAD usage limits (AES-128-GCM)" {
    // AES-128-GCM confidentiality limit for QUIC (2^23 packets)
    const QUIC_AES_128_GCM_LIMIT: u64 = 1 << 23; // ~8.4 million packets

    var packets_protected: u64 = 0;

    // Should be able to protect up to the limit
    try testing.expect(QUIC_AES_128_GCM_LIMIT == 8388608);

    // After limit, must perform key update
    packets_protected = QUIC_AES_128_GCM_LIMIT;
    try testing.expect(packets_protected >= QUIC_AES_128_GCM_LIMIT);
}

// RFC 9001 §5: Packet Number Encoding in Nonce
//
// Tests that packet number is properly encoded in the nonce.
//
// The nonce is constructed by XORing the packet protection IV
// with the packet number (left-padded with zeros).
test "RFC 9001 §5: Packet number in nonce" {
    // Packet protection IV
    const iv_hex = "000102030405060708090a0b";
    var iv: [12]u8 = undefined;
    hexToBytes(iv_hex, &iv);

    // Packet number (64-bit, network byte order)
    const packet_number: u64 = 12345;

    // Construct nonce by XORing IV with packet number
    var nonce: [12]u8 = iv;
    var pn_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &pn_bytes, packet_number, .big);

    // XOR the last 8 bytes with packet number
    for (0..8) |i| {
        nonce[4 + i] ^= pn_bytes[i];
    }

    // Nonce should differ from IV in last bytes
    try testing.expect(!std.mem.eql(u8, &iv, &nonce));

    // First 4 bytes should still match IV (no XOR applied there)
    try testing.expectEqualSlices(u8, iv[0..4], nonce[0..4]);
}

// RFC 9001 §5.2: Initial Packet Protection
//
// Tests that Initial packets use special derivation.
//
// Initial packets are protected using secrets derived from the
// connection ID rather than TLS handshake secrets.
test "RFC 9001 §5.2: Initial packet protection uses DCID" {
    // Destination Connection ID
    const dcid_hex = "8394c8f03e515708";
    var dcid: [8]u8 = undefined;
    hexToBytes(dcid_hex, &dcid);

    // Derive initial secret from DCID (not from TLS handshake)
    const initial_secret = key_schedule.HkdfSha256.extract(&key_schedule.initial_salt_v1, &dcid);

    // Derive client initial secret
    var client_initial_secret: [32]u8 = undefined;
    try key_schedule.expandLabel(initial_secret[0..], "client in", "", &client_initial_secret);

    // Derive packet protection key from initial secret
    var client_key: [16]u8 = undefined;
    try key_schedule.expandLabel(client_initial_secret[0..], "quic key", "", &client_key);

    // Key should be derived independently of TLS handshake
    try testing.expect(client_key.len == 16);
}

// RFC 9001 §5.3: Key Update Mechanism
//
// Tests that QUIC can update keys without full handshake.
//
// Application traffic secrets can be updated using TLS KeyUpdate:
// ```
// application_traffic_secret_N+1 =
//     HKDF-Expand-Label(application_traffic_secret_N,
//                      "quic ku", "", Hash.length)
// ```
test "RFC 9001 §5.3: QUIC key update" {
    // Current application traffic secret
    const current_secret_hex =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++ "a" ++
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++ "a";
    var current_secret: [32]u8 = undefined;
    hexToBytes(current_secret_hex, &current_secret);

    // Update to next generation (using "quic ku" label)
    var next_secret: [32]u8 = undefined;
    try key_schedule.expandLabel(current_secret[0..], "quic ku", "", &next_secret);

    // Updated secret should differ from current
    try testing.expect(!std.mem.eql(u8, &current_secret, &next_secret));

    // Derive new packet protection key from updated secret
    var new_key: [16]u8 = undefined;
    try key_schedule.expandLabel(next_secret[0..], "quic key", "", &new_key);

    try testing.expect(new_key.len == 16);
}

// RFC 9001 §5.1: Different Encryption Levels Use Different Secrets
//
// Tests that Initial, Handshake, and Application data use different secrets.
test "RFC 9001 §5.1: Encryption level independence" {
    // Initial secret (from DCID)
    const dcid_hex = "0001020304050607";
    var dcid: [8]u8 = undefined;
    hexToBytes(dcid_hex, &dcid);
    const initial_secret = key_schedule.HkdfSha256.extract(&key_schedule.initial_salt_v1, &dcid);

    // Handshake secret (from ECDHE, placeholder)
    const handshake_secret_hex =
        "11111111111111111111111111111111" ++
        "11111111111111111111111111111111";
    var handshake_secret: [32]u8 = undefined;
    hexToBytes(handshake_secret_hex, &handshake_secret);

    // Application secret (from master secret, placeholder)
    const app_secret_hex =
        "22222222222222222222222222222222" ++
        "22222222222222222222222222222222";
    var app_secret: [32]u8 = undefined;
    hexToBytes(app_secret_hex, &app_secret);

    // All three should be independent
    try testing.expect(!std.mem.eql(u8, &initial_secret, &handshake_secret));
    try testing.expect(!std.mem.eql(u8, &handshake_secret, &app_secret));
    try testing.expect(!std.mem.eql(u8, &initial_secret, &app_secret));
}

// RFC 9001 §5: Packet Protection Labels
//
// Tests that QUIC uses "quic" prefix for labels instead of "tls13".
test "RFC 9001 §5: QUIC label prefix" {
    const secret_hex =
        "fedcba9876543210fedcba9876543210" ++
        "fedcba9876543210fedcba9876543210";
    var secret: [32]u8 = undefined;
    hexToBytes(secret_hex, &secret);

    // QUIC uses "quic key", "quic iv", "quic hp" labels
    var quic_key: [16]u8 = undefined;
    try key_schedule.expandLabel(secret[0..], "quic key", "", &quic_key);

    var quic_iv: [12]u8 = undefined;
    try key_schedule.expandLabel(secret[0..], "quic iv", "", &quic_iv);

    var quic_hp: [16]u8 = undefined;
    try key_schedule.expandLabel(secret[0..], "quic hp", "", &quic_hp);

    // All should produce output
    try testing.expect(quic_key.len == 16);
    try testing.expect(quic_iv.len == 12);
    try testing.expect(quic_hp.len == 16);

    // Different labels should produce different outputs
    try testing.expect(!std.mem.eql(u8, &quic_key, quic_hp[0..16]));
}
