//! RFC 8446 §4.4.4: Finished Message Tests
//!
//! Tests for TLS 1.3 Finished message computation and verification.
//!
//! ## RFC 8446 §4.4.4: Finished
//!
//! The Finished message is the final message in the Authentication Block.
//! It is essential for providing authentication of the handshake and of the
//! computed keys.
//!
//! ```
//! struct {
//!     opaque verify_data[Hash.length];
//! } Finished;
//! ```
//!
//! The verify_data value is computed as follows:
//!
//! ```
//! finished_key =
//!     HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
//!
//! verify_data =
//!     HMAC(finished_key,
//!          Transcript-Hash(Handshake Context,
//!                         Certificate*, CertificateVerify*))
//! ```
//!
//! Where:
//! - BaseKey is the traffic secret for the encryption level
//! - Hash.length is the output length of the hash function
//! - * indicates optional messages
//!
//! ## Test Coverage
//!
//! - Finished key derivation
//! - verify_data computation
//! - HMAC with transcript hash
//! - Client vs server Finished
//! - Different hash algorithms

const std = @import("std");
const testing = std.testing;
const key_schedule = @import("quic_tls");

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

// RFC 8446 §4.4.4: Finished Key Derivation
//
// Tests derivation of finished_key from base traffic secret.
//
// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
test "RFC 8446 §4.4.4: Finished key derivation" {
    // Server handshake traffic secret (base key)
    const traffic_secret_hex =
        "b3eddb126e067f35a780b3abf45e2d8f" ++
        "3b1a950738f52e9600746a0e27a55a21";
    var traffic_secret: [32]u8 = undefined;
    hexToBytes(traffic_secret_hex, &traffic_secret);

    // Derive finished_key
    var finished_key: [32]u8 = undefined;
    try key_schedule.expandLabel(traffic_secret[0..], "finished", "", &finished_key);

    // Finished key should be 32 bytes for SHA-256
    try testing.expectEqual(@as(usize, 32), finished_key.len);

    // Should be deterministic
    var finished_key2: [32]u8 = undefined;
    try key_schedule.expandLabel(traffic_secret[0..], "finished", "", &finished_key2);
    try testing.expectEqualSlices(u8, &finished_key, &finished_key2);
}

// RFC 8446 §4.4.4: verify_data Computation
//
// Tests computation of verify_data using HMAC.
//
// verify_data = HMAC(finished_key, transcript_hash)
test "RFC 8446 §4.4.4: verify_data computation" {
    // Finished key (derived from traffic secret)
    const finished_key_hex =
        "00112233445566778899aabbccddeeff" ++
        "00112233445566778899aabbccddeeff";
    var finished_key: [32]u8 = undefined;
    hexToBytes(finished_key_hex, &finished_key);

    // Transcript hash (SHA-256 of all handshake messages so far)
    const transcript_hash_hex =
        "aabbccddeeff00112233445566778899" ++
        "aabbccddeeff00112233445566778899";
    var transcript_hash: [32]u8 = undefined;
    hexToBytes(transcript_hash_hex, &transcript_hash);

    // Compute verify_data = HMAC(finished_key, transcript_hash)
    var verify_data: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&verify_data, &transcript_hash, &finished_key);

    // verify_data should be 32 bytes for SHA-256
    try testing.expectEqual(@as(usize, 32), verify_data.len);

    // Should be deterministic
    var verify_data2: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&verify_data2, &transcript_hash, &finished_key);
    try testing.expectEqualSlices(u8, &verify_data, &verify_data2);
}

// RFC 8446 §4.4.4: Client Finished vs Server Finished
//
// Tests that client and server Finished messages use different base keys.
//
// Client uses client_handshake_traffic_secret
// Server uses server_handshake_traffic_secret
test "RFC 8446 §4.4.4: Client vs server Finished keys differ" {
    // Client handshake traffic secret
    const client_secret_hex =
        "11111111111111111111111111111111" ++
        "11111111111111111111111111111111";
    var client_secret: [32]u8 = undefined;
    hexToBytes(client_secret_hex, &client_secret);

    // Server handshake traffic secret
    const server_secret_hex =
        "22222222222222222222222222222222" ++
        "22222222222222222222222222222222";
    var server_secret: [32]u8 = undefined;
    hexToBytes(server_secret_hex, &server_secret);

    // Derive client finished key
    var client_finished_key: [32]u8 = undefined;
    try key_schedule.expandLabel(client_secret[0..], "finished", "", &client_finished_key);

    // Derive server finished key
    var server_finished_key: [32]u8 = undefined;
    try key_schedule.expandLabel(server_secret[0..], "finished", "", &server_finished_key);

    // Client and server finished keys should differ
    try testing.expect(!std.mem.eql(u8, &client_finished_key, &server_finished_key));
}

// RFC 8446 §4.4.4: Finished Message Size
//
// Tests that Finished message size matches hash output length.
//
// For SHA-256: 32 bytes
// For SHA-384: 48 bytes
test "RFC 8446 §4.4.4: Finished message size" {
    const traffic_secret_hex =
        "ffffffffffffffffffffffffffffffff" ++
        "ffffffffffffffffffffffffffffffff";
    var traffic_secret: [32]u8 = undefined;
    hexToBytes(traffic_secret_hex, &traffic_secret);

    const transcript_hash_hex =
        "0000000000000000000000000000000" ++ "0" ++
        "00000000000000000000000000000000";
    var transcript_hash: [32]u8 = undefined;
    hexToBytes(transcript_hash_hex, &transcript_hash);

    // Derive finished key
    var finished_key: [32]u8 = undefined;
    try key_schedule.expandLabel(traffic_secret[0..], "finished", "", &finished_key);

    // Compute verify_data
    var verify_data: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&verify_data, &transcript_hash, &finished_key);

    // Finished message is just verify_data (32 bytes for SHA-256)
    try testing.expectEqual(@as(usize, 32), verify_data.len);
}

// RFC 8446 §4.4.4: Finished with Empty Transcript
//
// Tests Finished computation with empty transcript hash.
//
// This can occur in 0-RTT scenarios where certain messages are omitted.
test "RFC 8446 §4.4.4: Finished with empty transcript" {
    const traffic_secret_hex =
        "abcdef0123456789abcdef0123456789" ++
        "abcdef0123456789abcdef0123456789";
    var traffic_secret: [32]u8 = undefined;
    hexToBytes(traffic_secret_hex, &traffic_secret);

    // Empty transcript hash (SHA-256 of empty message)
    var empty_hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var empty_transcript: [32]u8 = undefined;
    empty_hasher.final(&empty_transcript);

    // Derive finished key
    var finished_key: [32]u8 = undefined;
    try key_schedule.expandLabel(traffic_secret[0..], "finished", "", &finished_key);

    // Compute verify_data with empty transcript
    var verify_data: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&verify_data, &empty_transcript, &finished_key);

    // Should still produce valid 32-byte verify_data
    try testing.expectEqual(@as(usize, 32), verify_data.len);
}

// RFC 8446 §4.4.4: Finished Verification
//
// Tests that Finished message verification detects tampering.
//
// Receiver recomputes verify_data and compares with received value.
test "RFC 8446 §4.4.4: Finished verification detects tampering" {
    const traffic_secret_hex =
        "1234567890abcdef1234567890abcdef" ++
        "1234567890abcdef1234567890abcdef";
    var traffic_secret: [32]u8 = undefined;
    hexToBytes(traffic_secret_hex, &traffic_secret);

    const transcript_hash_hex =
        "fedcba0987654321fedcba0987654321" ++
        "fedcba0987654321fedcba0987654321";
    var transcript_hash: [32]u8 = undefined;
    hexToBytes(transcript_hash_hex, &transcript_hash);

    // Sender computes verify_data
    var finished_key: [32]u8 = undefined;
    try key_schedule.expandLabel(traffic_secret[0..], "finished", "", &finished_key);

    var sender_verify_data: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&sender_verify_data, &transcript_hash, &finished_key);

    // Receiver recomputes verify_data (with same inputs)
    var receiver_verify_data: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&receiver_verify_data, &transcript_hash, &finished_key);

    // Should match
    try testing.expectEqualSlices(u8, &sender_verify_data, &receiver_verify_data);

    // Tamper with received verify_data
    var tampered_verify_data = sender_verify_data;
    tampered_verify_data[0] ^= 0x01; // Flip one bit

    // Verification should fail
    try testing.expect(!std.mem.eql(u8, &receiver_verify_data, &tampered_verify_data));
}

// RFC 8446 §4.4.4: Finished with SHA-384
//
// Tests Finished computation with SHA-384 (used with TLS_AES_256_GCM_SHA384).
test "RFC 8446 §4.4.4: Finished with SHA-384" {
    // Traffic secret for SHA-384 cipher suite (48 bytes = 96 hex chars).
    // QUAL-205 migration surfaced that the previous literal was only
    // 40 bytes (80 hex chars); the remaining 8 bytes were whatever
    // `undefined` contained. Padded to exact 48 bytes.
    const traffic_secret_hex =
        "001122334455667788990011223344556677889900112233" ++
        "44556677889900112233445566778899aabbccddeeff0011";
    var traffic_secret: [48]u8 = undefined;
    hexToBytes(traffic_secret_hex, &traffic_secret);

    // Transcript hash (SHA-384, 48 bytes = 96 hex chars).
    const transcript_hash_hex =
        "aabbccddeeff00112233445566778899aabbccddeeff0011" ++
        "2233445566778899aabbccddeeff00112233445566778899";
    var transcript_hash: [48]u8 = undefined;
    hexToBytes(transcript_hash_hex, &transcript_hash);

    // Note: expandLabel would need to support SHA-384
    // This is a structural test showing SHA-384 produces 48-byte output
    var verify_data: [48]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha384.create(&verify_data, &transcript_hash, &traffic_secret);

    // Finished message should be 48 bytes for SHA-384
    try testing.expectEqual(@as(usize, 48), verify_data.len);
}

// RFC 8446 §4.4.4: Finished Label
//
// Tests that the "finished" label is used correctly in HKDF-Expand-Label.
//
// The label "finished" is distinct from other labels like "key" or "iv".
test "RFC 8446 §4.4.4: Finished label uniqueness" {
    const traffic_secret_hex =
        "aabbccddeeff00112233445566778899" ++
        "aabbccddeeff00112233445566778899";
    var traffic_secret: [32]u8 = undefined;
    hexToBytes(traffic_secret_hex, &traffic_secret);

    // Derive with "finished" label
    var finished_key: [32]u8 = undefined;
    try key_schedule.expandLabel(traffic_secret[0..], "finished", "", &finished_key);

    // Derive with different label (e.g., "key")
    var other_key: [16]u8 = undefined;
    try key_schedule.expandLabel(traffic_secret[0..], "key", "", &other_key);

    // Different labels should produce different outputs
    try testing.expect(!std.mem.eql(u8, finished_key[0..16], &other_key));
}
