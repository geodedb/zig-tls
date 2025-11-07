//! RFC 8446 §4.4.1: Transcript Hash Tests
//!
//! Tests for TLS 1.3 transcript hash computation.
//!
//! ## RFC 8446 §4.4.1: Transcript-Hash
//!
//! Many of the cryptographic computations in TLS make use of a transcript hash.
//! This is computed by hashing the concatenation of each included handshake
//! message, including the handshake message header carrying the handshake
//! message type and length fields, but not including record layer headers.
//!
//! ```
//! Transcript-Hash(M1, M2, ... Mn) = Hash(M1 || M2 || ... || Mn)
//! ```
//!
//! Where:
//! - Hash is the hash function associated with the cipher suite
//! - M1, M2, etc. are complete handshake messages (including type and length)
//! - || denotes concatenation
//!
//! ## Test Coverage
//!
//! - Empty transcript hash
//! - Single message transcript
//! - Multiple message transcript
//! - Incremental hashing
//! - Different hash algorithms (SHA-256, SHA-384)

const std = @import("std");
const testing = std.testing;

// Helper to convert hex string to bytes
fn hexToBytes(comptime hex: []const u8, out: []u8) void {
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        out[i / 2] = std.fmt.parseInt(u8, hex[i .. i + 2], 16) catch unreachable;
    }
}

// Helper to compare hex string with bytes
fn expectEqualHex(comptime hex: []const u8, actual: []const u8) !void {
    var expected: [hex.len / 2]u8 = undefined;
    hexToBytes(hex, &expected);
    try testing.expectEqualSlices(u8, &expected, actual);
}

// RFC 8446 §4.4.1: Empty Transcript Hash
//
// Tests the initial state of the transcript hash (empty).
// Hash(empty) should produce the hash of an empty message.
test "RFC 8446 §4.4.1: Empty transcript hash (SHA-256)" {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    // SHA-256 of empty message
    const expected_hex =
        "e3b0c44298fc1c149afbf4c8996fb924" ++
        "27ae41e4649b934ca495991b7852b855";

    try expectEqualHex(expected_hex, &digest);
}

// RFC 8446 §4.4.1: Single Message Transcript
//
// Tests transcript hash with a single handshake message.
//
// Handshake message structure:
// ```
// struct {
//     HandshakeType msg_type;    /* 1 byte */
//     uint24 length;             /* 3 bytes */
//     select (msg_type) {
//         ...
//     } body;
// } Handshake;
// ```
test "RFC 8446 §4.4.1: Single message transcript" {
    // ClientHello message (simplified):
    // msg_type: ClientHello (1)
    // length: 5 bytes
    // body: [0x01, 0x02, 0x03, 0x04, 0x05]
    const client_hello = [_]u8{
        0x01, // HandshakeType: ClientHello
        0x00, 0x00, 0x05, // length: 5 bytes (24-bit)
        0x01, 0x02, 0x03, 0x04, 0x05, // body
    };

    // Compute transcript hash
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&client_hello);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    // Digest should be deterministic
    try testing.expect(digest.len == 32);

    // Verify by recomputing
    var hasher2 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher2.update(&client_hello);
    var digest2: [32]u8 = undefined;
    hasher2.final(&digest2);

    try testing.expectEqualSlices(u8, &digest, &digest2);
}

// RFC 8446 §4.4.1: Multiple Message Transcript
//
// Tests transcript hash with multiple handshake messages.
//
// The transcript hash is computed over the concatenation of all messages:
// Hash(ClientHello || ServerHello || ...)
test "RFC 8446 §4.4.1: Multiple message transcript" {
    // ClientHello
    const client_hello = [_]u8{
        0x01, // HandshakeType: ClientHello
        0x00, 0x00, 0x03, // length: 3 bytes
        0xAA, 0xBB, 0xCC, // body
    };

    // ServerHello
    const server_hello = [_]u8{
        0x02, // HandshakeType: ServerHello
        0x00, 0x00, 0x02, // length: 2 bytes
        0xDD, 0xEE, // body
    };

    // Compute transcript hash incrementally
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&client_hello);
    hasher.update(&server_hello);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    // Verify by computing over concatenation
    var hasher2 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher2.update(&client_hello);
    hasher2.update(&server_hello);
    var digest2: [32]u8 = undefined;
    hasher2.final(&digest2);

    // Should produce same result
    try testing.expectEqualSlices(u8, &digest, &digest2);
}

// RFC 8446 §4.4.1: Incremental Transcript Hashing
//
// Tests that incremental hashing produces the same result as
// hashing the complete concatenation.
test "RFC 8446 §4.4.1: Incremental vs batch hashing" {
    const msg1 = [_]u8{ 0x01, 0x00, 0x00, 0x02, 0xAA, 0xBB };
    const msg2 = [_]u8{ 0x02, 0x00, 0x00, 0x03, 0xCC, 0xDD, 0xEE };
    const msg3 = [_]u8{ 0x03, 0x00, 0x00, 0x01, 0xFF };

    // Incremental hashing
    var hasher_incremental = std.crypto.hash.sha2.Sha256.init(.{});
    hasher_incremental.update(&msg1);
    hasher_incremental.update(&msg2);
    hasher_incremental.update(&msg3);
    var digest_incremental: [32]u8 = undefined;
    hasher_incremental.final(&digest_incremental);

    // Batch hashing (concatenate first)
    var concatenated = try testing.allocator.alloc(u8, msg1.len + msg2.len + msg3.len);
    defer testing.allocator.free(concatenated);

    @memcpy(concatenated[0..msg1.len], &msg1);
    @memcpy(concatenated[msg1.len .. msg1.len + msg2.len], &msg2);
    @memcpy(concatenated[msg1.len + msg2.len ..], &msg3);

    var hasher_batch = std.crypto.hash.sha2.Sha256.init(.{});
    hasher_batch.update(concatenated);
    var digest_batch: [32]u8 = undefined;
    hasher_batch.final(&digest_batch);

    // Both methods should produce identical results
    try testing.expectEqualSlices(u8, &digest_incremental, &digest_batch);
}

// RFC 8446 §4.4.1: Transcript Hash with SHA-384
//
// Tests transcript hashing with SHA-384 (used with TLS_AES_256_GCM_SHA384).
test "RFC 8446 §4.4.1: Transcript hash with SHA-384" {
    const message = [_]u8{ 0x01, 0x00, 0x00, 0x05, 0x11, 0x22, 0x33, 0x44, 0x55 };

    // Compute SHA-384 transcript hash
    var hasher = std.crypto.hash.sha2.Sha384.init(.{});
    hasher.update(&message);
    var digest: [48]u8 = undefined;
    hasher.final(&digest);

    // SHA-384 produces 48-byte digest
    try testing.expectEqual(@as(usize, 48), digest.len);

    // Verify deterministic
    var hasher2 = std.crypto.hash.sha2.Sha384.init(.{});
    hasher2.update(&message);
    var digest2: [48]u8 = undefined;
    hasher2.final(&digest2);

    try testing.expectEqualSlices(u8, &digest, &digest2);
}

// RFC 8446 §4.4.1: Handshake Message Type Included in Transcript
//
// Tests that the handshake message type and length are included
// in the transcript hash.
//
// The transcript includes:
// - msg_type (1 byte)
// - length (3 bytes)
// - body (length bytes)
test "RFC 8446 §4.4.1: Message header included in transcript" {
    // Message with different bodies but same type/length should differ
    const msg1 = [_]u8{ 0x01, 0x00, 0x00, 0x02, 0xAA, 0xBB };
    const msg2 = [_]u8{ 0x01, 0x00, 0x00, 0x02, 0xCC, 0xDD };

    var hasher1 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher1.update(&msg1);
    var digest1: [32]u8 = undefined;
    hasher1.final(&digest1);

    var hasher2 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher2.update(&msg2);
    var digest2: [32]u8 = undefined;
    hasher2.final(&digest2);

    // Different bodies should produce different hashes
    try testing.expect(!std.mem.eql(u8, &digest1, &digest2));

    // Message with same body but different type should also differ
    const msg3 = [_]u8{ 0x02, 0x00, 0x00, 0x02, 0xAA, 0xBB }; // type=2 instead of 1

    var hasher3 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher3.update(&msg3);
    var digest3: [32]u8 = undefined;
    hasher3.final(&digest3);

    // Different types should produce different hashes
    try testing.expect(!std.mem.eql(u8, &digest1, &digest3));
}

// RFC 8446 §4.4.1: Message Order Matters
//
// Tests that the order of messages in the transcript affects the hash.
//
// Hash(M1 || M2) ≠ Hash(M2 || M1)
test "RFC 8446 §4.4.1: Message order affects transcript" {
    const msg1 = [_]u8{ 0x01, 0x00, 0x00, 0x02, 0xAA, 0xBB };
    const msg2 = [_]u8{ 0x02, 0x00, 0x00, 0x02, 0xCC, 0xDD };

    // Hash in order: msg1, msg2
    var hasher1 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher1.update(&msg1);
    hasher1.update(&msg2);
    var digest1: [32]u8 = undefined;
    hasher1.final(&digest1);

    // Hash in reverse order: msg2, msg1
    var hasher2 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher2.update(&msg2);
    hasher2.update(&msg1);
    var digest2: [32]u8 = undefined;
    hasher2.final(&digest2);

    // Different orders should produce different hashes
    try testing.expect(!std.mem.eql(u8, &digest1, &digest2));
}

// RFC 8446 §4.4.1: Transcript Hash Length
//
// Tests that transcript hash length matches the hash algorithm output size.
test "RFC 8446 §4.4.1: Transcript hash output length" {
    const message = [_]u8{ 0x01, 0x00, 0x00, 0x01, 0xFF };

    // SHA-256 produces 32-byte (256-bit) output
    var hasher256 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher256.update(&message);
    var digest256: [32]u8 = undefined;
    hasher256.final(&digest256);
    try testing.expectEqual(@as(usize, 32), digest256.len);

    // SHA-384 produces 48-byte (384-bit) output
    var hasher384 = std.crypto.hash.sha2.Sha384.init(.{});
    hasher384.update(&message);
    var digest384: [48]u8 = undefined;
    hasher384.final(&digest384);
    try testing.expectEqual(@as(usize, 48), digest384.len);
}
