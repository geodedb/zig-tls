// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Transcript Hash Management
//!
//! RFC 8446 §4.4.1: Transcript-Hash
//!
//! The transcript hash is computed as:
//!   Hash(Handshake Context) = Hash(Messages)
//! where Messages is the concatenation of all Handshake messages.
//!
//! The transcript hash is critical for Finished message verification and must be
//! updated in exact message order received/sent. Any tampering with the transcript
//! will cause handshake failure.
//!
//! ## HelloRetryRequest Special Handling (RFC 8446 §4.4.1)
//!
//! When HelloRetryRequest is used, the transcript is modified with a synthetic
//! "message_hash" message to bind the retry to the original ClientHello:
//!
//! ```
//! Transcript = Hash(message_hash || HelloRetryRequest || ClientHello2 || ...)
//!
//! where message_hash is constructed as:
//!   message_hash = Handshake {
//!     msg_type = message_hash (254)
//!     length = Hash.length
//!     body = Hash(ClientHello1)
//!   }
//! ```
//!
//! This prevents attackers from causing the client to retry with different
//! parameters by ensuring the first ClientHello is bound to the transcript.
//!
//! # Usage
//!
//! ## Normal Flow
//! ```zig
//! var transcript = Transcript.init();
//! transcript.update(client_hello_bytes);
//! transcript.update(server_hello_bytes);
//! const hash = transcript.finalize(.sha256);
//! // Use hash for Finished message verification
//! ```
//!
//! ## HelloRetryRequest Flow
//! ```zig
//! var transcript = Transcript.init();
//! transcript.update(client_hello1_bytes);
//!
//! // Server sends HelloRetryRequest
//! transcript.handleHelloRetryRequest(client_hello1_bytes, .sha256);
//! transcript.update(hello_retry_request_bytes);
//! transcript.update(client_hello2_bytes);
//! // Continue with rest of handshake...
//! ```

const std = @import("std");
const logger = @import("quic_logger");
const ks = @import("quic_tls");

const Hash = ks.Hash;
const Secret = ks.Secret;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;

/// RFC 8446 §4.4.1: Synthetic message type for HelloRetryRequest transcript.
///
/// The value 254 (0xFE) is reserved for the "message_hash" synthetic message
/// that replaces ClientHello1 in the transcript when HelloRetryRequest is used.
///
/// This is NOT a real handshake message type - it only appears in transcript
/// hash computation to bind the retry to the original ClientHello.
const MESSAGE_HASH_TYPE: u8 = 254;

/// Debug tracing controls (DISABLED for production builds).
/// Set to true locally when diagnosing handshake flows.
const handshake_trace_enabled = false;
const secret_trace_enabled = false;

// SEC-049: Compile-time safety: prevent handshake trace logging in release builds.
// Handshake traces can leak error details, cipher suite info, and other metadata
// that aids attackers in fingerprinting or exploiting the TLS implementation.
comptime {
    if (handshake_trace_enabled and @import("builtin").mode != .Debug) {
        @compileError("SECURITY: handshake_trace_enabled must be false in release builds — handshake metadata would be logged");
    }
}

// Compile-time safety: prevent secret logging in release builds
comptime {
    if (secret_trace_enabled and @import("builtin").mode != .Debug) {
        @compileError("SECURITY: secret_trace_enabled must be false in release builds - secrets would be logged!");
    }
}

inline fn traceHandshake(comptime fmt: []const u8, args: anytype) void {
    if (handshake_trace_enabled) logger.debugPrint(fmt, args);
}

inline fn traceSecrets(comptime fmt: []const u8, args: anytype) void {
    if (secret_trace_enabled) logger.debugPrint(fmt, args);
}

/// RFC 8446 §4.4.1: Transcript hash management
///
/// Maintains both SHA-256 and SHA-384 hash states concurrently to support
/// multiple cipher suites without knowing which hash algorithm will be used
/// until cipher suite negotiation completes.
///
/// After cipher suite negotiation (ServerHello), callers SHOULD call `lockHash`
/// to skip updates to the unused hash algorithm. This avoids wasting cycles on
/// the hash that will never be finalized (PERF-004).
pub const Transcript = struct {
    sha256: Sha256,
    sha384: Sha384,
    /// After cipher suite negotiation selects a hash, this field is set so that
    /// `update()` skips the unused algorithm.  Before negotiation (pre-ServerHello)
    /// this is `null` and both hashes are updated.
    locked_hash: ?Hash = null,

    /// Initialize a new transcript hash helper.
    /// RFC 8446 §4.4.1: Transcript hash begins empty
    pub fn init() Transcript {
        return .{
            .sha256 = Sha256.init(.{}),
            .sha384 = Sha384.init(.{}),
            .locked_hash = null,
        };
    }

    /// Lock the transcript to a single hash algorithm after cipher suite negotiation.
    ///
    /// Once locked, `update()` will only feed data into the selected hash,
    /// saving redundant computation for every subsequent handshake message.
    ///
    /// Must be called AFTER ServerHello processing when the cipher suite (and
    /// therefore the hash) is known.  Calling `lockHash` before ServerHello
    /// would break `snapshot()` and `finalize()` for the other hash.
    pub fn lockHash(self: *Transcript, hash: Hash) void {
        self.locked_hash = hash;
    }

    /// Update transcript with raw bytes (handshake messages).
    /// RFC 8446 §4.4.1: Messages MUST be included in order sent/received
    ///
    /// When `locked_hash` is set (post-negotiation), only the selected hash
    /// is updated.  Before negotiation both SHA-256 and SHA-384 are updated.
    pub fn update(self: *Transcript, msg: []const u8) void {
        if (self.locked_hash) |h| {
            switch (h) {
                .sha256 => self.sha256.update(msg),
                .sha384 => self.sha384.update(msg),
            }
        } else {
            self.sha256.update(msg);
            self.sha384.update(msg);
        }

        // Debug: log what's being added to transcript
        if (handshake_trace_enabled and msg.len >= 4) {
            const msg_type = msg[0];
            const msg_len = (@as(usize, msg[1]) << 16) | (@as(usize, msg[2]) << 8) | msg[3];
            const type_name = switch (msg_type) {
                0x01 => "ClientHello",
                0x02 => "ServerHello",
                0x08 => "EncryptedExtensions",
                0x0B => "Certificate",
                0x0F => "CertificateVerify",
                0x14 => "Finished",
                else => "Unknown",
            };
            traceHandshake("[TRANSCRIPT] Adding {s} (0x{X:0>2}) len={} bytes, first 8: {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2}\n", .{
                type_name,                      msg_type,                       msg_len,
                if (msg.len > 0) msg[0] else 0, if (msg.len > 1) msg[1] else 0, if (msg.len > 2) msg[2] else 0,
                if (msg.len > 3) msg[3] else 0, if (msg.len > 4) msg[4] else 0, if (msg.len > 5) msg[5] else 0,
                if (msg.len > 6) msg[6] else 0, if (msg.len > 7) msg[7] else 0,
            });

            // Print full message bytes for ClientHello and ServerHello
            if (msg_type == 0x01 or msg_type == 0x02) {
                traceHandshake("[TRANSCRIPT] Full {s} message ({} bytes):\n", .{ type_name, msg.len });
                var i: usize = 0;
                while (i < msg.len) : (i += 32) {
                    traceHandshake("  ", .{});
                    var j: usize = i;
                    while (j < @min(i + 32, msg.len)) : (j += 1) {
                        traceHandshake("{X:0>2}", .{msg[j]});
                    }
                    traceHandshake("\n", .{});
                }
            }
        }
    }

    fn finalizeSha256(self: *Transcript) Secret {
        var tmp = self.sha256;
        var out: [Sha256.digest_length]u8 = undefined;
        tmp.final(&out);
        return Secret.fromSlice(.sha256, out[0..]);
    }

    fn finalizeSha384(self: *Transcript) Secret {
        var tmp = self.sha384;
        var out: [Sha384.digest_length]u8 = undefined;
        tmp.final(&out);
        return Secret.fromSlice(.sha384, out[0..]);
    }

    /// Finalize and return current transcript hash without consuming internal state.
    /// RFC 8446 §4.4.1: Returns Hash(Messages) for the specified hash algorithm
    ///
    /// The transcript state is not modified, allowing multiple finalize calls
    /// at different points in the handshake.
    pub fn finalize(self: *Transcript, hash: Hash) Secret {
        const digest = switch (hash) {
            .sha256 => self.finalizeSha256(),
            .sha384 => self.finalizeSha384(),
        };
        const slice = digest.slice();
        if (secret_trace_enabled and slice.len >= 8) {
            traceSecrets("[TRANSCRIPT] Finalized hash ({} bytes): {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2} {X:0>2}...\n", .{
                slice.len,
                slice[0],
                slice[1],
                slice[2],
                slice[3],
                slice[4],
                slice[5],
                slice[6],
                slice[7],
            });
        }
        return digest;
    }

    /// Finalize both SHA-256 and SHA-384 digests simultaneously.
    /// Used to cache transcript hash at key points (e.g., after ClientHello).
    pub fn snapshot(self: *Transcript) HashDigestCache {
        return .{
            .sha256 = self.finalizeSha256(),
            .sha384 = self.finalizeSha384(),
        };
    }

    /// Reset transcript to initial empty state.
    /// Also clears `locked_hash` so both hashes resume being updated.
    pub fn reset(self: *Transcript) void {
        self.sha256 = Sha256.init(.{});
        self.sha384 = Sha384.init(.{});
        self.locked_hash = null;
    }

    /// Handle HelloRetryRequest by replacing transcript with synthetic message_hash.
    ///
    /// RFC 8446 §4.4.1: When HelloRetryRequest is sent, the transcript is replaced
    /// with a special "message_hash" synthetic message containing Hash(ClientHello1).
    ///
    /// The new transcript becomes:
    /// ```
    /// Transcript = Hash(message_hash || HelloRetryRequest || ClientHello2 || ...)
    /// ```
    ///
    /// This method:
    /// 1. Computes Hash(ClientHello1) from current transcript state
    /// 2. Constructs synthetic message_hash message
    /// 3. Resets transcript and initializes with message_hash
    ///
    /// ## Parameters
    ///
    /// - `client_hello1`: The first ClientHello message bytes (including handshake framing)
    /// - `hash`: Hash algorithm to use (determined by cipher suite)
    ///
    /// ## Usage
    ///
    /// ```zig
    /// // After receiving ClientHello1 and deciding to send HRR:
    /// transcript.handleHelloRetryRequest(client_hello1_bytes, .sha256);
    /// // Now add HelloRetryRequest:
    /// transcript.update(hello_retry_request_bytes);
    /// // Client will send ClientHello2:
    /// transcript.update(client_hello2_bytes);
    /// ```
    ///
    /// ## Security Note
    ///
    /// The message_hash binds the HelloRetryRequest to the original ClientHello1,
    /// preventing downgrade attacks where an attacker modifies ClientHello1 during retry.
    ///
    /// ## RFC Reference
    ///
    /// RFC 8446 §4.4.1:
    /// "When the server responds to a ClientHello with a HelloRetryRequest, the value
    /// of ClientHello1 is replaced with a special synthetic handshake message of
    /// handshake type "message_hash" containing Hash(ClientHello1)."
    pub fn handleHelloRetryRequest(
        self: *Transcript,
        client_hello1: []const u8,
        hash: Hash,
    ) void {
        traceHandshake("[TRANSCRIPT] HelloRetryRequest detected - creating synthetic message_hash\n", .{});

        // Step 1: Compute Hash(ClientHello1) from current transcript
        // The transcript currently contains only ClientHello1
        const ch1_hash = self.finalize(hash);
        const ch1_hash_bytes = ch1_hash.slice();

        if (handshake_trace_enabled) {
            traceHandshake("[TRANSCRIPT] Hash(ClientHello1) = ", .{});
            for (ch1_hash_bytes) |b| {
                traceHandshake("{X:0>2}", .{b});
            }
            traceHandshake("\n", .{});
        }

        // Step 2: Construct synthetic message_hash message
        // Format: [type:1][length:3][hash_value:N]
        // where N is hash length (32 for SHA-256, 48 for SHA-384)
        var message_hash_buf: [4 + 48]u8 = undefined; // Max size: 4-byte header + 48-byte SHA-384
        const hash_len = ch1_hash_bytes.len;

        message_hash_buf[0] = MESSAGE_HASH_TYPE; // 254 (0xFE)
        message_hash_buf[1] = 0; // Length high byte
        message_hash_buf[2] = 0; // Length middle byte
        message_hash_buf[3] = @intCast(hash_len); // Length low byte (32 or 48)
        @memcpy(message_hash_buf[4 .. 4 + hash_len], ch1_hash_bytes);

        const message_hash_message = message_hash_buf[0 .. 4 + hash_len];

        if (handshake_trace_enabled) {
            traceHandshake("[TRANSCRIPT] Synthetic message_hash ({} bytes): ", .{message_hash_message.len});
            for (message_hash_message) |b| {
                traceHandshake("{X:0>2}", .{b});
            }
            traceHandshake("\n", .{});
        }

        // Step 3: Reset transcript and initialize with synthetic message
        self.reset();
        self.update(message_hash_message);

        traceHandshake("[TRANSCRIPT] Transcript replaced with message_hash. Ready for HRR + ClientHello2.\n", .{});

        // Caller will now add:
        // 1. HelloRetryRequest (ServerHello with HRR random)
        // 2. ClientHello2 (with updated key_share and cookie)
        // 3. Rest of handshake messages

        _ = client_hello1; // May be used in future for additional validation
    }
};

/// Create a synthetic message_hash message for HelloRetryRequest.
///
/// RFC 8446 §4.4.1: The message_hash is a synthetic handshake message with
/// type 254 containing Hash(ClientHello1).
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for the returned buffer
/// - `client_hello1_hash`: Hash of the first ClientHello (32 or 48 bytes)
///
/// ## Returns
///
/// - Handshake-framed message: [254][0][0][len][hash_bytes]
/// - Caller owns returned slice and must free it
///
/// ## Wire Format
///
/// ```
/// struct {
///     HandshakeType msg_type = message_hash(254);
///     uint24 length = Hash.length;
///     opaque hash_output<Hash.length>;
/// } MessageHash;
/// ```
///
/// ## Usage
///
/// ```zig
/// const ch1_hash: [32]u8 = ...; // Hash(ClientHello1)
/// const msg_hash = try createMessageHash(allocator, &ch1_hash);
/// defer allocator.free(msg_hash);
/// transcript.update(msg_hash);
/// ```
pub fn createMessageHash(allocator: std.mem.Allocator, client_hello1_hash: []const u8) ![]u8 {
    // Validate hash length (must be 32 for SHA-256 or 48 for SHA-384)
    if (client_hello1_hash.len != 32 and client_hello1_hash.len != 48) {
        return error.InvalidHashLength;
    }

    // Allocate buffer: 4-byte header + hash
    var buf = try allocator.alloc(u8, 4 + client_hello1_hash.len);

    // Construct message: [type][length:3][hash]
    buf[0] = MESSAGE_HASH_TYPE; // 254
    buf[1] = 0; // Length high byte
    buf[2] = 0; // Length middle byte
    buf[3] = @intCast(client_hello1_hash.len); // Length low byte
    @memcpy(buf[4..], client_hello1_hash);

    return buf;
}

/// Cache of transcript hash digests for both SHA-256 and SHA-384.
/// Used to store snapshots at key handshake points.
pub const HashDigestCache = struct {
    sha256: ?Secret = null,
    sha384: ?Secret = null,

    pub fn set(self: *HashDigestCache, hash: Hash, digest: Secret) void {
        switch (hash) {
            .sha256 => self.sha256 = digest,
            .sha384 => self.sha384 = digest,
        }
    }

    pub fn get(self: *const HashDigestCache, hash: Hash) ?Secret {
        return switch (hash) {
            .sha256 => self.sha256,
            .sha384 => self.sha384,
        };
    }

    pub fn clear(self: *HashDigestCache) void {
        self.sha256 = null;
        self.sha384 = null;
    }
};

/// RFC 8446 §4.4.1: transcripts and cached hashes used across handshake flights.
pub const TranscriptSet = struct {
    handshake: Transcript,
    client_hello_hash: HashDigestCache = .{},
    finished_hash: HashDigestCache = .{},

    /// Creates a new transcript set with empty transcripts.
    pub fn init() TranscriptSet {
        return .{ .handshake = Transcript.init(), .client_hello_hash = .{}, .finished_hash = .{} };
    }

    /// Resets all transcripts to their initial empty state.
    pub fn reset(self: *TranscriptSet) void {
        self.handshake.reset();
        self.client_hello_hash.clear();
        self.finished_hash.clear();
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "MESSAGE_HASH_TYPE constant value" {
    const testing = std.testing;

    // RFC 8446 §4.4.1: message_hash type is 254 (0xFE)
    try testing.expectEqual(254, MESSAGE_HASH_TYPE);
}

test "createMessageHash - SHA-256" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create a 32-byte hash (SHA-256)
    var ch1_hash: [32]u8 = undefined;
    std.testing.io.random(&ch1_hash);

    const msg_hash = try createMessageHash(allocator, &ch1_hash);
    defer allocator.free(msg_hash);

    // Verify structure: [type:1][length:3][hash:32]
    try testing.expectEqual(4 + 32, msg_hash.len);
    try testing.expectEqual(MESSAGE_HASH_TYPE, msg_hash[0]);
    try testing.expectEqual(@as(u8, 0), msg_hash[1]); // Length high byte
    try testing.expectEqual(@as(u8, 0), msg_hash[2]); // Length middle byte
    try testing.expectEqual(@as(u8, 32), msg_hash[3]); // Length low byte
    try testing.expectEqualSlices(u8, &ch1_hash, msg_hash[4..]);
}

test "createMessageHash - SHA-384" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create a 48-byte hash (SHA-384)
    var ch1_hash: [48]u8 = undefined;
    std.testing.io.random(&ch1_hash);

    const msg_hash = try createMessageHash(allocator, &ch1_hash);
    defer allocator.free(msg_hash);

    // Verify structure: [type:1][length:3][hash:48]
    try testing.expectEqual(4 + 48, msg_hash.len);
    try testing.expectEqual(MESSAGE_HASH_TYPE, msg_hash[0]);
    try testing.expectEqual(@as(u8, 0), msg_hash[1]);
    try testing.expectEqual(@as(u8, 0), msg_hash[2]);
    try testing.expectEqual(@as(u8, 48), msg_hash[3]);
    try testing.expectEqualSlices(u8, &ch1_hash, msg_hash[4..]);
}

test "createMessageHash - invalid hash length" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // 31 bytes (invalid - not 32 or 48)
    var invalid_hash: [31]u8 = undefined;
    std.testing.io.random(&invalid_hash);

    try testing.expectError(error.InvalidHashLength, createMessageHash(allocator, &invalid_hash));

    // 40 bytes (invalid)
    var invalid_hash2: [40]u8 = undefined;
    std.testing.io.random(&invalid_hash2);

    try testing.expectError(error.InvalidHashLength, createMessageHash(allocator, &invalid_hash2));
}

test "Transcript.handleHelloRetryRequest - SHA-256" {
    const testing = std.testing;

    // Create a fake ClientHello1
    const client_hello1 = "fake_client_hello_1_for_testing_purposes";

    // Initialize transcript and add ClientHello1
    var transcript = Transcript.init();
    transcript.update(client_hello1);

    // Get hash before HRR handling
    const ch1_hash_before = transcript.finalize(.sha256);
    const ch1_hash_bytes = ch1_hash_before.slice();

    // Handle HelloRetryRequest
    transcript.handleHelloRetryRequest(client_hello1, .sha256);

    // After HRR handling, transcript should contain message_hash
    // Finalize transcript to get Hash(message_hash)
    const transcript_after_hrr = transcript.finalize(.sha256);

    // The transcript should NOT equal the original ClientHello1 hash
    try testing.expect(!std.mem.eql(u8, ch1_hash_bytes, transcript_after_hrr.slice()));

    // Verify the transcript was reset and now contains synthetic message
    // We can verify this by manually computing what it should be:
    // Hash(message_hash) where message_hash = [254][0][0][32][Hash(CH1)]

    var expected_transcript = Transcript.init();
    var message_hash_buf: [4 + 32]u8 = undefined;
    message_hash_buf[0] = 254;
    message_hash_buf[1] = 0;
    message_hash_buf[2] = 0;
    message_hash_buf[3] = 32;
    @memcpy(message_hash_buf[4..], ch1_hash_bytes);
    expected_transcript.update(&message_hash_buf);

    const expected_hash = expected_transcript.finalize(.sha256);
    try testing.expectEqualSlices(u8, expected_hash.slice(), transcript_after_hrr.slice());
}

test "Transcript.handleHelloRetryRequest - SHA-384" {
    const testing = std.testing;

    const client_hello1 = "fake_client_hello_1_for_testing_sha384";

    var transcript = Transcript.init();
    transcript.update(client_hello1);

    const ch1_hash_before = transcript.finalize(.sha384);
    const ch1_hash_bytes = ch1_hash_before.slice();
    try testing.expectEqual(48, ch1_hash_bytes.len); // SHA-384 is 48 bytes

    transcript.handleHelloRetryRequest(client_hello1, .sha384);

    const transcript_after_hrr = transcript.finalize(.sha384);

    // Verify it's different from original
    try testing.expect(!std.mem.eql(u8, ch1_hash_bytes, transcript_after_hrr.slice()));

    // Verify correctness by manual computation
    var expected_transcript = Transcript.init();
    var message_hash_buf: [4 + 48]u8 = undefined;
    message_hash_buf[0] = 254;
    message_hash_buf[1] = 0;
    message_hash_buf[2] = 0;
    message_hash_buf[3] = 48;
    @memcpy(message_hash_buf[4..], ch1_hash_bytes);
    expected_transcript.update(&message_hash_buf);

    const expected_hash = expected_transcript.finalize(.sha384);
    try testing.expectEqualSlices(u8, expected_hash.slice(), transcript_after_hrr.slice());
}

test "Transcript.handleHelloRetryRequest - full flow simulation" {
    const testing = std.testing;

    // Simulate full HRR flow with realistic message flow
    const client_hello1 = "ClientHello1_with_x25519_key_share";
    const hello_retry_request = "ServerHello_with_HRR_random_and_cookie";
    const client_hello2 = "ClientHello2_with_secp256r1_key_share_and_cookie";

    // Normal flow (without HRR) for comparison
    var normal_transcript = Transcript.init();
    normal_transcript.update(client_hello1);
    normal_transcript.update(hello_retry_request);
    normal_transcript.update(client_hello2);
    const normal_hash = normal_transcript.finalize(.sha256);

    // HRR flow
    var hrr_transcript = Transcript.init();
    hrr_transcript.update(client_hello1);

    // Compute Hash(CH1) before handling HRR
    const ch1_hash = hrr_transcript.finalize(.sha256);

    // Handle HRR (replaces transcript with message_hash)
    hrr_transcript.handleHelloRetryRequest(client_hello1, .sha256);

    // Add HRR and CH2
    hrr_transcript.update(hello_retry_request);
    hrr_transcript.update(client_hello2);

    const hrr_hash = hrr_transcript.finalize(.sha256);

    // The two flows should produce different transcript hashes
    try testing.expect(!std.mem.eql(u8, normal_hash.slice(), hrr_hash.slice()));

    // Verify HRR flow matches manual construction
    var manual_transcript = Transcript.init();

    // Add message_hash
    var message_hash_buf: [4 + 32]u8 = undefined;
    message_hash_buf[0] = 254;
    message_hash_buf[1] = 0;
    message_hash_buf[2] = 0;
    message_hash_buf[3] = 32;
    @memcpy(message_hash_buf[4..], ch1_hash.slice());
    manual_transcript.update(&message_hash_buf);

    // Add HRR and CH2
    manual_transcript.update(hello_retry_request);
    manual_transcript.update(client_hello2);

    const manual_hash = manual_transcript.finalize(.sha256);

    // HRR flow should match manual construction
    try testing.expectEqualSlices(u8, manual_hash.slice(), hrr_hash.slice());
}

test "Transcript.handleHelloRetryRequest - idempotency check" {
    const testing = std.testing;

    const client_hello1 = "test_client_hello_for_idempotency";

    var transcript = Transcript.init();
    transcript.update(client_hello1);

    // Handle HRR once
    transcript.handleHelloRetryRequest(client_hello1, .sha256);
    const hash1 = transcript.finalize(.sha256);

    // Handle HRR again (should replace with new message_hash of current state)
    transcript.handleHelloRetryRequest(client_hello1, .sha256);
    const hash2 = transcript.finalize(.sha256);

    // Second HRR should produce different result (it hashes the message_hash)
    try testing.expect(!std.mem.eql(u8, hash1.slice(), hash2.slice()));
}

test "Transcript basic update and finalize - no HRR" {
    const testing = std.testing;

    var transcript = Transcript.init();

    // Add some messages
    transcript.update("message1");
    transcript.update("message2");
    transcript.update("message3");

    // Finalize both hashes
    const sha256_hash = transcript.finalize(.sha256);
    const sha384_hash = transcript.finalize(.sha384);

    // Hashes should be different lengths
    try testing.expectEqual(32, sha256_hash.slice().len);
    try testing.expectEqual(48, sha384_hash.slice().len);

    // Hashes should be non-zero (not uninitialized)
    var all_zero_256 = true;
    for (sha256_hash.slice()) |b| {
        if (b != 0) {
            all_zero_256 = false;
            break;
        }
    }
    try testing.expect(!all_zero_256);

    var all_zero_384 = true;
    for (sha384_hash.slice()) |b| {
        if (b != 0) {
            all_zero_384 = false;
            break;
        }
    }
    try testing.expect(!all_zero_384);
}

test "Transcript.lockHash - only updates locked algorithm" {
    const testing = std.testing;

    // Build a reference transcript without locking
    var ref = Transcript.init();
    ref.update("ClientHello");
    ref.update("ServerHello");
    ref.update("EncryptedExtensions");

    // Build a transcript that locks after ServerHello
    var locked = Transcript.init();
    locked.update("ClientHello");
    locked.update("ServerHello");
    locked.lockHash(.sha256);
    locked.update("EncryptedExtensions");

    // The SHA-256 finalize should match the reference (both saw all messages)
    const ref_256 = ref.finalize(.sha256);
    const locked_256 = locked.finalize(.sha256);
    try testing.expectEqualSlices(u8, ref_256.slice(), locked_256.slice());

    // The SHA-384 should NOT match because the locked transcript skipped
    // updating SHA-384 for "EncryptedExtensions"
    const ref_384 = ref.finalize(.sha384);
    const locked_384 = locked.finalize(.sha384);
    try testing.expect(!std.mem.eql(u8, ref_384.slice(), locked_384.slice()));
}

test "Transcript.lockHash - reset clears lock" {
    const testing = std.testing;

    var transcript = Transcript.init();
    transcript.lockHash(.sha256);
    try testing.expect(transcript.locked_hash != null);

    transcript.reset();
    try testing.expect(transcript.locked_hash == null);
}
