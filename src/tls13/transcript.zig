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
//! # Usage
//!
//! ```zig
//! var transcript = Transcript.init();
//! transcript.update(client_hello_bytes);
//! transcript.update(server_hello_bytes);
//! const hash = transcript.finalize(.sha256);
//! // Use hash for Finished message verification
//! ```

const std = @import("std");
const ks = @import("quic_tls");

const Hash = ks.Hash;
const Secret = ks.Secret;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;

/// Debug tracing controls.
/// Set to true locally when diagnosing handshake flows; disabled in production builds.
const handshake_trace_enabled = false;
const secret_trace_enabled = false;

inline fn traceHandshake(comptime fmt: []const u8, args: anytype) void {
    if (handshake_trace_enabled) std.debug.print(fmt, args);
}

inline fn traceSecrets(comptime fmt: []const u8, args: anytype) void {
    if (secret_trace_enabled) std.debug.print(fmt, args);
}

/// RFC 8446 §4.4.1: Transcript hash management
///
/// Maintains both SHA-256 and SHA-384 hash states concurrently to support
/// multiple cipher suites without knowing which hash algorithm will be used
/// until cipher suite negotiation completes.
pub const Transcript = struct {
    sha256: Sha256,
    sha384: Sha384,

    /// Initialize a new transcript hash helper.
    /// RFC 8446 §4.4.1: Transcript hash begins empty
    pub fn init() Transcript {
        return .{
            .sha256 = Sha256.init(.{}),
            .sha384 = Sha384.init(.{}),
        };
    }

    /// Update transcript with raw bytes (handshake messages).
    /// RFC 8446 §4.4.1: Messages MUST be included in order sent/received
    ///
    /// This updates both SHA-256 and SHA-384 states. The negotiated cipher suite
    /// determines which hash is finalized for secret derivation.
    pub fn update(self: *Transcript, msg: []const u8) void {
        self.sha256.update(msg);
        self.sha384.update(msg);

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
    pub fn reset(self: *Transcript) void {
        self.sha256 = Sha256.init(.{});
        self.sha384 = Sha384.init(.{});
    }
};

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
        return .{
            .handshake = Transcript.init(),
            .client_hello_hash = .{},
            .finished_hash = .{}
        };
    }

    /// Resets all transcripts to their initial empty state.
    pub fn reset(self: *TranscriptSet) void {
        self.handshake.reset();
        self.client_hello_hash.clear();
        self.finished_hash.clear();
    }
};
