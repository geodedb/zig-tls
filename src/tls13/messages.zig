//! Handshake Message Parsing and Encoding
//!
//! RFC 8446 §4: Handshake Protocol
//! RFC 9001 §8.3: QUIC-specific constraints
//!
//! This module provides utilities for encoding and parsing TLS 1.3 handshake
//! messages in the QUIC context. It handles the basic message framing (type
//! and length) and provides helpers for minimal test messages.

const std = @import("std");

/// Debug tracing for handshake messages.
const handshake_trace_enabled = false;

inline fn traceHandshake(comptime fmt: []const u8, args: anytype) void {
    if (handshake_trace_enabled) std.debug.print(fmt, args);
}

/// TLS 1.3 handshake message types (RFC 8446 §4).
pub const HsType = enum(u8) {
    /// ClientHello message (RFC 8446 §4.1.2).
    client_hello = 1,
    /// ServerHello message (RFC 8446 §4.1.3).
    server_hello = 2,
    /// NewSessionTicket for resumption (RFC 8446 §4.6.1).
    new_session_ticket = 4,
    /// EncryptedExtensions message (RFC 8446 §4.3.1).
    encrypted_extensions = 8,
    /// Certificate message (RFC 8446 §4.4.2).
    certificate = 11,
    /// CertificateVerify message (RFC 8446 §4.4.3).
    certificate_verify = 15,
    /// Finished message (RFC 8446 §4.4.4).
    finished = 20,
};

/// Parsed handshake message with type and body reference.
pub const HandshakeMessage = struct {
    typ: HsType,
    body: []const u8,
    n: usize,
};

/// Encode a TLS handshake message with type and 24-bit length prefix.
///
/// RFC 8446 §4: Handshake protocol message format:
/// ```
/// struct {
///     HandshakeType msg_type;    // 1 byte
///     uint24 length;             // 3 bytes (big-endian)
///     opaque body[length];
/// } Handshake;
/// ```
///
/// # Parameters
/// - alloc: Allocator for the returned buffer
/// - typ: Handshake message type (client_hello, server_hello, etc.)
/// - body: Message body bytes (varies by type)
///
/// # Returns
/// Allocated buffer containing: [type:1][length:3][body:N]
/// Caller owns returned slice and must free it.
///
/// # Example
/// ```zig
/// const finished_body: [32]u8 = ... // verify_data
/// const msg = try encodeHandshake(allocator, .finished, &finished_body);
/// defer allocator.free(msg);
/// ```
pub fn encodeHandshake(alloc: std.mem.Allocator, typ: HsType, body: []const u8) ![]u8 {
    var out = try alloc.alloc(u8, 4 + body.len);
    out[0] = @intFromEnum(typ);
    const L: u32 = @intCast(body.len);
    // 24-bit big-endian length
    out[1] = @intCast((L >> 16) & 0xff);
    out[2] = @intCast((L >> 8) & 0xff);
    out[3] = @intCast(L & 0xff);
    @memcpy(out[4..], body);
    return out;
}

/// Parse one complete handshake message from buffered CRYPTO data.
///
/// RFC 8446 §4: Attempts to parse a single handshake message from the input.
/// Returns null if insufficient data available (caller should buffer more).
///
/// RFC 9001 §8.3: Validates that end_of_early_data (type 5) is not sent over QUIC.
///
/// # Parameters
/// - data: Buffered CRYPTO data (may contain partial or multiple messages)
///
/// # Returns
/// - `HandshakeMessage`: Parsed message with type, body slice, and total bytes consumed
/// - `null`: Need more data (fewer than 4 bytes, or incomplete body)
/// - `error`: Protocol violation (e.g., end_of_early_data in QUIC)
///
/// # Usage Pattern
/// ```zig
/// while (true) {
///     const parsed = try parseHandshakeOne(buffer) orelse break;
///     // Process parsed.typ and parsed.body
///     buffer = buffer[parsed.n..]; // Consume bytes
/// }
/// ```
///
/// # Notes
/// - Returned `body` slice points into input `data` (no allocation)
/// - Caller must track consumed bytes via `n` field
/// - Handles fragmentation across QUIC packets via buffering
pub fn parseHandshakeOne(data: []const u8) !?HandshakeMessage {
    if (data.len < 4) return null; // Need at least type + length
    const t_byte = data[0];

    // RFC 9001 §8.3: EndOfEarlyData (type 5) MUST NOT be sent over QUIC
    // Early data termination is implicit when sending on higher encryption level
    if (t_byte == 5) {
        traceHandshake("TLS: Received EndOfEarlyData message (RFC 9001 violation - type 5 prohibited)\n", .{});
        return error.ProtocolViolation;
    }

    const typ: HsType = std.meta.intToEnum(HsType, t_byte) catch return error.UnknownHandshakeType;

    // Parse 24-bit big-endian length
    const L: usize = (@as(usize, data[1]) << 16) | (@as(usize, data[2]) << 8) | @as(usize, data[3]);
    const need = 4 + L;

    if (data.len < need) return null; // Incomplete message body

    return HandshakeMessage{
        .typ = typ,
        .body = data[4 .. 4 + L], // Slice into input buffer
        .n = need, // Total bytes consumed
    };
}

/// Generate X25519 keypair and optionally compute shared secret.
///
/// # Parameters
/// - peer_pub_opt: Optional peer public key for ECDHE computation
///
/// # Returns
/// Struct containing:
/// - priv_key: Generated private key (32 bytes)
/// - pub_key: Corresponding public key (32 bytes)
/// - shared: ECDHE shared secret if peer_pub_opt provided, null otherwise
///
/// # Usage
/// ```zig
/// // Generate keypair only
/// const keys = x25519KeypairAndShared(null);
///
/// // Generate keypair and compute shared secret
/// const keys = x25519KeypairAndShared(peer_public_key);
/// if (keys.shared) |secret| {
///     // Use secret for key derivation
/// }
/// ```
pub fn x25519KeypairAndShared(peer_pub_opt: ?[32]u8) struct { priv_key: [32]u8, pub_key: [32]u8, shared: ?[32]u8 } {
    var sk: [32]u8 = undefined;
    std.crypto.random.bytes(&sk);
    // Zig 0.15.1 API: recoverPublicKey derives public key from private key
    const pk = std.crypto.dh.X25519.recoverPublicKey(sk) catch unreachable;
    var shared: ?[32]u8 = null;
    if (peer_pub_opt) |peer_pub| {
        // Zig 0.15.1 API: scalarmult returns the shared secret directly
        const sh = std.crypto.dh.X25519.scalarmult(sk, peer_pub) catch {
            shared = null;
            return .{ .priv_key = sk, .pub_key = pk, .shared = shared };
        };
        shared = sh;
    }
    return .{ .priv_key = sk, .pub_key = pk, .shared = shared };
}

/// Encode a minimalistic ClientHello body carrying an X25519 key share only (non-interoperable placeholder).
///
/// This creates a minimal "CH1" format for testing. For real TLS 1.3 interoperability,
/// use tls13_full.buildClientHello() instead.
///
/// Format: "CH1" || client_pub[32]
pub fn encodeMinimalClientHello(alloc: std.mem.Allocator, client_pub: [32]u8) ![]u8 {
    // Body: "CH1" || client_pub
    var body: [3 + 32]u8 = undefined;
    body[0] = 'C';
    body[1] = 'H';
    body[2] = '1';
    @memcpy(body[3..], &client_pub);
    return encodeHandshake(alloc, .client_hello, body[0..]);
}

/// Encode a minimalistic ServerHello body carrying an X25519 key share only (non-interoperable placeholder).
///
/// This creates a minimal "SH1" format for testing. For real TLS 1.3 interoperability,
/// use tls13_full.buildServerHello() instead.
///
/// Format: "SH1" || server_pub[32]
pub fn encodeMinimalServerHello(alloc: std.mem.Allocator, server_pub: [32]u8) ![]u8 {
    var body: [3 + 32]u8 = undefined;
    body[0] = 'S';
    body[1] = 'H';
    body[2] = '1';
    @memcpy(body[3..], &server_pub);
    return encodeHandshake(alloc, .server_hello, body[0..]);
}

/// Attempt to parse minimal CH/SH and return pubkeys if present.
///
/// Recognizes the minimal "CH1" and "SH1" test formats. Returns null if
/// the message doesn't match the expected minimal format.
///
/// # Parameters
/// - typ: Expected message type
/// - body: Message body bytes
///
/// # Returns
/// - X25519 public key (32 bytes) if minimal format recognized
/// - null if not a minimal format message
pub fn parseMinimalHelloPub(typ: HsType, body: []const u8) ?[32]u8 {
    if (body.len != 3 + 32) return null;
    if (typ == .client_hello and std.mem.eql(u8, body[0..3], "CH1")) {
        var pk: [32]u8 = undefined;
        @memcpy(&pk, body[3..]);
        return pk;
    }
    if (typ == .server_hello and std.mem.eql(u8, body[0..3], "SH1")) {
        var pk: [32]u8 = undefined;
        @memcpy(&pk, body[3..]);
        return pk;
    }
    return null;
}
