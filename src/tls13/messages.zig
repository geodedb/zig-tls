// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Handshake Message Parsing and Encoding
//!
//! RFC 8446 §4: Handshake Protocol
//! RFC 9001 §8.3: QUIC-specific constraints
//!
//! This module provides utilities for encoding and parsing TLS 1.3 handshake
//! messages in the QUIC context. It handles the basic message framing (type
//! and length) and provides helpers for minimal test messages.

const std = @import("std");
const entropy = @import("entropy");
const logger = @import("quic_logger");
// fips-exempt: non-security — secure memory zeroization, not a crypto algorithm.
const secureZero = std.crypto.secureZero;
// fips-exempt: standalone X25519 is NOT a FIPS-approved key-agreement and the
// seam has no raw X25519 DH primitive. This helper is only consumed by tests
// and the public re-export; the FIPS handshake path uses the fail-closed,
// comptime-guarded code in tls13/context.zig (consumer-owned escape hatch).
const X25519 = std.crypto.dh.X25519;

/// Debug tracing for handshake messages.
const handshake_trace_enabled = false;

// SEC-049: Compile-time safety: prevent handshake trace logging in release builds.
// Handshake traces can leak error details, cipher suite info, and other metadata
// that aids attackers in fingerprinting or exploiting the TLS implementation.
comptime {
    if (handshake_trace_enabled and @import("builtin").mode != .Debug) {
        @compileError("SECURITY: handshake_trace_enabled must be false in release builds — handshake metadata would be logged");
    }
}

inline fn traceHandshake(comptime fmt: []const u8, args: anytype) void {
    if (handshake_trace_enabled) logger.debugPrint(fmt, args);
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
    /// CertificateRequest message (RFC 8446 §4.3.2).
    certificate_request = 13,
    /// CertificateVerify message (RFC 8446 §4.4.3).
    certificate_verify = 15,
    /// Finished message (RFC 8446 §4.4.4).
    finished = 20,
    /// KeyUpdate message for refreshing traffic keys (RFC 8446 §4.6.3).
    key_update = 24,
};

/// KeyUpdate request type (RFC 8446 §4.6.3).
///
/// Indicates whether the peer should also update its keys in response.
pub const KeyUpdateRequest = enum(u8) {
    /// Sender has updated its keys, peer should NOT respond with KeyUpdate.
    update_not_requested = 0,
    /// Sender has updated its keys AND requests peer to also update.
    update_requested = 1,
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

/// Zero-allocation variant of encodeHandshake that writes into a caller-provided buffer.
///
/// PERF-013: Enables server flight batching without per-message allocation.
/// Writes the 4-byte handshake header (type + 24-bit length) followed by the body
/// into `buf`, and returns the total number of bytes written.
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
/// - buf: Caller-provided output buffer (must be at least 4 + body.len bytes)
/// - typ: Handshake message type
/// - body: Message body bytes
///
/// # Returns
/// Total bytes written (4 + body.len)
///
/// # Errors
/// - `error.BufferTooSmall`: `buf` is shorter than 4 + body.len
pub fn encodeHandshakeBuf(buf: []u8, typ: HsType, body: []const u8) !usize {
    const total = 4 + body.len;
    if (buf.len < total) return error.BufferTooSmall;
    buf[0] = @intFromEnum(typ);
    const L: u32 = @intCast(body.len);
    buf[1] = @intCast((L >> 16) & 0xff);
    buf[2] = @intCast((L >> 8) & 0xff);
    buf[3] = @intCast(L & 0xff);
    @memcpy(buf[4..][0..body.len], body);
    return total;
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

    // Zig 0.16 compat: std.meta.intToEnum was removed; validate manually.
    const typ: HsType = switch (t_byte) {
        1, 2, 4, 8, 11, 13, 15, 20, 24 => @enumFromInt(t_byte),
        else => {
            const dump_len: usize = if (data.len < 32) data.len else 32;
            logger.debugPrint(
                "TLS: Unknown handshake type byte=0x{X}, buf_len={}, head={any}\n",
                .{ t_byte, data.len, data[0..dump_len] },
            );
            return error.UnknownHandshakeType;
        },
    };

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
/// # Security Considerations (CWE-226)
/// The caller is responsible for zeroizing the returned priv_key after use
/// via `secureZero(u8, &keys.priv_key)`. Private keys should not
/// be stored longer than necessary and must be zeroized before the memory
/// is released or goes out of scope.
///
/// # Usage
/// ```zig
/// // Generate keypair only
/// var keys = try x25519KeypairAndShared(null);
/// defer secureZero(u8, &keys.priv_key);
///
/// // Generate keypair and compute shared secret
/// var keys = try x25519KeypairAndShared(peer_public_key);
/// defer secureZero(u8, &keys.priv_key);
/// if (keys.shared) |secret| {
///     // Use secret for key derivation
/// }
/// ```
pub const X25519Result = struct { priv_key: [32]u8, pub_key: [32]u8, shared: ?[32]u8 };

/// SEC-009: X25519 errors surfaced to callers instead of silently returning zeroed keys.
pub const X25519Error = error{
    /// The peer's public key is a weak/low-order point (e.g. all-zeros),
    /// producing an all-zero shared secret. Continuing would be insecure.
    WeakPublicKey,
};

pub fn x25519KeypairAndShared(peer_pub_opt: ?[32]u8) X25519Error!X25519Result {
    var sk: [32]u8 = undefined;
    defer secureZero(u8, &sk);
    // SEC-074: fail-closed entropy (shared helper; replaces local cryptoRandom).
    entropy.fillRandom(&sk);
    // SAFETY: recoverPublicKey only fails when the private key is the all-zero point (producing
    // a weak public key). Since sk is filled from entropy.fillRandom, the probability of
    // generating an all-zero 32-byte key is ~2^-256, which is cryptographically negligible.
    const pk = X25519.recoverPublicKey(sk) catch unreachable;
    var shared: ?[32]u8 = null;
    if (peer_pub_opt) |peer_pub| {
        // Zig 0.15.1 API: scalarmult returns the shared secret directly
        const sh = X25519.scalarmult(sk, peer_pub) catch {
            // SEC-009: Return an error instead of silently returning zeroed keys.
            // The caller can decide how to handle a weak peer public key.
            return X25519Error.WeakPublicKey;
        };
        shared = sh;
    }
    return .{ .priv_key = sk, .pub_key = pk, .shared = shared };
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

/// Build a KeyUpdate message (RFC 8446 §4.6.3).
///
/// RFC 8446 §4.6.3:
/// ```
/// struct {
///     KeyUpdateRequest request_update;
/// } KeyUpdate;
///
/// enum { update_not_requested(0), update_requested(1) } KeyUpdateRequest;
/// ```
///
/// # Parameters
/// - alloc: Allocator for the returned buffer
/// - request_update: If true, requests peer to also update keys
///
/// # Returns
/// Allocated buffer containing complete KeyUpdate handshake message.
/// Caller owns returned slice and must free it.
///
/// # Example
/// ```zig
/// // Update our keys without requesting peer update
/// const ku_msg = try buildKeyUpdate(allocator, false);
/// defer allocator.free(ku_msg);
///
/// // Update our keys AND request peer to update
/// const ku_msg2 = try buildKeyUpdate(allocator, true);
/// defer allocator.free(ku_msg2);
/// ```
pub fn buildKeyUpdate(alloc: std.mem.Allocator, request_update: bool) ![]u8 {
    const request: KeyUpdateRequest = if (request_update) .update_requested else .update_not_requested;
    const body = [_]u8{@intFromEnum(request)};
    return encodeHandshake(alloc, .key_update, &body);
}

/// Parse a KeyUpdate message body (RFC 8446 §4.6.3).
///
/// Extracts the KeyUpdateRequest field from the message body.
///
/// # Parameters
/// - body: Message body bytes (should be exactly 1 byte)
///
/// # Returns
/// - `KeyUpdateRequest`: The parsed request type
/// - `error.InvalidKeyUpdateLength`: Body is not exactly 1 byte
/// - `error.InvalidKeyUpdateRequest`: Body contains invalid enum value (not 0 or 1)
///
/// # Example
/// ```zig
/// const msg = try parseHandshakeOne(buffer) orelse return;
/// if (msg.typ == .key_update) {
///     const request = try parseKeyUpdate(msg.body);
///     if (request == .update_requested) {
///         // Peer wants us to update keys too
///     }
/// }
/// ```
pub fn parseKeyUpdate(body: []const u8) !KeyUpdateRequest {
    if (body.len != 1) return error.InvalidKeyUpdateLength;
    return switch (body[0]) {
        0, 1 => @enumFromInt(body[0]),
        else => error.InvalidKeyUpdateRequest,
    };
}

// ============================================================================
// GAP-0132: NewSessionTicket (RFC 8446 §4.6.1)
//
// Wire layout (RFC 8446 §4.6.1):
//   struct {
//       uint32 ticket_lifetime;
//       uint32 ticket_age_add;
//       opaque ticket_nonce<0..255>;
//       opaque ticket<1..2^16-1>;
//       Extension extensions<0..2^16-2>;
//   } NewSessionTicket;
//
// The build path is server-side; the parse path is client-side. The client
// dispatches the parsed ticket to `Callbacks.on_session_ticket` so the
// application layer can persist it for resumption.
// ============================================================================

/// Parameters for `buildNewSessionTicket`. The opaque `ticket` blob is
/// server-defined (typically an encrypted state envelope keyed off the
/// session-ticket master key); this module only handles the wire format.
pub const NewSessionTicketParams = struct {
    /// Lifetime hint in seconds (RFC 8446 §4.6.1: MUST NOT exceed 7 days).
    /// Callers are expected to enforce the upper bound; the encoder honours
    /// any 32-bit value the server chooses.
    ticket_lifetime: u32,
    /// Per-ticket random offset added to the obfuscated ticket age in
    /// resumption ClientHellos (RFC 8446 §4.2.11.1).
    ticket_age_add: u32,
    /// `opaque ticket_nonce<0..255>` — distinguishes tickets issued from
    /// the same resumption_master_secret (RFC 8446 §4.6.1).
    ticket_nonce: []const u8,
    /// `opaque ticket<1..2^16-1>` — the server-defined ticket blob.
    ticket: []const u8,
    /// Pre-encoded extensions block (raw ext_type+ext_len+ext_data
    /// concatenation, NO outer u16 length prefix). Defaults to empty.
    extensions: []const u8 = &[_]u8{},
};

/// Parsed NewSessionTicket wire fields. All slices borrow from the input
/// `body`; the parse is zero-allocation.
pub const ParsedNewSessionTicket = struct {
    ticket_lifetime: u32,
    ticket_age_add: u32,
    ticket_nonce: []const u8,
    ticket: []const u8,
    /// Raw bytes of the `Extension` list (no outer length prefix, suitable
    /// for re-encoding or for further parsing by extension-aware callers).
    extensions: []const u8,
};

/// Build a NewSessionTicket message body (RFC 8446 §4.6.1). Returns an
/// allocator-owned slice containing only the body bytes — wrap with
/// `encodeHandshake(.new_session_ticket, body)` to add the 4-byte
/// handshake header.
pub fn buildNewSessionTicket(alloc: std.mem.Allocator, params: NewSessionTicketParams) ![]u8 {
    if (params.ticket_nonce.len > 255) return error.TicketNonceTooLong;
    if (params.ticket.len < 1) return error.InvalidTicketLength;
    if (params.ticket.len > std.math.maxInt(u16)) return error.InvalidTicketLength;
    if (params.extensions.len > std.math.maxInt(u16) - 1) return error.ExtensionsTooLong;

    const total: usize = 4 + 4 + 1 + params.ticket_nonce.len + 2 + params.ticket.len + 2 + params.extensions.len;
    var buf = try alloc.alloc(u8, total);
    errdefer alloc.free(buf);

    var pos: usize = 0;
    std.mem.writeInt(u32, buf[pos..][0..4], params.ticket_lifetime, .big);
    pos += 4;
    std.mem.writeInt(u32, buf[pos..][0..4], params.ticket_age_add, .big);
    pos += 4;
    buf[pos] = @intCast(params.ticket_nonce.len);
    pos += 1;
    @memcpy(buf[pos..][0..params.ticket_nonce.len], params.ticket_nonce);
    pos += params.ticket_nonce.len;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(params.ticket.len), .big);
    pos += 2;
    @memcpy(buf[pos..][0..params.ticket.len], params.ticket);
    pos += params.ticket.len;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(params.extensions.len), .big);
    pos += 2;
    @memcpy(buf[pos..][0..params.extensions.len], params.extensions);
    pos += params.extensions.len;
    std.debug.assert(pos == total);

    return buf;
}

/// Parse a NewSessionTicket body (RFC 8446 §4.6.1). All returned slices
/// borrow from `body`; ownership stays with the caller.
pub fn parseNewSessionTicket(body: []const u8) !ParsedNewSessionTicket {
    // Minimum *header* size: 4 (lifetime) + 4 (age_add) + 1 (nonce_len) +
    // 2 (ticket_len) + 2 (ext_len) = 13. The per-field bounds checks
    // below catch every undersize variable-length payload after that.
    if (body.len < 13) return error.TooShort;

    var pos: usize = 0;
    const ticket_lifetime = std.mem.readInt(u32, body[pos..][0..4], .big);
    pos += 4;
    const ticket_age_add = std.mem.readInt(u32, body[pos..][0..4], .big);
    pos += 4;

    const nonce_len: usize = body[pos];
    pos += 1;
    if (pos + nonce_len > body.len) return error.TooShort;
    const ticket_nonce = body[pos .. pos + nonce_len];
    pos += nonce_len;

    if (pos + 2 > body.len) return error.TooShort;
    const ticket_len: usize = std.mem.readInt(u16, body[pos..][0..2], .big);
    pos += 2;
    if (ticket_len == 0) return error.InvalidTicketLength;
    if (pos + ticket_len > body.len) return error.TooShort;
    const ticket = body[pos .. pos + ticket_len];
    pos += ticket_len;

    if (pos + 2 > body.len) return error.TooShort;
    const ext_len: usize = std.mem.readInt(u16, body[pos..][0..2], .big);
    pos += 2;
    if (pos + ext_len > body.len) return error.TooShort;
    const extensions = body[pos .. pos + ext_len];
    pos += ext_len;

    if (pos != body.len) return error.TrailingBytes;

    return .{
        .ticket_lifetime = ticket_lifetime,
        .ticket_age_add = ticket_age_add,
        .ticket_nonce = ticket_nonce,
        .ticket = ticket,
        .extensions = extensions,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "KeyUpdate: buildKeyUpdate - update_not_requested" {
    const alloc = std.testing.allocator;

    const msg = try buildKeyUpdate(alloc, false);
    defer alloc.free(msg);

    // Verify message structure: [type:1][length:3][body:1]
    try std.testing.expectEqual(@as(usize, 5), msg.len);
    try std.testing.expectEqual(@as(u8, 24), msg[0]); // type = key_update
    try std.testing.expectEqual(@as(u8, 0), msg[1]); // length high byte
    try std.testing.expectEqual(@as(u8, 0), msg[2]); // length mid byte
    try std.testing.expectEqual(@as(u8, 1), msg[3]); // length low byte (1 byte body)
    try std.testing.expectEqual(@as(u8, 0), msg[4]); // body: update_not_requested
}

test "KeyUpdate: buildKeyUpdate - update_requested" {
    const alloc = std.testing.allocator;

    const msg = try buildKeyUpdate(alloc, true);
    defer alloc.free(msg);

    // Verify message structure
    try std.testing.expectEqual(@as(usize, 5), msg.len);
    try std.testing.expectEqual(@as(u8, 24), msg[0]); // type = key_update
    try std.testing.expectEqual(@as(u8, 0), msg[1]);
    try std.testing.expectEqual(@as(u8, 0), msg[2]);
    try std.testing.expectEqual(@as(u8, 1), msg[3]);
    try std.testing.expectEqual(@as(u8, 1), msg[4]); // body: update_requested
}

test "KeyUpdate: parseKeyUpdate - update_not_requested" {
    const body = [_]u8{0}; // update_not_requested
    const request = try parseKeyUpdate(&body);
    try std.testing.expectEqual(KeyUpdateRequest.update_not_requested, request);
}

test "KeyUpdate: parseKeyUpdate - update_requested" {
    const body = [_]u8{1}; // update_requested
    const request = try parseKeyUpdate(&body);
    try std.testing.expectEqual(KeyUpdateRequest.update_requested, request);
}

test "KeyUpdate: parseKeyUpdate - invalid length (empty)" {
    const body = [_]u8{};
    const result = parseKeyUpdate(&body);
    try std.testing.expectError(error.InvalidKeyUpdateLength, result);
}

test "KeyUpdate: parseKeyUpdate - invalid length (too long)" {
    const body = [_]u8{ 0, 0 };
    const result = parseKeyUpdate(&body);
    try std.testing.expectError(error.InvalidKeyUpdateLength, result);
}

test "KeyUpdate: parseKeyUpdate - invalid enum value" {
    const body = [_]u8{2}; // Invalid: only 0 and 1 are valid
    const result = parseKeyUpdate(&body);
    try std.testing.expectError(error.InvalidKeyUpdateRequest, result);
}

test "KeyUpdate: parseKeyUpdate - invalid enum value (255)" {
    const body = [_]u8{255};
    const result = parseKeyUpdate(&body);
    try std.testing.expectError(error.InvalidKeyUpdateRequest, result);
}

test "KeyUpdate: roundtrip - update_not_requested" {
    const alloc = std.testing.allocator;

    // Build message
    const msg = try buildKeyUpdate(alloc, false);
    defer alloc.free(msg);

    // Parse complete message
    const parsed = try parseHandshakeOne(msg);
    try std.testing.expect(parsed != null);
    try std.testing.expectEqual(HsType.key_update, parsed.?.typ);
    try std.testing.expectEqual(@as(usize, 1), parsed.?.body.len);

    // Parse KeyUpdate body
    const request = try parseKeyUpdate(parsed.?.body);
    try std.testing.expectEqual(KeyUpdateRequest.update_not_requested, request);
}

test "KeyUpdate: roundtrip - update_requested" {
    const alloc = std.testing.allocator;

    // Build message
    const msg = try buildKeyUpdate(alloc, true);
    defer alloc.free(msg);

    // Parse complete message
    const parsed = try parseHandshakeOne(msg);
    try std.testing.expect(parsed != null);
    try std.testing.expectEqual(HsType.key_update, parsed.?.typ);
    try std.testing.expectEqual(@as(usize, 1), parsed.?.body.len);

    // Parse KeyUpdate body
    const request = try parseKeyUpdate(parsed.?.body);
    try std.testing.expectEqual(KeyUpdateRequest.update_requested, request);
}

test "KeyUpdate: enum values match RFC 8446" {
    // RFC 8446 §4.6.3: update_not_requested(0), update_requested(1)
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(KeyUpdateRequest.update_not_requested));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(KeyUpdateRequest.update_requested));
}

test "KeyUpdate: HsType enum value matches RFC 8446" {
    // RFC 8446 §4: key_update message type is 24
    try std.testing.expectEqual(@as(u8, 24), @intFromEnum(HsType.key_update));
}

// ============================================================================
// Tests - encodeHandshakeBuf (PERF-013)
// ============================================================================

test "PERF-013: encodeHandshakeBuf writes same output as encodeHandshake" {
    const alloc = std.testing.allocator;
    const body = "test body content";

    // Allocating variant
    const allocated = try encodeHandshake(alloc, .finished, body);
    defer alloc.free(allocated);

    // Zero-alloc variant
    var buf: [256]u8 = undefined;
    const n = try encodeHandshakeBuf(&buf, .finished, body);

    try std.testing.expectEqual(allocated.len, n);
    try std.testing.expectEqualSlices(u8, allocated, buf[0..n]);
}

test "PERF-013: encodeHandshakeBuf returns correct byte count" {
    const body = [_]u8{0xAA} ** 100;
    var buf: [256]u8 = undefined;
    const n = try encodeHandshakeBuf(&buf, .certificate, &body);
    try std.testing.expectEqual(@as(usize, 104), n);
}

test "PERF-013: encodeHandshakeBuf buffer too small" {
    const body = [_]u8{0xBB} ** 100;
    var buf: [50]u8 = undefined;
    const result = encodeHandshakeBuf(&buf, .certificate, &body);
    try std.testing.expectError(error.BufferTooSmall, result);
}

test "PERF-013: encodeHandshakeBuf empty body" {
    var buf: [4]u8 = undefined;
    const n = try encodeHandshakeBuf(&buf, .server_hello, &[_]u8{});
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqual(@as(u8, @intFromEnum(HsType.server_hello)), buf[0]);
    try std.testing.expectEqual(@as(u8, 0), buf[1]);
    try std.testing.expectEqual(@as(u8, 0), buf[2]);
    try std.testing.expectEqual(@as(u8, 0), buf[3]);
}

test "PERF-013: encodeHandshakeBuf roundtrip with parseHandshakeOne" {
    const body = "finished_verify_data_32_bytes!!!";
    var buf: [256]u8 = undefined;
    const n = try encodeHandshakeBuf(&buf, .finished, body);

    const parsed = try parseHandshakeOne(buf[0..n]);
    try std.testing.expect(parsed != null);
    try std.testing.expectEqual(HsType.finished, parsed.?.typ);
    try std.testing.expectEqualSlices(u8, body, parsed.?.body);
    try std.testing.expectEqual(n, parsed.?.n);
}

test "PERF-013: encodeHandshakeBuf exact-fit buffer" {
    const body = [_]u8{0xCC} ** 10;
    var buf: [14]u8 = undefined; // exactly 4 + 10
    const n = try encodeHandshakeBuf(&buf, .encrypted_extensions, &body);
    try std.testing.expectEqual(@as(usize, 14), n);
}

test "SEC-009: x25519KeypairAndShared returns error union — keypair-only succeeds" {
    // Generating a keypair without a peer key should always succeed.
    var result = try x25519KeypairAndShared(null);
    defer secureZero(u8, &result.priv_key);
    // shared must be null when no peer key provided
    try std.testing.expect(result.shared == null);
    // public key must not be all zeros (vanishingly unlikely from random)
    const zero_key = [_]u8{0} ** 32;
    try std.testing.expect(!std.mem.eql(u8, &result.pub_key, &zero_key));
}

test "SEC-009: x25519KeypairAndShared returns WeakPublicKey on all-zero peer key" {
    // An all-zero public key is a low-order point; scalarmult must reject it.
    const zero_peer = [_]u8{0} ** 32;
    const result = x25519KeypairAndShared(zero_peer);
    try std.testing.expectError(X25519Error.WeakPublicKey, result);
}

test "SEC-009: x25519KeypairAndShared computes shared secret with valid peer key" {
    // Generate two keypairs and verify they can derive a shared secret.
    var alice = try x25519KeypairAndShared(null);
    defer secureZero(u8, &alice.priv_key);
    var bob = try x25519KeypairAndShared(null);
    defer secureZero(u8, &bob.priv_key);

    // Alice computes shared secret using Bob's public key
    var alice_shared = try x25519KeypairAndShared(bob.pub_key);
    defer secureZero(u8, &alice_shared.priv_key);

    try std.testing.expect(alice_shared.shared != null);
}

test "SEC-009: x25519KeypairAndShared return type is error union" {
    // Verify at comptime that the return type is an error union.
    comptime {
        const F = @TypeOf(x25519KeypairAndShared);
        const return_type = @typeInfo(F).@"fn".return_type.?;
        if (@typeInfo(return_type) != .error_union) {
            @compileError("x25519KeypairAndShared must return an error union");
        }
    }
}
