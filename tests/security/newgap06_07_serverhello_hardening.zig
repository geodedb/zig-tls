// SPDX-License-Identifier: Apache-2.0
//! NEWGAP-06 / NEWGAP-07 regressions for the client's live ServerHello parser
//! (`Context.handleServerHello`), reached via `processCrypto(.Initial, ...)`.
//!
//! NEWGAP-07 (= QUAL-387): the inline duplicate-extension tracker used a
//! known-types-only `std.EnumSet`, so duplicate UNKNOWN extension types in a
//! real ServerHello bypassed the RFC 8446 §4.2 prohibition (the production
//! twin of the NEWGAP-05 fix to the helper parsers).
//!
//! NEWGAP-06: the client never validated `legacy_session_id_echo`. The client
//! sends an empty `legacy_session_id`, so per RFC 8446 §4.1.3 the echo MUST be
//! empty; a non-empty echo MUST abort with `illegal_parameter`.

const std = @import("std");
const testing = std.testing;
const tls13 = @import("tls13");
const tls13_full = @import("tls13_full");

fn clientCtx() !tls13.Context {
    const client_config = tls13.Config{
        .allocator = testing.allocator,
        .role = .Client,
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{ 0x00, 0x01 },
        .server_name = "test.example.com",
    };
    return tls13.Context.init(client_config, tls13.Callbacks{});
}

/// Frame a ServerHello body (no handshake header) given the raw extensions
/// blob, cipher suite, and session_id. Returns an owned framed handshake msg.
fn frameServerHello(
    alloc: std.mem.Allocator,
    session_id: []const u8,
    cipher: u16,
    exts: []const u8,
) ![]u8 {
    return frameServerHelloComp(alloc, session_id, cipher, 0x00, exts);
}

fn frameServerHelloComp(
    alloc: std.mem.Allocator,
    session_id: []const u8,
    cipher: u16,
    compression: u8,
    exts: []const u8,
) ![]u8 {
    var b = std.ArrayList(u8).empty;
    errdefer b.deinit(alloc);
    try b.appendSlice(alloc, &.{ 0x03, 0x03 }); // legacy_version
    try b.appendNTimes(alloc, 0xAA, 32); // random (not HRR, not downgrade sentinel)
    try b.append(alloc, @intCast(session_id.len)); // session_id len
    try b.appendSlice(alloc, session_id);
    try b.append(alloc, @intCast((cipher >> 8) & 0xff));
    try b.append(alloc, @intCast(cipher & 0xff));
    try b.append(alloc, compression); // compression
    try b.append(alloc, @intCast((exts.len >> 8) & 0xff));
    try b.append(alloc, @intCast(exts.len & 0xff));
    try b.appendSlice(alloc, exts);

    const body_len = b.items.len;
    var msg = std.ArrayList(u8).empty;
    errdefer msg.deinit(alloc);
    try msg.append(alloc, 0x02); // ServerHello handshake type
    try msg.append(alloc, @intCast((body_len >> 16) & 0xff));
    try msg.append(alloc, @intCast((body_len >> 8) & 0xff));
    try msg.append(alloc, @intCast(body_len & 0xff));
    try msg.appendSlice(alloc, b.items);
    b.deinit(alloc);
    return msg.toOwnedSlice(alloc);
}

const supported_versions_ext = [_]u8{ 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };
const key_share_ext = [_]u8{ 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20 } ++ [_]u8{0xBB} ** 32;

test "NEWGAP-07: client rejects duplicate UNKNOWN extension in ServerHello" {
    const alloc = testing.allocator;
    var ctx = try clientCtx();
    defer ctx.deinit();
    try ctx.startClientHandshake();

    // Valid supported_versions + key_share, then two identical UNKNOWN exts.
    const unknown = [_]u8{ 0x8a, 0x8a, 0x00, 0x00 }; // type 0x8a8a, empty body
    var exts = std.ArrayList(u8).empty;
    defer exts.deinit(alloc);
    try exts.appendSlice(alloc, &supported_versions_ext);
    try exts.appendSlice(alloc, &key_share_ext);
    try exts.appendSlice(alloc, &unknown);
    try exts.appendSlice(alloc, &unknown);

    const msg = try frameServerHello(alloc, &[_]u8{}, 0x1301, exts.items);
    defer alloc.free(msg);

    try testing.expectError(tls13.HandshakeError.DuplicateExtension, ctx.processCrypto(.Initial, msg));
}

test "NEWGAP-06: client rejects non-empty legacy_session_id_echo" {
    const alloc = testing.allocator;
    var ctx = try clientCtx();
    defer ctx.deinit();
    try ctx.startClientHandshake();

    var exts = std.ArrayList(u8).empty;
    defer exts.deinit(alloc);
    try exts.appendSlice(alloc, &supported_versions_ext);
    try exts.appendSlice(alloc, &key_share_ext);

    // Client sent an EMPTY session_id; a 4-byte echo violates RFC 8446 §4.1.3.
    const msg = try frameServerHello(alloc, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, 0x1301, exts.items);
    defer alloc.free(msg);

    try testing.expectError(tls13.HandshakeError.IllegalSessionIdEcho, ctx.processCrypto(.Initial, msg));
}

test "NEWGAP-06/07: well-formed ServerHello with empty session_id still parses past the gate" {
    const alloc = testing.allocator;
    var ctx = try clientCtx();
    defer ctx.deinit();
    try ctx.startClientHandshake();

    var exts = std.ArrayList(u8).empty;
    defer exts.deinit(alloc);
    try exts.appendSlice(alloc, &supported_versions_ext);
    try exts.appendSlice(alloc, &key_share_ext);

    const msg = try frameServerHello(alloc, &[_]u8{}, 0x1301, exts.items);
    defer alloc.free(msg);

    // A valid ServerHello must NOT be rejected with the §4.1.3/§4.2 errors this
    // test guards. It proceeds into key derivation (which may surface other
    // errors), so we only assert the hardening gates do not false-positive.
    ctx.processCrypto(.Initial, msg) catch |err| {
        try testing.expect(err != tls13.HandshakeError.DuplicateExtension);
        try testing.expect(err != tls13.HandshakeError.IllegalSessionIdEcho);
        try testing.expect(err != tls13.HandshakeError.IllegalLegacyVersion);
        try testing.expect(err != tls13.HandshakeError.TooManyExtensions);
    };
}

test "QUAL-391: ServerHello with non-zero legacy_compression_method -> IllegalCompressionMethods" {
    const alloc = testing.allocator;
    var ctx = try clientCtx();
    defer ctx.deinit();
    try ctx.startClientHandshake();

    var exts = std.ArrayList(u8).empty;
    defer exts.deinit(alloc);
    try exts.appendSlice(alloc, &supported_versions_ext);
    try exts.appendSlice(alloc, &key_share_ext);

    // RFC 8446 §4.1.3: ServerHello.legacy_compression_method MUST be 0x00.
    const msg = try frameServerHelloComp(alloc, &[_]u8{}, 0x1301, 0x01, exts.items);
    defer alloc.free(msg);

    try testing.expectError(tls13.HandshakeError.IllegalCompressionMethods, ctx.processCrypto(.Initial, msg));
}
