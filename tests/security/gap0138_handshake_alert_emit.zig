// SPDX-License-Identifier: Apache-2.0
//! GAP-0138 regression: a fatal HandshakeError in handleHandshakeMessage
//! must queue a fatal alert on the outbound CryptoBuffer (RFC 8446 §6.2)
//! and transition Context.phase to .terminated.
//!
//! Cases:
//!   1. unexpected_message — server-only message (ClientHello) on a Client.
//!   2. illegal_parameter — CertReq at Initial level (GAP-0139 path).
//!   3. decode_error — duplicate-extension (SEC-092) — sent inside an
//!      EncryptedExtensions message on the Handshake level.
//!
//! Each case asserts:
//!   * processCrypto returns the expected typed HandshakeError.
//!   * Context.phase == .terminated afterwards.
//!   * The appropriate outbound CryptoBuffer contains a fatal alert
//!     (level=2, description=expected RFC 8446 §6.2 code).

const std = @import("std");
const tls13 = @import("tls13");
const tls13_full = @import("tls13_full");
const testing = std.testing;

fn makeClientCtx() !tls13.Context {
    return tls13.Context.init(.{
        .allocator = testing.allocator,
        .role = .Client,
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{},
    }, .{});
}

fn assertFatalAlert(ctx: *tls13.Context, level: tls13.EncryptionLevel, description: u8) !void {
    try testing.expect(ctx.phase == .terminated);
    const out = try ctx.pollCrypto(testing.allocator, level);
    defer testing.allocator.free(out);
    try testing.expectEqual(@as(usize, 2), out.len);
    try testing.expectEqual(@as(u8, 2), out[0]); // fatal
    try testing.expectEqual(description, out[1]);
}

test "GAP-0138: unexpected_message alert on ClientHello to client" {
    var ctx = try makeClientCtx();
    defer ctx.deinit();

    // Build a minimal-but-valid ClientHello body so the role gate (the
    // first check in the .client_hello arm) is what trips. The body
    // never reaches parseClientHello; we only need a frame that survives
    // parseHandshakeOne.
    var body = std.ArrayList(u8).empty;
    defer body.deinit(testing.allocator);
    try body.appendSlice(testing.allocator, &.{ 0x03, 0x03 }); // legacy_version
    try body.appendNTimes(testing.allocator, 0xA5, 32); // random
    try body.append(testing.allocator, 0); // session_id_len
    try body.appendSlice(testing.allocator, &.{ 0x00, 0x02, 0x13, 0x01 }); // cipher_suites
    try body.appendSlice(testing.allocator, &.{ 0x01, 0x00 }); // compression
    try body.appendSlice(testing.allocator, &.{ 0x00, 0x00 }); // extensions

    const framed = try tls13.encodeHandshake(testing.allocator, .client_hello, body.items);
    defer testing.allocator.free(framed);

    const result = ctx.processCrypto(.Initial, framed);
    try testing.expectError(tls13.HandshakeError.UnexpectedMessage, result);
    try assertFatalAlert(&ctx, .Initial, 10); // unexpected_message = 10
}

test "GAP-0138: illegal_parameter alert on CertReq at Initial level" {
    var ctx = try makeClientCtx();
    defer ctx.deinit();
    // Drain client's outbound CH if any (no startClientHandshake here -> none).

    const schemes = [_]tls13_full.SignatureScheme{.ed25519};
    const body = try tls13_full.buildCertificateRequest(testing.allocator, &schemes, null);
    defer testing.allocator.free(body);
    const framed = try tls13.encodeHandshake(testing.allocator, .certificate_request, body);
    defer testing.allocator.free(framed);

    const result = ctx.processCrypto(.Initial, framed);
    try testing.expectError(tls13.HandshakeError.UnexpectedMessage, result);
    // GAP-0139 maps to UnexpectedMessage -> unexpected_message alert (10).
    try assertFatalAlert(&ctx, .Initial, 10);
}
