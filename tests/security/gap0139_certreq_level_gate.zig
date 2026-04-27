// SPDX-License-Identifier: Apache-2.0
//! GAP-0139 regression: CertificateRequest must be gated by encryption
//! level + handshake phase per RFC 8446 §4.3.2 / §4.6.2.
//!
//! Cases:
//!   1. Initial level -> reject with HandshakeError.UnexpectedMessage
//!      (RFC 8446 §4.3.2 forbids CR at Initial; CR is sent by the server
//!      AFTER ServerHello, so the keys must be Handshake by then).
//!   2. Handshake level during initial handshake -> accept.
//!   3. Application level WITHOUT `post_handshake_auth` configured ->
//!      reject (RFC 8446 §4.6.2 requires the extension to have been
//!      negotiated).
//!   4. Application level WITH `post_handshake_auth = true` -> accept.

const std = @import("std");
const tls13 = @import("tls13");
const tls13_full = @import("tls13_full");
const testing = std.testing;

fn buildCertReqMessage(alloc: std.mem.Allocator) ![]u8 {
    const schemes = [_]tls13_full.SignatureScheme{.ed25519};
    const body = try tls13_full.buildCertificateRequest(alloc, &schemes, null);
    defer alloc.free(body);
    return tls13.encodeHandshake(alloc, .certificate_request, body);
}

fn makeClientCtx(post_handshake_auth: bool) !tls13.Context {
    return tls13.Context.init(.{
        .allocator = testing.allocator,
        .role = .Client,
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{},
        .post_handshake_auth = post_handshake_auth,
    }, .{});
}

test "GAP-0139: CR at Initial level is rejected" {
    var ctx = try makeClientCtx(false);
    defer ctx.deinit();

    const msg = try buildCertReqMessage(testing.allocator);
    defer testing.allocator.free(msg);

    const result = ctx.processCrypto(.Initial, msg);
    try testing.expectError(tls13.HandshakeError.UnexpectedMessage, result);
}

test "GAP-0139: CR at Application level without post_handshake_auth is rejected" {
    var ctx = try makeClientCtx(false);
    defer ctx.deinit();

    const msg = try buildCertReqMessage(testing.allocator);
    defer testing.allocator.free(msg);

    const result = ctx.processCrypto(.Application, msg);
    try testing.expectError(tls13.HandshakeError.UnexpectedMessage, result);
}

test "GAP-0139: CR at Application level with post_handshake_auth=true is accepted (post-handshake)" {
    // Without a full handshake replay, the simplest deterministic check is
    // that the level gate alone does NOT reject when post_handshake_auth is
    // enabled. The handler still parses the body and sets
    // `client_cert_requested = true`. Note that real post-handshake auth
    // also requires the handshake to have completed; the gate distinguishes
    // "this combination is allowed" from "this combination is forbidden".
    var ctx = try makeClientCtx(true);
    defer ctx.deinit();

    // Pretend handshake has completed so the post-handshake path is valid.
    ctx.phase = .application_ready;

    const msg = try buildCertReqMessage(testing.allocator);
    defer testing.allocator.free(msg);

    try ctx.processCrypto(.Application, msg);
    try testing.expect(ctx.client_cert_requested);
}

test "GAP-0139: CR at Handshake level during initial handshake is accepted" {
    var ctx = try makeClientCtx(false);
    defer ctx.deinit();

    // Simulate that the handshake has reached the keys_installed phase
    // (server has sent ServerHello + EE; CR follows EE per §4.3.2).
    ctx.phase = .keys_installed;

    const msg = try buildCertReqMessage(testing.allocator);
    defer testing.allocator.free(msg);

    try ctx.processCrypto(.Handshake, msg);
    try testing.expect(ctx.client_cert_requested);
}
