// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Server-side HelloRetryRequest (HRR) Conformance Tests
//!
//! These tests cover the server emitting HRR when a client offers a non-X25519
//! `key_share` group. They complement `tests/context_hrr_tests.zig` which only
//! exercises client-side HRR handling.
//!
//! ## Why this exists
//!
//! `tls/src/tls13/context.zig:negotiateCipherAndKeys` contains the gate
//! that triggers HRR when `ch_view.key_share.group != .x25519`. RFC 8446
//! §4.1.4 requires the server to send HRR rather than `handshake_failure`
//! whenever a mutually supported group exists but the client did not include
//! a key_share for it. The TLS package only implements X25519 ECDHE today
//! (see `Config.supported_groups` validator at context.zig:593-597), so the
//! server **must** rely on HRR for clients whose first key_share preference
//! is not X25519 (quic-go, mvfst, picoquic-with-secp256r1, post-Q1-2026
//! Chrome with PQ-hybrid).
//!
//! Originally reported via the zig-quic interop suite (NoHandshakeKeys
//! against quic-go and mvfst); see `docs/QUIC_INTEROP_HRR_ISSUE.md`.
//!
//! ## RFC References
//!
//! - RFC 8446 §4.1.4: HelloRetryRequest structure and trigger conditions.
//! - RFC 8446 §4.2.7: supported_groups extension.
//! - RFC 8446 §4.2.8: key_share extension (Client Hello variant).
//! - RFC 8446 §4.2.2: cookie extension (post-HRR).

const std = @import("std");
const testing = std.testing;
const tls13 = @import("tls13");
const tls13_full = @import("tls13_full");

// ============================================================================
// Helpers
// ============================================================================

/// Build a framed (4-byte header + body) ClientHello with a key_share entry
/// for the given group code. Used to construct CH1s that the parser does
/// not currently support natively (e.g. PQ-hybrid `0x6399`).
///
/// The cipher_suites/sigalgs match the test config so cipher negotiation
/// reaches the key_share gate, which is the surface under test.
fn buildFramedClientHelloWithGroup(
    allocator: std.mem.Allocator,
    group_code: u16,
    key_bytes: []const u8,
    cookie: ?[]const u8,
) ![]u8 {
    var body = try std.ArrayList(u8).initCapacity(allocator, 256);
    defer body.deinit(allocator);

    // legacy_version = 0x0303
    try body.appendSlice(allocator, &[_]u8{ 0x03, 0x03 });

    // 32-byte client_random (deterministic for tests)
    try body.appendNTimes(allocator, 0xAA, 32);

    // session_id_len = 0
    try body.append(allocator, 0);

    // cipher_suites = [TLS_AES_128_GCM_SHA256]
    try body.appendSlice(allocator, &[_]u8{ 0x00, 0x02, 0x13, 0x01 });

    // compression_methods = [0]
    try body.appendSlice(allocator, &[_]u8{ 0x01, 0x00 });

    // Build extensions block
    var exts = try std.ArrayList(u8).initCapacity(allocator, 128);
    defer exts.deinit(allocator);

    // supported_versions: [0x0304] (TLS 1.3)
    try exts.appendSlice(allocator, &[_]u8{
        0x00, 0x2b, // type
        0x00, 0x03, // ext_len
        0x02, // versions list len
        0x03, 0x04, // TLS 1.3
    });

    // supported_groups: advertise both x25519 and the offered group so the
    // server has at least one mutually-known group to select after HRR.
    const sg_group_count: u16 = 2;
    const sg_list_len: u16 = sg_group_count * 2;
    const sg_ext_len: u16 = sg_list_len + 2;
    try exts.appendSlice(allocator, &[_]u8{ 0x00, 0x0a }); // type
    try exts.append(allocator, @intCast(sg_ext_len >> 8));
    try exts.append(allocator, @intCast(sg_ext_len & 0xff));
    try exts.append(allocator, @intCast(sg_list_len >> 8));
    try exts.append(allocator, @intCast(sg_list_len & 0xff));
    try exts.append(allocator, @intCast(group_code >> 8));
    try exts.append(allocator, @intCast(group_code & 0xff));
    try exts.appendSlice(allocator, &[_]u8{ 0x00, 0x1d }); // x25519

    // signature_algorithms: [ed25519] for the test ed25519 cert path.
    try exts.appendSlice(allocator, &[_]u8{
        0x00, 0x0d, // type = signature_algorithms
        0x00, 0x04, // ext_len
        0x00, 0x02, // list len
        0x08, 0x07, // ed25519 (0x0807)
    });

    // key_share with one entry of the requested group + raw key_bytes.
    const ks_entry_len: u16 = @intCast(2 + 2 + key_bytes.len);
    const ks_list_len: u16 = ks_entry_len;
    const ks_ext_len: u16 = ks_list_len + 2;
    try exts.appendSlice(allocator, &[_]u8{ 0x00, 0x33 }); // type = key_share
    try exts.append(allocator, @intCast(ks_ext_len >> 8));
    try exts.append(allocator, @intCast(ks_ext_len & 0xff));
    try exts.append(allocator, @intCast(ks_list_len >> 8));
    try exts.append(allocator, @intCast(ks_list_len & 0xff));
    try exts.append(allocator, @intCast(group_code >> 8));
    try exts.append(allocator, @intCast(group_code & 0xff));
    try exts.append(allocator, @intCast(key_bytes.len >> 8));
    try exts.append(allocator, @intCast(key_bytes.len & 0xff));
    try exts.appendSlice(allocator, key_bytes);

    // QUIC transport parameters: empty placeholder so RFC 9001 §8.2 is satisfied.
    try exts.appendSlice(allocator, &[_]u8{
        0x00, 0x39, // type = quic_transport_parameters
        0x00, 0x00, // ext_len = 0
    });

    // Optional cookie extension (post-HRR CH2 echo). RFC 8446 §4.2.2:
    // ext_data carries a `Cookie` struct (`opaque cookie<1..2^16-1>`),
    // i.e. 2-byte ext_data_len, then a 2-byte inner cookie length,
    // then the cookie bytes.
    if (cookie) |c| {
        const ext_data_len: u16 = @intCast(c.len + 2);
        const inner_len: u16 = @intCast(c.len);
        try exts.appendSlice(allocator, &[_]u8{
            0x00,                        0x2c,
            @intCast(ext_data_len >> 8), @intCast(ext_data_len & 0xff),
            @intCast(inner_len >> 8),    @intCast(inner_len & 0xff),
        });
        try exts.appendSlice(allocator, c);
    }

    // Append extensions block to body
    const exts_len: u16 = @intCast(exts.items.len);
    try body.append(allocator, @intCast(exts_len >> 8));
    try body.append(allocator, @intCast(exts_len & 0xff));
    try body.appendSlice(allocator, exts.items);

    return tls13.encodeHandshake(allocator, .client_hello, body.items);
}

/// Construct a server context with X25519-only `supported_groups` and the
/// minimum config needed for `negotiateCipherAndKeys` to reach the
/// key_share gate. No certificate is configured: tests bound their
/// expectations to the parse / HRR-emit boundary.
fn makeServerCtx() !tls13.Context {
    return tls13.Context.init(.{
        .allocator = testing.allocator,
        .role = .Server,
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{},
    }, .{});
}

/// Locate the key_share extension's selected_group inside an HRR (which is a
/// ServerHello at the wire level) framed with the 4-byte handshake header.
/// Returns the absolute offset of the 2-byte group within `msg`, or null.
fn findHrrSelectedGroupOffset(msg: []const u8) ?usize {
    if (msg.len < 4) return null;
    // Skip handshake header (4 bytes) + legacy_version (2) + random (32)
    var pos: usize = 4 + 2 + 32;
    if (pos + 1 > msg.len) return null;
    const sid_len: usize = msg[pos];
    pos += 1 + sid_len;
    if (pos + 2 + 1 + 2 > msg.len) return null;
    pos += 2; // cipher_suite
    pos += 1; // compression_method
    const exts_len: usize = @as(usize, msg[pos]) << 8 | msg[pos + 1];
    pos += 2;
    const exts_end = pos + exts_len;
    if (exts_end > msg.len) return null;
    while (pos + 4 <= exts_end) {
        const etype: u16 = @as(u16, msg[pos]) << 8 | msg[pos + 1];
        const elen: usize = @as(usize, msg[pos + 2]) << 8 | msg[pos + 3];
        pos += 4;
        if (etype == 0x0033) {
            if (elen < 2) return null;
            return pos; // group is 2 bytes at offset pos in HRR's key_share
        }
        pos += elen;
    }
    return null;
}

/// Extract the cookie bytes from an HRR message. Caller does NOT own.
///
/// RFC 8446 §4.2.2: ext_data wraps a `Cookie` struct with a 2-byte inner
/// length prefix followed by the cookie bytes. We surface the inner
/// payload (i.e. the bytes the client echoes verbatim in CH2).
fn extractHrrCookie(msg: []const u8) ?[]const u8 {
    if (msg.len < 4) return null;
    var pos: usize = 4 + 2 + 32;
    if (pos + 1 > msg.len) return null;
    const sid_len: usize = msg[pos];
    pos += 1 + sid_len;
    if (pos + 5 > msg.len) return null;
    pos += 2; // cipher_suite
    pos += 1; // compression
    const exts_len: usize = @as(usize, msg[pos]) << 8 | msg[pos + 1];
    pos += 2;
    const exts_end = pos + exts_len;
    if (exts_end > msg.len) return null;
    while (pos + 4 <= exts_end) {
        const etype: u16 = @as(u16, msg[pos]) << 8 | msg[pos + 1];
        const elen: usize = @as(usize, msg[pos + 2]) << 8 | msg[pos + 3];
        pos += 4;
        if (pos + elen > exts_end) return null;
        if (etype == 0x002c) {
            if (elen < 2) return null;
            const ck_len: usize = @as(usize, msg[pos]) << 8 | msg[pos + 1];
            if (2 + ck_len > elen) return null;
            return msg[pos + 2 .. pos + 2 + ck_len];
        }
        pos += elen;
    }
    return null;
}

// ============================================================================
// Test 1: secp256r1 CH1 triggers HRR (mvfst-style failure)
// ============================================================================

test "HRR-server: CH1 with secp256r1 key_share triggers HRR (no error)" {
    // RFC 8446 §4.1.4: When the client's offered key_share is not in the
    // server's supported_groups but supported_groups overlaps, server MUST
    // emit HRR (not handshake_failure). mvfst defaults to NIST P-256 in
    // many builds, so this is the production-critical path.
    var server_ctx = try makeServerCtx();
    defer server_ctx.deinit();

    // 65-byte uncompressed P-256 point placeholder (orchestrator never
    // touches the bytes; only the group code drives the HRR decision).
    var p256_key: [65]u8 = undefined;
    p256_key[0] = 0x04;
    @memset(p256_key[1..], 0xBB);

    const ch1 = try buildFramedClientHelloWithGroup(
        testing.allocator,
        0x0017, // secp256r1
        &p256_key,
        null,
    );
    defer testing.allocator.free(ch1);

    // CH1 must NOT fail at parse — the orchestrator owns the HRR decision.
    try server_ctx.processCrypto(.Initial, ch1);

    // hrr_sent must be set after HRR queue.
    try testing.expect(server_ctx.hrr_sent);

    // An HRR message must be queued at the Initial encryption level.
    const hrr_msg = try server_ctx.pollCrypto(testing.allocator, .Initial);
    defer testing.allocator.free(hrr_msg);
    try testing.expect(hrr_msg.len > 0);

    // The HRR's key_share must request x25519 (0x001d).
    const grp_off = findHrrSelectedGroupOffset(hrr_msg) orelse
        return error.TestExpectedKeyShareInHrr;
    try testing.expectEqual(@as(u8, 0x00), hrr_msg[grp_off]);
    try testing.expectEqual(@as(u8, 0x1d), hrr_msg[grp_off + 1]);
}

// ============================================================================
// Test 2: PQ-hybrid CH1 triggers HRR (quic-go-style failure)
// ============================================================================

test "HRR-server: CH1 with x25519_kyber768_draft00 key_share triggers HRR" {
    // quic-go (Go ≥ 1.23) advertises X25519+Kyber768 hybrid (0x6399) as its
    // first key_share preference. The codepoint is unknown to NamedGroup —
    // the orchestrator must still emit HRR rather than fail-closed at parse.
    var server_ctx = try makeServerCtx();
    defer server_ctx.deinit();

    // Hybrid public key length is impl-defined; use a 1216-byte placeholder
    // (32 bytes X25519 + 1184 bytes Kyber768 KEM public, the quic-go shape).
    var hybrid_key: [1216]u8 = undefined;
    @memset(&hybrid_key, 0xCC);

    const ch1 = try buildFramedClientHelloWithGroup(
        testing.allocator,
        0x6399, // x25519_kyber768_draft00 (Cloudflare/Google draft codepoint)
        &hybrid_key,
        null,
    );
    defer testing.allocator.free(ch1);

    try server_ctx.processCrypto(.Initial, ch1);
    try testing.expect(server_ctx.hrr_sent);

    const hrr_msg = try server_ctx.pollCrypto(testing.allocator, .Initial);
    defer testing.allocator.free(hrr_msg);
    try testing.expect(hrr_msg.len > 0);

    const grp_off = findHrrSelectedGroupOffset(hrr_msg) orelse
        return error.TestExpectedKeyShareInHrr;
    try testing.expectEqual(@as(u8, 0x00), hrr_msg[grp_off]);
    try testing.expectEqual(@as(u8, 0x1d), hrr_msg[grp_off + 1]);
}

// ============================================================================
// Test 2b (QUAL-369): preserve raw key_share codepoint for unknown groups
// ============================================================================

test "HRR-server: parser preserves raw_group_code for unknown PQ-hybrid codepoint" {
    // QUAL-369: when the offered key_share group code is outside our
    // NamedGroup enum (e.g. 0x6399), the parser stores .secp256r1 as a
    // sentinel so the orchestrator can issue HRR, but the original u16
    // codepoint MUST be preserved on KeyShareEntry.raw_group_code so
    // future logic can switch on the actual offered group.
    var server_ctx = try makeServerCtx();
    defer server_ctx.deinit();

    var hybrid_key: [1216]u8 = undefined;
    @memset(&hybrid_key, 0xC9);

    const ch1 = try buildFramedClientHelloWithGroup(
        testing.allocator,
        0x6399,
        &hybrid_key,
        null,
    );
    defer testing.allocator.free(ch1);

    try server_ctx.processCrypto(.Initial, ch1);

    // The orchestrator's view of the parsed CH1 must still expose the
    // original codepoint even though `group` is the X25519-not-X25519
    // sentinel. State has already been reset post-HRR, so we read the
    // view BEFORE the reset by inspecting the surviving HRR; this test
    // exercises the parser-to-view plumbing directly.
    const ch1_body = ch1[4..]; // strip 4-byte handshake header
    const parsed = try tls13_full.parseClientHello(testing.allocator, ch1_body);
    defer {
        testing.allocator.free(parsed.cipher_suites);
        if (parsed.supported_groups) |g| testing.allocator.free(g);
        if (parsed.signature_algorithms) |a| testing.allocator.free(a);
        if (parsed.alpn_list) |l| testing.allocator.free(l);
        if (parsed.pre_shared_key) |psk| {
            testing.allocator.free(psk.identities);
            testing.allocator.free(psk.binders);
        }
    }
    const ks = parsed.key_share orelse return error.TestExpectedKeyShare;
    try testing.expectEqual(@as(u16, 0x6399), ks.raw_group_code);
    // Sentinel non-X25519 group so the orchestrator triggers HRR.
    try testing.expect(ks.group != .x25519);
}

// ============================================================================
// Test 2c (SEC-087): HRR cookie ext_data carries the RFC 8446 §4.2.2 inner length prefix
// ============================================================================

test "HRR-server: cookie ext on the wire has the RFC 8446 §4.2.2 inner length prefix" {
    // SEC-087: RFC 8446 §4.2.2 specifies the cookie extension's ext_data
    // as a `Cookie` struct (`opaque cookie<1..2^16-1>`), i.e. a 2-byte
    // length prefix followed by the cookie bytes. Prior to this fix the
    // HRR builder elided the inner prefix, breaking interop with clients
    // that parsed the ext_data per spec. This regression test asserts
    // the wire format directly.
    var server_ctx = try makeServerCtx();
    defer server_ctx.deinit();

    var p256_key: [65]u8 = undefined;
    p256_key[0] = 0x04;
    @memset(p256_key[1..], 0xA1);

    const ch1 = try buildFramedClientHelloWithGroup(
        testing.allocator,
        0x0017,
        &p256_key,
        null,
    );
    defer testing.allocator.free(ch1);
    try server_ctx.processCrypto(.Initial, ch1);

    const hrr_msg = try server_ctx.pollCrypto(testing.allocator, .Initial);
    defer testing.allocator.free(hrr_msg);

    // Walk extensions to find the cookie. ext_data must be:
    //   inner_len (2) | <inner_len cookie bytes>
    // and inner_len + 2 MUST equal ext_data_len.
    var pos: usize = 4 + 2 + 32; // header + version + random
    if (pos + 1 > hrr_msg.len) return error.TestUnexpectedHrrShape;
    const sid_len: usize = hrr_msg[pos];
    pos += 1 + sid_len;
    pos += 2 + 1; // cipher_suite + compression
    if (pos + 2 > hrr_msg.len) return error.TestUnexpectedHrrShape;
    const exts_len: usize = @as(usize, hrr_msg[pos]) << 8 | hrr_msg[pos + 1];
    pos += 2;
    const exts_end = pos + exts_len;

    var found = false;
    while (pos + 4 <= exts_end) {
        const etype: u16 = @as(u16, hrr_msg[pos]) << 8 | hrr_msg[pos + 1];
        const elen: usize = @as(usize, hrr_msg[pos + 2]) << 8 | hrr_msg[pos + 3];
        pos += 4;
        if (etype == 0x002c) {
            try testing.expect(elen >= 2);
            const inner: usize = @as(usize, hrr_msg[pos]) << 8 | hrr_msg[pos + 1];
            try testing.expectEqual(elen - 2, inner);
            try testing.expect(inner > 0); // RFC 8446: cookie<1..2^16-1>
            found = true;
            break;
        }
        pos += elen;
    }
    try testing.expect(found);
}

// ============================================================================
// Test 3: HRR transport bookkeeping — Initial outbound holds HRR, Handshake empty
// ============================================================================

test "HRR-server: Handshake-level outbound is empty after HRR (RFC 9001 §4)" {
    // QUIC integration: HRR rides at Initial encryption level. The Handshake
    // level must remain dormant until CH2 + ServerHello complete the key
    // installation. This is what the zig-quic interop suite asserted by
    // observing `NoHandshakeKeys` only when sendHandshakePackets fired —
    // it should be a no-op until the flight is complete.
    var server_ctx = try makeServerCtx();
    defer server_ctx.deinit();

    var p256_key: [65]u8 = undefined;
    p256_key[0] = 0x04;
    @memset(p256_key[1..], 0xDD);

    const ch1 = try buildFramedClientHelloWithGroup(
        testing.allocator,
        0x0017,
        &p256_key,
        null,
    );
    defer testing.allocator.free(ch1);

    try server_ctx.processCrypto(.Initial, ch1);

    // Initial-level outbound holds the HRR.
    try testing.expect(server_ctx.streams.buffers[
        @intFromEnum(tls13.EncryptionLevel.Initial)
    ].outbound.items.len > 0);

    // Handshake-level outbound MUST be empty (no Handshake keys yet).
    try testing.expectEqual(@as(usize, 0), server_ctx.streams.buffers[
        @intFromEnum(tls13.EncryptionLevel.Handshake)
    ].outbound.items.len);

    // Handshake-level send secret slot MUST NOT be valid yet.
    const hs_send = server_ctx.secrets.slot(.Handshake, .send);
    try testing.expect(!hs_send.valid);
}

// ============================================================================
// Test 4: CH2 acceptance after HRR — orchestrator reaches X25519 path
// ============================================================================

test "HRR-server: CH2 with x25519 after HRR is accepted (parser does not reject)" {
    // After HRR emission, the server resets stored CH state and accepts a
    // second ClientHello (RFC 8446 §4.1.4). CH2 must include the cookie
    // extension echoing HRR's cookie. The orchestrator should reach the
    // X25519 gate and proceed past it on second pass.
    //
    // This test bounds at "no error during CH2 parse + second-pass
    // negotiation" — the full server flight (Cert + CV + Finished) is
    // exercised by integration tests under tests/conformance/. Here we
    // verify the parser+validator+orchestrator reach a known-good state.
    var server_ctx = try makeServerCtx();
    defer server_ctx.deinit();

    // ----- CH1 with secp256r1 key_share -----
    var p256_key: [65]u8 = undefined;
    p256_key[0] = 0x04;
    @memset(p256_key[1..], 0xEE);
    const ch1 = try buildFramedClientHelloWithGroup(
        testing.allocator,
        0x0017,
        &p256_key,
        null,
    );
    defer testing.allocator.free(ch1);
    try server_ctx.processCrypto(.Initial, ch1);

    // ----- Drain HRR + capture cookie for the echo -----
    const hrr_msg = try server_ctx.pollCrypto(testing.allocator, .Initial);
    defer testing.allocator.free(hrr_msg);
    const cookie = extractHrrCookie(hrr_msg) orelse
        return error.TestExpectedCookieInHrr;
    const cookie_copy = try testing.allocator.dupe(u8, cookie);
    defer testing.allocator.free(cookie_copy);

    // ----- CH2 with valid X25519 key (RFC 8446 §4.2.8 requires 32 bytes) -----
    var x25519_key: [32]u8 = undefined;
    @memset(&x25519_key, 0x77);
    const ch2 = try buildFramedClientHelloWithGroup(
        testing.allocator,
        0x001d, // x25519
        &x25519_key,
        cookie_copy,
    );
    defer testing.allocator.free(ch2);

    // CH2 must reach negotiateCipherAndKeys's X25519 path. The full flight
    // emits ServerHello + EE + Cert + CV + Finished — without server certs
    // configured, the cert step returns an error AFTER the X25519 path is
    // reached. We accept either:
    //   - clean success (no certs requested in PSK-only path; not used here),
    //   - the cert-related error from buildCertificateMsg (which proves the
    //     parser+orchestrator reached cert emission, i.e. past the X25519 gate).
    server_ctx.processCrypto(.Initial, ch2) catch |err| switch (err) {
        // `MissingCertificate` is raised by `buildCertificateMsg` AFTER the
        // X25519 path completes ServerHello + Handshake-secret installation
        // — exactly the proof we need that the bug is fixed (the previous
        // failure mode was MissingKeyShare at the parser, before
        // negotiateCipherAndKeys was even reachable). The other accepted
        // errors are similarly downstream of the X25519 gate.
        error.MissingCertificate,
        error.NoSignatureScheme,
        error.UnexpectedMessage,
        error.InternalError,
        => {},
        else => return err,
    };

    // RFC 9001 §5.1: Handshake-level secrets MUST be installed before the
    // server emits any Handshake-level CRYPTO frames. The orchestrator sets
    // `phase = .keys_installed` immediately after `installHandshakeTrafficPair`
    // (context.zig:1894). At least one of the Handshake secret slots must
    // also be valid by this point.
    const hs_send = server_ctx.secrets.slot(.Handshake, .send);
    const hs_recv = server_ctx.secrets.slot(.Handshake, .recv);
    try testing.expect(hs_send.valid or hs_recv.valid or
        server_ctx.phase == .keys_installed or
        server_ctx.phase == .application_ready);
}

// ============================================================================
// Test 5 (SEC-086): forged cookie on CH2 is rejected with InvalidCookie
// ============================================================================

test "HRR-server: CH2 with a forged cookie is rejected (SEC-086)" {
    // RFC 8446 §4.2.2: the server MUST verify that the cookie echoed in
    // CH2 is the one it issued in HRR (HMAC over server_secret,
    // client_random, CH1_transcript_hash). A flipped HMAC bit must
    // abort with `illegal_parameter`.
    var server_ctx = try makeServerCtx();
    defer server_ctx.deinit();

    var p256_key: [65]u8 = undefined;
    p256_key[0] = 0x04;
    @memset(p256_key[1..], 0x55);
    const ch1 = try buildFramedClientHelloWithGroup(
        testing.allocator,
        0x0017,
        &p256_key,
        null,
    );
    defer testing.allocator.free(ch1);
    try server_ctx.processCrypto(.Initial, ch1);

    const hrr_msg = try server_ctx.pollCrypto(testing.allocator, .Initial);
    defer testing.allocator.free(hrr_msg);
    const cookie = extractHrrCookie(hrr_msg) orelse return error.TestExpectedCookieInHrr;

    // Flip the high bit of the first HMAC byte to force a verification miss.
    const forged = try testing.allocator.dupe(u8, cookie);
    defer testing.allocator.free(forged);
    forged[0] ^= 0x80;

    var x25519_key: [32]u8 = undefined;
    @memset(&x25519_key, 0x77);
    const ch2 = try buildFramedClientHelloWithGroup(
        testing.allocator,
        0x001d,
        &x25519_key,
        forged,
    );
    defer testing.allocator.free(ch2);

    try testing.expectError(
        tls13.HandshakeError.InvalidCookie,
        server_ctx.processCrypto(.Initial, ch2),
    );
}

// ============================================================================
// Test 6 (SEC-086): missing cookie on CH2 is rejected with InvalidCookie
// ============================================================================

test "HRR-server: CH2 without a cookie ext is rejected (SEC-086)" {
    // RFC 8446 §4.2.2: the cookie is OPTIONAL in HRR but if the server
    // sent one (it always does in this implementation), the client MUST
    // echo it. Absent cookie on CH2 aborts with InvalidCookie.
    var server_ctx = try makeServerCtx();
    defer server_ctx.deinit();

    var p256_key: [65]u8 = undefined;
    p256_key[0] = 0x04;
    @memset(p256_key[1..], 0x66);
    const ch1 = try buildFramedClientHelloWithGroup(
        testing.allocator,
        0x0017,
        &p256_key,
        null,
    );
    defer testing.allocator.free(ch1);
    try server_ctx.processCrypto(.Initial, ch1);

    const hrr_msg = try server_ctx.pollCrypto(testing.allocator, .Initial);
    defer testing.allocator.free(hrr_msg);

    var x25519_key: [32]u8 = undefined;
    @memset(&x25519_key, 0x77);
    const ch2 = try buildFramedClientHelloWithGroup(
        testing.allocator,
        0x001d,
        &x25519_key,
        null, // no cookie echo — RFC violation
    );
    defer testing.allocator.free(ch2);

    try testing.expectError(
        tls13.HandshakeError.InvalidCookie,
        server_ctx.processCrypto(.Initial, ch2),
    );
}
