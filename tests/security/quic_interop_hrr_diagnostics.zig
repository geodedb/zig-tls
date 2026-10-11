// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! QUIC-INTEROP-HRR: upstream diagnostic landing tests.
//!
//! Background: the cookie-verify diagnostics added in commit `307b100`
//! cover four post-HRR failure branches inside `negotiateCipherAndKeys`.
//! The 2026-04-27 interop run against quic-go and mvfst showed that
//! NEITHER `[TLS-HRR]` line fired for either failing client — meaning
//! the cookie-verify path is bypassed entirely. The fault is upstream:
//!
//! - mvfst: CH2 never reaches `negotiateCipherAndKeys` after HRR.
//! - quic-go: HRR may not even fire on CH1; a different early-return
//!   path inside `negotiateCipherAndKeys` (or `ClientHelloInfo.parse`)
//!   silently consumes the failure and the QUIC layer surfaces a
//!   generic `NoHandshakeKeys`.
//!
//! This test file covers the new `[TLS-HRR]` diagnostics that flag
//! every upstream early-return on the server's CH1/CH2 path. Each test
//! installs a `quic_logger.setTestSink` capture, drives a synthetic
//! ClientHello through the server context, and asserts that the
//! corresponding `[TLS-HRR]` line landed. Tests for paths that *also*
//! raise a HandshakeError additionally assert the error variant so the
//! diagnostic does not change behaviour.
//!
//! See `docs/QUIC_INTEROP_HRR_ISSUE.md` for the full investigation
//! history.

const std = @import("std");
const testing = std.testing;
const tls13 = @import("tls13");
const tls13_full = @import("tls13_full");
const active_group: tls13_full.NamedGroup = if (tls13.fips_enabled) .x25519_mlkem768 else .x25519;
const active_code: u16 = @intFromEnum(active_group);
const quic_logger = @import("quic_logger");

// ============================================================================
// Capture sink (single-threaded test invariant — one active sink at a time)
// ============================================================================

/// Static capture buffer. The `quic_logger` test sink is a function
/// pointer that cannot capture closure state, so we rely on a module-
/// local `var` plus the convention that `beginCapture`/`endCapture`
/// bracket every test. Zig's default test runner is single-threaded, so
/// concurrent access is not a concern.
var captured_buf: [16 * 1024]u8 = undefined;
var captured_len: usize = 0;

fn captureSink(level: quic_logger.Level, message: []const u8) void {
    _ = level;
    if (captured_len + message.len + 1 > captured_buf.len) return;
    @memcpy(captured_buf[captured_len .. captured_len + message.len], message);
    captured_buf[captured_len + message.len] = '\n';
    captured_len += message.len + 1;
}

fn beginCapture() void {
    captured_len = 0;
    quic_logger.setTestSink(captureSink);
}

fn endCapture() void {
    quic_logger.setTestSink(null);
}

fn captured() []const u8 {
    return captured_buf[0..captured_len];
}

fn captureContains(needle: []const u8) bool {
    return std.mem.indexOf(u8, captured(), needle) != null;
}

// ============================================================================
// ClientHello synthesis helpers (lifted shape from tests/context_hrr_server_tests.zig)
// ============================================================================

const BuildOpts = struct {
    /// key_share group code (e.g. 0x001d X25519, 0x0017 secp256r1, 0x6399 hybrid).
    /// When `null`, the key_share extension is omitted entirely (drives
    /// `ClientHelloInfo.parse` MissingKeyShare).
    group_code: ?u16,
    /// Bytes for the key_share entry payload. Length determines the
    /// `key_exchange<1..2^16-1>` bytes on the wire — short for X25519
    /// truncation tests, 65 for P-256, etc.
    key_bytes: []const u8,
    /// Cipher suites list. Empty list drives `NoCipherSuite`.
    cipher_suites: []const u16 = &[_]u16{0x1301}, // TLS_AES_128_GCM_SHA256
    /// signature_algorithms entries. Empty list omits the extension and
    /// drives the orchestrator's `NoSignatureScheme` peer-list-missing
    /// path.
    sig_algs: []const u16 = &[_]u16{0x0807}, // ed25519
    /// Optional cookie ext echo (for CH2 simulation).
    cookie: ?[]const u8 = null,
    /// 32-byte client_random override.
    random_byte: u8 = 0xAA,
};

fn buildFramedClientHello(allocator: std.mem.Allocator, opts: BuildOpts) ![]u8 {
    var body = try std.ArrayList(u8).initCapacity(allocator, 256);
    defer body.deinit(allocator);

    // legacy_version
    try body.appendSlice(allocator, &[_]u8{ 0x03, 0x03 });
    // client_random
    try body.appendNTimes(allocator, opts.random_byte, 32);
    // session_id_len = 0
    try body.append(allocator, 0);

    // cipher_suites
    const cs_list_len: u16 = @intCast(opts.cipher_suites.len * 2);
    try body.append(allocator, @intCast(cs_list_len >> 8));
    try body.append(allocator, @intCast(cs_list_len & 0xff));
    for (opts.cipher_suites) |cs| {
        try body.append(allocator, @intCast(cs >> 8));
        try body.append(allocator, @intCast(cs & 0xff));
    }

    // compression_methods
    try body.appendSlice(allocator, &[_]u8{ 0x01, 0x00 });

    // ----- extensions -----
    var exts = try std.ArrayList(u8).initCapacity(allocator, 128);
    defer exts.deinit(allocator);

    // supported_versions: TLS 1.3
    try exts.appendSlice(allocator, &[_]u8{
        0x00, 0x2b, // type
        0x00, 0x03, // ext_len
        0x02, // versions list len
        0x03, 0x04, // TLS 1.3
    });

    // supported_groups: x25519 always advertised so post-HRR CH2 has a path.
    // When the test offers a non-X25519 group_code, also advertise it so
    // RFC 8446 §4.2.7 invariants are preserved.
    var sg_groups = try std.ArrayList(u16).initCapacity(allocator, 2);
    defer sg_groups.deinit(allocator);
    if (opts.group_code) |g| {
        if (g != 0x001d) try sg_groups.append(allocator, g);
    }
    try sg_groups.append(allocator, active_code);
    const sg_list_len: u16 = @intCast(sg_groups.items.len * 2);
    const sg_ext_len: u16 = sg_list_len + 2;
    try exts.appendSlice(allocator, &[_]u8{ 0x00, 0x0a });
    try exts.append(allocator, @intCast(sg_ext_len >> 8));
    try exts.append(allocator, @intCast(sg_ext_len & 0xff));
    try exts.append(allocator, @intCast(sg_list_len >> 8));
    try exts.append(allocator, @intCast(sg_list_len & 0xff));
    for (sg_groups.items) |g| {
        try exts.append(allocator, @intCast(g >> 8));
        try exts.append(allocator, @intCast(g & 0xff));
    }

    // signature_algorithms (omit extension when sig_algs is empty)
    if (opts.sig_algs.len != 0) {
        const sa_list_len: u16 = @intCast(opts.sig_algs.len * 2);
        const sa_ext_len: u16 = sa_list_len + 2;
        try exts.appendSlice(allocator, &[_]u8{ 0x00, 0x0d });
        try exts.append(allocator, @intCast(sa_ext_len >> 8));
        try exts.append(allocator, @intCast(sa_ext_len & 0xff));
        try exts.append(allocator, @intCast(sa_list_len >> 8));
        try exts.append(allocator, @intCast(sa_list_len & 0xff));
        for (opts.sig_algs) |sa| {
            try exts.append(allocator, @intCast(sa >> 8));
            try exts.append(allocator, @intCast(sa & 0xff));
        }
    }

    // key_share (skip when group_code is null — drives MissingKeyShare)
    if (opts.group_code) |g| {
        const ks_entry_len: u16 = @intCast(2 + 2 + opts.key_bytes.len);
        const ks_list_len: u16 = ks_entry_len;
        const ks_ext_len: u16 = ks_list_len + 2;
        try exts.appendSlice(allocator, &[_]u8{ 0x00, 0x33 });
        try exts.append(allocator, @intCast(ks_ext_len >> 8));
        try exts.append(allocator, @intCast(ks_ext_len & 0xff));
        try exts.append(allocator, @intCast(ks_list_len >> 8));
        try exts.append(allocator, @intCast(ks_list_len & 0xff));
        try exts.append(allocator, @intCast(g >> 8));
        try exts.append(allocator, @intCast(g & 0xff));
        try exts.append(allocator, @intCast(opts.key_bytes.len >> 8));
        try exts.append(allocator, @intCast(opts.key_bytes.len & 0xff));
        try exts.appendSlice(allocator, opts.key_bytes);
    }

    // QUIC transport parameters (empty placeholder — RFC 9001 §8.2)
    try exts.appendSlice(allocator, &[_]u8{
        0x00, 0x39, // type
        0x00, 0x00, // ext_len
    });

    // Optional cookie ext (post-HRR CH2 simulation)
    if (opts.cookie) |c| {
        const ext_data_len: u16 = @intCast(c.len + 2);
        const inner_len: u16 = @intCast(c.len);
        try exts.appendSlice(allocator, &[_]u8{ 0x00, 0x2c });
        try exts.append(allocator, @intCast(ext_data_len >> 8));
        try exts.append(allocator, @intCast(ext_data_len & 0xff));
        try exts.append(allocator, @intCast(inner_len >> 8));
        try exts.append(allocator, @intCast(inner_len & 0xff));
        try exts.appendSlice(allocator, c);
    }

    const exts_len: u16 = @intCast(exts.items.len);
    try body.append(allocator, @intCast(exts_len >> 8));
    try body.append(allocator, @intCast(exts_len & 0xff));
    try body.appendSlice(allocator, exts.items);

    return tls13.encodeHandshake(allocator, .client_hello, body.items);
}

fn makeServerCtx() !tls13.Context {
    return tls13.Context.init(.{
        .allocator = testing.allocator,
        .role = .Server,
        .supported_groups = &.{active_group},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{},
    }, .{});
}

fn makeServerCtxNoSigSchemes() !tls13.Context {
    return tls13.Context.init(.{
        .allocator = testing.allocator,
        .role = .Server,
        .supported_groups = &.{active_group},
        .supported_signature_schemes = &.{},
        .quic_transport_parameters = &[_]u8{},
    }, .{});
}

// ============================================================================
// Test 1: parsed-state dump fires on CH1 entry
// ============================================================================

test "[TLS-HRR] CH1 parse-state dump fires after setClientHello succeeds" {
    // The orchestrator MUST emit a one-line `[TLS-HRR]` snapshot of the
    // parsed CH1 (key_share group + raw codepoint, key_len, cipher_suite
    // count, cookie presence) so interop logs can distinguish "client
    // offered X25519 but downstream check failed" from "client offered
    // group X classified as Y".
    beginCapture();
    defer endCapture();

    var server_ctx = try makeServerCtx();
    defer server_ctx.deinit();

    var p256_key: [65]u8 = undefined;
    p256_key[0] = 0x04;
    @memset(p256_key[1..], 0xBB);

    const ch1 = try buildFramedClientHello(testing.allocator, .{
        .group_code = 0x0017, // secp256r1 (mvfst path)
        .key_bytes = &p256_key,
    });
    defer testing.allocator.free(ch1);

    try server_ctx.processCrypto(.Initial, ch1);

    // The dump must mark the CH index, the encryption level, the parsed
    // group, and the raw codepoint so interop logs disambiguate quic-go's
    // 0x6399 from mvfst's 0x0017.
    try testing.expect(captureContains("[TLS-HRR] ClientHello"));
    try testing.expect(captureContains("raw_group_code=0x0017"));
    try testing.expect(captureContains("level=Initial"));
}

test "[TLS-HRR] CH1 parse-state dump records PQ-hybrid raw codepoint (quic-go path)" {
    beginCapture();
    defer endCapture();

    var server_ctx = try makeServerCtx();
    defer server_ctx.deinit();

    var hybrid_key: [1216]u8 = undefined;
    @memset(&hybrid_key, 0xCC);

    const ch1 = try buildFramedClientHello(testing.allocator, .{
        .group_code = 0x6399, // x25519_kyber768_draft00
        .key_bytes = &hybrid_key,
    });
    defer testing.allocator.free(ch1);

    try server_ctx.processCrypto(.Initial, ch1);

    try testing.expect(captureContains("[TLS-HRR] ClientHello"));
    try testing.expect(captureContains("raw_group_code=0x6399"));
}

// ============================================================================
// Test 2: setClientHello parse-failure diagnostics
// ============================================================================

test "[TLS-HRR] CH1 with no key_share extension surfaces MissingKeyShare via diagnostic" {
    // RFC 8446 §4.2.8: ClientHello MUST include a key_share extension.
    // `ClientHelloInfo.parse` raises `MissingKeyShare` and
    // `dispatchHandshake.client_hello` propagates it via `failAlert`.
    // The diagnostic distinguishes "client did not offer key_share at
    // all" (RFC violation) from "client offered an unsupported group"
    // (legitimate HRR trigger). Without it the QUIC layer only sees a
    // generic NoHandshakeKeys.
    beginCapture();
    defer endCapture();

    var server_ctx = try makeServerCtx();
    defer server_ctx.deinit();

    const ch1 = try buildFramedClientHello(testing.allocator, .{
        .group_code = null, // <-- omits key_share extension
        .key_bytes = &[_]u8{},
    });
    defer testing.allocator.free(ch1);

    try testing.expectError(
        tls13.HandshakeError.MissingKeyShare,
        server_ctx.processCrypto(.Initial, ch1),
    );

    try testing.expect(captureContains("[TLS-HRR] ClientHello parse failed"));
    try testing.expect(captureContains("MissingKeyShare"));
}

test "[TLS-HRR] CH1 with empty cipher_suites surfaces NoCipherSuite via diagnostic" {
    // `ClientHelloInfo.parse` raises NoCipherSuite when the offered
    // suites list contains no TLS 1.3 entries.
    beginCapture();
    defer endCapture();

    var server_ctx = try makeServerCtx();
    defer server_ctx.deinit();

    var x25519_key: [32]u8 = undefined;
    @memset(&x25519_key, 0x77);

    const ch1 = try buildFramedClientHello(testing.allocator, .{
        .group_code = 0x001d,
        .key_bytes = &x25519_key,
        .cipher_suites = &[_]u16{0x009C}, // TLS_RSA_WITH_AES_128_GCM_SHA256 (TLS 1.2 only)
    });
    defer testing.allocator.free(ch1);

    try testing.expectError(
        tls13.HandshakeError.NoCipherSuite,
        server_ctx.processCrypto(.Initial, ch1),
    );

    try testing.expect(captureContains("[TLS-HRR] ClientHello parse failed"));
    try testing.expect(captureContains("NoCipherSuite"));
}

// ============================================================================
// Test 3: negotiateCipherAndKeys early-return diagnostics
// ============================================================================

test "[TLS-HRR] negotiate NoSignatureScheme (server-config-empty) surfaces diagnostic" {
    // The orchestrator's first NoSignatureScheme path: server's
    // supported_signature_schemes config is empty. Without the
    // diagnostic the QUIC layer only sees NoHandshakeKeys.
    beginCapture();
    defer endCapture();

    var server_ctx = try makeServerCtxNoSigSchemes();
    defer server_ctx.deinit();

    var x25519_key: [32]u8 = undefined;
    @memset(&x25519_key, 0x77);

    const ch1 = try buildFramedClientHello(testing.allocator, .{
        .group_code = 0x001d,
        .key_bytes = &x25519_key,
    });
    defer testing.allocator.free(ch1);

    try testing.expectError(
        tls13.HandshakeError.NoSignatureScheme,
        server_ctx.processCrypto(.Initial, ch1),
    );

    try testing.expect(captureContains("[TLS-HRR] negotiate"));
    try testing.expect(captureContains("NoSignatureScheme"));
    try testing.expect(captureContains("server_config_empty"));
}

test "[TLS-HRR] negotiate NoSignatureScheme (peer-list-missing) surfaces diagnostic" {
    // The orchestrator's second NoSignatureScheme path: client did not
    // include a signature_algorithms extension at all. Most TLS 1.3
    // stacks send it, but synthetic CHs may omit it.
    beginCapture();
    defer endCapture();

    var server_ctx = try makeServerCtx();
    defer server_ctx.deinit();

    var x25519_key: [32]u8 = undefined;
    @memset(&x25519_key, 0x77);

    const ch1 = try buildFramedClientHello(testing.allocator, .{
        .group_code = 0x001d,
        .key_bytes = &x25519_key,
        .sig_algs = &[_]u16{}, // omit signature_algorithms
    });
    defer testing.allocator.free(ch1);

    try testing.expectError(
        tls13.HandshakeError.NoSignatureScheme,
        server_ctx.processCrypto(.Initial, ch1),
    );

    try testing.expect(captureContains("[TLS-HRR] negotiate"));
    try testing.expect(captureContains("NoSignatureScheme"));
    try testing.expect(captureContains("peer_list_missing"));
}

test "[TLS-HRR] negotiate NoSignatureScheme (no-overlap) surfaces diagnostic" {
    // The orchestrator's third NoSignatureScheme path: client offered a
    // signature_algorithms list, server has a list, but they do not
    // overlap (e.g. client wants RSA-PSS, server only has Ed25519).
    beginCapture();
    defer endCapture();

    var server_ctx = try makeServerCtx();
    defer server_ctx.deinit();

    var x25519_key: [32]u8 = undefined;
    @memset(&x25519_key, 0x77);

    const ch1 = try buildFramedClientHello(testing.allocator, .{
        .group_code = 0x001d,
        .key_bytes = &x25519_key,
        .sig_algs = &[_]u16{0x0804}, // rsa_pss_rsae_sha256 only
    });
    defer testing.allocator.free(ch1);

    try testing.expectError(
        tls13.HandshakeError.NoSignatureScheme,
        server_ctx.processCrypto(.Initial, ch1),
    );

    try testing.expect(captureContains("[TLS-HRR] negotiate"));
    try testing.expect(captureContains("NoSignatureScheme"));
    try testing.expect(captureContains("no_overlap"));
}

test "[TLS-HRR] negotiate UnsupportedKeyShareGroup (active group short key) surfaces diagnostic" {
    // RFC 7748 §6.1: X25519 public keys are 32 bytes. A CH offering
    // group=0x001d with a non-32-byte key trips the
    // `key.len != 32` guard in `negotiateCipherAndKeys`. Diagnostic
    // distinguishes "wrong key length" from "wrong group".
    beginCapture();
    defer endCapture();

    var server_ctx = try makeServerCtx();
    defer server_ctx.deinit();

    // 31-byte X25519 key (off by one — also rejected by parseKeyShare's
    // X25519 fast path, so it falls through to the unsupported-sentinel
    // path with group=.x25519 set by the std.enums.fromInt mapping).
    var short_key: [if (tls13.fips_enabled) 1215 else 31]u8 = undefined;
    @memset(&short_key, 0x77);

    const ch1 = try buildFramedClientHello(testing.allocator, .{
        .group_code = active_code,
        .key_bytes = &short_key,
    });
    defer testing.allocator.free(ch1);

    try testing.expectError(
        tls13.HandshakeError.UnsupportedKeyShareGroup,
        server_ctx.processCrypto(.Initial, ch1),
    );

    try testing.expect(captureContains("[TLS-HRR] negotiate"));
    try testing.expect(captureContains("UnsupportedKeyShareGroup"));
    try testing.expect(captureContains(if (tls13.fips_enabled) "hybrid_bad_len" else "x25519_short_key"));
}

// ============================================================================
// Test 4: HRR-emit diagnostic also fires (covers existing path is unchanged)
// ============================================================================

test "[TLS-HRR] HRR emission still fires diagnostic for non-X25519 CH1" {
    // Sanity check: the non-X25519 first ClientHello path still queues
    // HRR, AND now also produces the parse-state dump from Test 1.
    // Confirms the diagnostic is additive, not a behaviour change.
    beginCapture();
    defer endCapture();

    var server_ctx = try makeServerCtx();
    defer server_ctx.deinit();

    var p256_key: [65]u8 = undefined;
    p256_key[0] = 0x04;
    @memset(p256_key[1..], 0xBB);

    const ch1 = try buildFramedClientHello(testing.allocator, .{
        .group_code = 0x0017,
        .key_bytes = &p256_key,
    });
    defer testing.allocator.free(ch1);

    try server_ctx.processCrypto(.Initial, ch1);
    try testing.expect(server_ctx.hrr_sent);

    // CH1 parse-state dump must include the raw codepoint AND the run
    // proceeded into HRR emission (no error raised).
    try testing.expect(captureContains("raw_group_code=0x0017"));
}

// ============================================================================
// Test 5: [TLS-HS] success-path install diagnostics
// ============================================================================
//
// The existing `[TLS-HRR]` lines fire only on FAILURE branches inside
// `negotiateCipherAndKeys`. When none of them surface in a failing interop
// run, the absence is ambiguous — it could mean either:
//
//   (a) the TLS engine completed `installTrafficSecret(.Handshake, .send, …)`
//       successfully, in which case the QUIC layer's `NoHandshakeKeys` is a
//       downstream fault; OR
//   (b) the TLS engine never reached the install code path at all (silent
//       upstream failure), in which case the QUIC `NoHandshakeKeys` is the
//       correct upstream symptom.
//
// The QUIC team cannot distinguish these from the `[TLS-HRR]` failure
// surface alone. The 2026-04-27 finding in `docs/QUIC_INTEROP_HRR_ISSUE.md`
// explicitly recommends instrumenting "did `secrets.handshake.send.valid`
// flip false-to-true at any point? did `onSecretAvailable` fire?" — both
// of which are TLS-owned events at the `installTrafficSecret` call site.
//
// These tests assert that a tagged `[TLS-HS]` line surfaces exactly once
// per successful `installTrafficSecret` call, recording level, direction,
// secret length, and whether the `on_secret_available` callback was wired.
// Together with the existing `[TLS-HRR]` failure diagnostics, an interop
// log can now unambiguously bracket the QUIC<->TLS boundary.

test "[TLS-HS] handshake send secret install fires success-path diagnostic" {
    // Drives a full standalone-X25519 negotiation to install handshake
    // secrets; X25519 is not FIPS-approved, so skip under -Dfips=true.
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    // A direct X25519 ClientHello drives the orchestrator past the HRR gate
    // and into `emitServerFlight`, which calls
    // `installHandshakeTrafficPair(server_hs, client_hs)` BEFORE the cert
    // emission step. Without server certs configured, `buildCertificateMsg`
    // raises `MissingCertificate` AFTER the install completes — which is
    // exactly the observability moment the QUIC team asked for. The
    // post-install slot.valid check confirms the install actually happened;
    // the `[TLS-HS]` capture confirms it was *observable*.
    beginCapture();
    defer endCapture();

    var server_ctx = try makeServerCtx();
    defer server_ctx.deinit();

    var x25519_key: [32]u8 = undefined;
    @memset(&x25519_key, 0x77);

    const ch1 = try buildFramedClientHello(testing.allocator, .{
        .group_code = 0x001d,
        .key_bytes = &x25519_key,
    });
    defer testing.allocator.free(ch1);

    // Same downstream-error catch shape as the existing HRR-server CH2 test:
    // installHandshakeTrafficPair runs first; the cert/sig path errors after.
    server_ctx.processCrypto(.Initial, ch1) catch |err| switch (err) {
        error.MissingCertificate,
        error.NoSignatureScheme,
        error.UnexpectedMessage,
        error.InternalError,
        => {},
        else => return err,
    };

    // The send slot must be valid AND the diagnostic line must have fired.
    // Together they prove the install completed AND was observable.
    const hs_send = server_ctx.secrets.slot(.Handshake, .send);
    try testing.expect(hs_send.valid);
    try testing.expect(captureContains("[TLS-HS] secret installed"));
    try testing.expect(captureContains("level=Handshake"));
    try testing.expect(captureContains("dir=send"));
    try testing.expect(captureContains("role=Server"));
}

test "[TLS-HS] handshake recv secret install also fires diagnostic" {
    // Standalone-X25519 secret-install path; not FIPS-approved, skip under fips.
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    // Companion to the send test. The QUIC layer's boundary check inspects
    // BOTH directions (zig-quic conn.hs_server / conn.hs_client), so both
    // install events must be observable from the TLS side. The atomic
    // install in `installHandshakeTrafficPair` does send first then recv;
    // the `[TLS-HS]` line must fire for recv even though the test ends with
    // a downstream error from cert emission.
    beginCapture();
    defer endCapture();

    var server_ctx = try makeServerCtx();
    defer server_ctx.deinit();

    var x25519_key: [32]u8 = undefined;
    @memset(&x25519_key, 0x88);

    const ch1 = try buildFramedClientHello(testing.allocator, .{
        .group_code = 0x001d,
        .key_bytes = &x25519_key,
    });
    defer testing.allocator.free(ch1);

    server_ctx.processCrypto(.Initial, ch1) catch |err| switch (err) {
        error.MissingCertificate,
        error.NoSignatureScheme,
        error.UnexpectedMessage,
        error.InternalError,
        => {},
        else => return err,
    };

    try testing.expect(captureContains("dir=recv"));
}

test "[TLS-HS] secret install records on_secret_available callback state" {
    // Standalone-X25519 secret-install path; not FIPS-approved, skip under fips.
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    // The diagnostic must distinguish "callback fired" (the embedding QUIC
    // stack was notified that secrets are now usable) from "callback
    // not_registered" (TLS installed the slot but no one is listening).
    // Without this distinction, a zig-quic build that forgot to wire
    // `setTestSink` and also forgot `Callbacks.on_secret_available` would
    // produce silently degraded interop logs that look the same as a
    // properly-wired stack.
    //
    // makeServerCtx() leaves `on_secret_available = null`, so the line must
    // explicitly read `on_secret_available=not_registered`.
    beginCapture();
    defer endCapture();

    var server_ctx = try makeServerCtx();
    defer server_ctx.deinit();

    var x25519_key: [32]u8 = undefined;
    @memset(&x25519_key, 0x99);

    const ch1 = try buildFramedClientHello(testing.allocator, .{
        .group_code = 0x001d,
        .key_bytes = &x25519_key,
    });
    defer testing.allocator.free(ch1);

    server_ctx.processCrypto(.Initial, ch1) catch |err| switch (err) {
        error.MissingCertificate,
        error.NoSignatureScheme,
        error.UnexpectedMessage,
        error.InternalError,
        => {},
        else => return err,
    };

    try testing.expect(captureContains("on_secret_available=not_registered"));
}

test "[TLS-HS] secret install reports on_secret_available=fired when callback wired" {
    // Standalone-X25519 secret-install path; not FIPS-approved, skip under fips.
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    // Counterpart to the not_registered test: when a callback IS registered,
    // the diagnostic must read `on_secret_available=fired` so the QUIC team
    // can see in the log that the boundary notification actually delivered.
    // The callback below is a stub that simply records that it fired; the
    // important assertion is the captured log line.
    beginCapture();
    defer endCapture();

    const Stub = struct {
        var fire_count: u32 = 0;
        fn cb(ctx: *tls13.Context, level: tls13.EncryptionLevel, secret: []const u8) anyerror!void {
            _ = ctx;
            _ = level;
            _ = secret;
            fire_count += 1;
        }
    };
    Stub.fire_count = 0;

    var server_ctx = try tls13.Context.init(.{
        .allocator = testing.allocator,
        .role = .Server,
        .supported_groups = &.{active_group},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{},
    }, .{ .on_secret_available = Stub.cb });
    defer server_ctx.deinit();

    var x25519_key: [32]u8 = undefined;
    @memset(&x25519_key, 0xAA);

    const ch1 = try buildFramedClientHello(testing.allocator, .{
        .group_code = 0x001d,
        .key_bytes = &x25519_key,
    });
    defer testing.allocator.free(ch1);

    server_ctx.processCrypto(.Initial, ch1) catch |err| switch (err) {
        error.MissingCertificate,
        error.NoSignatureScheme,
        error.UnexpectedMessage,
        error.InternalError,
        => {},
        else => return err,
    };

    // The callback must have fired at least once for Handshake.send and
    // .recv (both directions install handshake traffic secrets), and the
    // log must record that the callback fired (not just that the slot
    // store succeeded).
    try testing.expect(Stub.fire_count >= 2);
    try testing.expect(captureContains("on_secret_available=fired"));
}
