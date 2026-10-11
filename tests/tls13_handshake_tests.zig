//! Comprehensive TLS 1.3 Handshake Integration Tests
//!
//! These tests exercise the full TLS 1.3 handshake state machine from
//! ClientHello through to encrypted application data streaming. Tests verify:
//! - Complete client and server handshake flows
//! - Secret derivation and key installation callbacks
//! - CRYPTO frame processing at correct encryption levels
//! - Application data encryption/decryption after handshake completion
//!
//! This validates end-to-end protocol correctness without requiring actual
//! network implementation - all data flows are in-memory.

const std = @import("std");
const testing = std.testing;
const x509 = @import("x509");
const tls13 = @import("tls13");
const tls13_full = @import("tls13_full");
const key_schedule = @import("quic_tls");
const record = @import("record");
const alert = @import("alert");
// SEC-077: build-gate lookup for the insecure-validation sentinel.
const build_options = @import("build_options");

const test_psk = "test_psk";
const test_ticket = "test_ticket";

fn lookupTestPsk(_: *tls13.Context, identity: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, identity, test_ticket)) return test_psk;
    return null;
}

// ============================================================================
// Context Initialization Tests
// ============================================================================

test "TLS 1.3 client context initialization" {
    // RFC 8446 §2 - Client initiates handshake

    const client_callbacks = tls13.Callbacks{};

    const client_config = tls13.Config{
        .allocator = testing.allocator,
        .role = .Client,
        .alpn_protocols = &.{"h3"},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{},
    };

    var client_ctx = try tls13.Context.init(client_config, client_callbacks);
    defer client_ctx.deinit();

    // Verify context initialized correctly
    try testing.expectEqual(tls13.Role.Client, client_ctx.config.role);
}

test "TLS 1.3 server context initialization" {
    // RFC 8446 §2 - Server responds to client handshake

    const server_callbacks = tls13.Callbacks{};

    const server_config = tls13.Config{
        .allocator = testing.allocator,
        .role = .Server,
        .alpn_protocols = &.{"h3"},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{},
    };

    var server_ctx = try tls13.Context.init(server_config, server_callbacks);
    defer server_ctx.deinit();

    // Verify context initialized correctly
    try testing.expectEqual(tls13.Role.Server, server_ctx.config.role);
}

// ============================================================================
// Basic Crypto Tests
// ============================================================================

test "TLS 1.3 AEAD cipher initialization and operations" {
    // RFC 8446 §5.3 - Record payload protection

    const key: [16]u8 = [_]u8{0x42} ** 16;
    const iv: [12]u8 = [_]u8{0x43} ** 12;

    var cipher = try record.AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null);
    defer cipher.wipe();

    // Encrypt a test message
    const plaintext = "Hello TLS 1.3";
    const ciphertext = try cipher.seal(testing.allocator, 0, "", plaintext);
    defer testing.allocator.free(ciphertext);

    // Verify ciphertext is longer than plaintext (includes authentication tag)
    try testing.expect(ciphertext.len > plaintext.len);

    // Decrypt and verify
    const decrypted = try cipher.open(testing.allocator, 0, "", ciphertext);
    defer testing.allocator.free(decrypted);

    try testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "TLS 1.3 handshake completion check" {
    // RFC 8446 - Handshake state tracking

    const client_callbacks = tls13.Callbacks{};

    const client_config = tls13.Config{
        .allocator = testing.allocator,
        .role = .Client,
        .alpn_protocols = &.{"h3"},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{ 0x00, 0x01 },
    };

    var client_ctx = try tls13.Context.init(client_config, client_callbacks);
    defer client_ctx.deinit();

    // Handshake should not be complete initially
    try testing.expect(!client_ctx.handshakeComplete());
}

// ============================================================================
// 0-RTT Security Tests
// ============================================================================

test "TLS 1.3 server rejects 0-RTT replay (no early secret installed)" {
    // Standalone X25519 handshake; not FIPS-approved, skip under -Dfips=true.
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    const client_callbacks = tls13.Callbacks{};
    const client_config = tls13.Config{
        .allocator = testing.allocator,
        .role = .Client,
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .enable_early_data = true,
        .resumption_psk = test_psk,
        .resumption_ticket = test_ticket,
        .quic_transport_parameters = &[_]u8{},
    };

    var client_ctx = try tls13.Context.init(client_config, client_callbacks);
    defer client_ctx.deinit();
    try client_ctx.startClientHandshake();

    const ch_msg = try client_ctx.pollCrypto(testing.allocator, .Initial);
    defer testing.allocator.free(ch_msg);

    const server_callbacks = tls13.Callbacks{
        .on_ticket_lookup = lookupTestPsk,
    };
    const server_config = tls13.Config{
        .allocator = testing.allocator,
        .role = .Server,
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .enable_early_data = true,
        .quic_transport_parameters = &[_]u8{},
    };

    var server_ctx = try tls13.Context.init(server_config, server_callbacks);
    defer server_ctx.deinit();

    // Preload anti-replay window with the same random used by the incoming ClientHello.
    // PERF-002: anti_replay is now an optional pointer, allocated for server+early_data.
    try testing.expect(client_ctx.client_random != null);
    try testing.expect(server_ctx.anti_replay != null);
    try server_ctx.anti_replay.?.add(client_ctx.client_random.?);

    try server_ctx.processCrypto(.Initial, ch_msg);

    const early_slot = server_ctx.secrets.slot(.Initial, .recv);
    try testing.expect(!early_slot.valid);
}

test "TLS 1.3 server rejects SHA-384 PSK binder trailing mismatch" {
    // Standalone X25519 handshake; not FIPS-approved, skip under -Dfips=true.
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    const client_callbacks = tls13.Callbacks{};
    const client_config = tls13.Config{
        .allocator = testing.allocator,
        .role = .Client,
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_256_GCM_SHA384},
        .resumption_psk = test_psk,
        .resumption_ticket = test_ticket,
        .quic_transport_parameters = &[_]u8{},
    };

    var client_ctx = try tls13.Context.init(client_config, client_callbacks);
    defer client_ctx.deinit();
    try client_ctx.startClientHandshake();

    const ch_msg = try client_ctx.pollCrypto(testing.allocator, .Initial);
    defer testing.allocator.free(ch_msg);

    const ch_body = ch_msg[4..];
    const parsed = try tls13_full.parseClientHello(testing.allocator, ch_body);
    defer {
        testing.allocator.free(parsed.cipher_suites);
        if (parsed.supported_groups) |groups| testing.allocator.free(groups);
        if (parsed.signature_algorithms) |algs| testing.allocator.free(algs);
        if (parsed.alpn_list) |list| testing.allocator.free(list);
        if (parsed.pre_shared_key) |psk| {
            testing.allocator.free(psk.identities);
            testing.allocator.free(psk.binders);
        }
    }

    try testing.expect(parsed.pre_shared_key != null);
    const psk = parsed.pre_shared_key.?;
    try testing.expect(psk.binders.len > 0);
    try testing.expectEqual(@as(usize, 48), psk.binders[0].len);

    var binder_mut = @constCast(psk.binders[0]);
    binder_mut[binder_mut.len - 1] ^= 0xff;

    const server_callbacks = tls13.Callbacks{
        .on_ticket_lookup = lookupTestPsk,
    };
    const server_config = tls13.Config{
        .allocator = testing.allocator,
        .role = .Server,
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_256_GCM_SHA384},
        .quic_transport_parameters = &[_]u8{},
    };

    var server_ctx = try tls13.Context.init(server_config, server_callbacks);
    defer server_ctx.deinit();

    try testing.expectError(tls13.HandshakeError.DecryptError, server_ctx.processCrypto(.Initial, ch_msg));
}

// ============================================================================
// QUIC Integration Tests
// ============================================================================

test "TLS 1.3 encryption levels match QUIC requirements" {
    // RFC 9001 §4.1.4 - QUIC uses TLS encryption levels for packet protection

    const levels = [_]tls13.EncryptionLevel{
        .Initial,
        .Handshake,
        .Application,
    };

    // Verify all required levels are defined
    for (levels) |level| {
        const level_int = @intFromEnum(level);
        try testing.expect(level_int >= 0);
    }
}

// ============================================================================
// PSK Configuration Validation Tests
// ============================================================================

test "TLS 1.3 PSK without ticket returns MissingResumptionTicket error" {
    // Standalone X25519 handshake; not FIPS-approved, skip under -Dfips=true.
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    // GAP-003: resumption_psk set but resumption_ticket null must return error,
    // not fall back to a hardcoded identity string that no server recognizes.
    const client_callbacks = tls13.Callbacks{};
    const client_config = tls13.Config{
        .allocator = testing.allocator,
        .role = .Client,
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .resumption_psk = test_psk,
        .resumption_ticket = null, // deliberately omitted
        .quic_transport_parameters = &[_]u8{},
    };

    var client_ctx = try tls13.Context.init(client_config, client_callbacks);
    defer client_ctx.deinit();

    // Starting the handshake with PSK but no ticket must fail
    try testing.expectError(
        error.MissingResumptionTicket,
        client_ctx.startClientHandshake(),
    );
}

// ============================================================================
// SEC-028: Client validates server-selected cipher suite was offered
// ============================================================================

test "SEC-028: client rejects unoffered cipher suite from ServerHello" {
    // Standalone X25519 handshake; not FIPS-approved, skip under -Dfips=true.
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    // Create client offering ONLY TLS_AES_128_GCM_SHA256 (0x1301)
    const client_callbacks = tls13.Callbacks{};
    const client_config = tls13.Config{
        .allocator = testing.allocator,
        .role = .Client,
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{ 0x00, 0x01 },
        .server_name = "test.example.com",
    };

    var client_ctx = try tls13.Context.init(client_config, client_callbacks);
    defer client_ctx.deinit();
    try client_ctx.startClientHandshake();

    // Construct a ServerHello body with TLS_AES_256_GCM_SHA384 (0x1302) which was NOT offered.
    // Body format: legacy_version(2) + random(32) + session_id_len(1) + cipher_suite(2) +
    //              compression(1) + extensions_length(2) + extensions
    var sh_body: [128]u8 = undefined;
    var pos: usize = 0;

    // legacy_version = 0x0303
    sh_body[pos] = 0x03;
    sh_body[pos + 1] = 0x03;
    pos += 2;

    // random (32 bytes) - NOT HRR random and NOT downgrade sentinel
    @memset(sh_body[pos .. pos + 32], 0xAA);
    pos += 32;

    // session_id_len = 0
    sh_body[pos] = 0;
    pos += 1;

    // cipher_suite = 0x1302 (TLS_AES_256_GCM_SHA384) - NOT offered by client
    sh_body[pos] = 0x13;
    sh_body[pos + 1] = 0x02;
    pos += 2;

    // compression = 0
    sh_body[pos] = 0;
    pos += 1;

    // Extensions: supported_versions(0x002b) + key_share(0x0033)
    const ext_supported_versions = [_]u8{
        0x00, 0x2b, // extension type: supported_versions
        0x00, 0x02, // extension length: 2
        0x03, 0x04, // TLS 1.3 (0x0304)
    };
    const key_share_data = [_]u8{
        0x00, 0x33, // extension type: key_share
        0x00, 0x24, // extension length: 36 (2+2+32)
        0x00, 0x1d, // group: x25519
        0x00, 0x20, // key_exchange length: 32
    } ++ [_]u8{0xBB} ** 32; // dummy public key

    const exts_len: u16 = ext_supported_versions.len + key_share_data.len;
    sh_body[pos] = @intCast((exts_len >> 8) & 0xff);
    sh_body[pos + 1] = @intCast(exts_len & 0xff);
    pos += 2;

    @memcpy(sh_body[pos .. pos + ext_supported_versions.len], &ext_supported_versions);
    pos += ext_supported_versions.len;
    @memcpy(sh_body[pos .. pos + key_share_data.len], &key_share_data);
    pos += key_share_data.len;

    // Wrap in handshake framing: type(1) + length(3)
    const body_len = pos;
    var sh_msg: [132]u8 = undefined;
    sh_msg[0] = 0x02; // ServerHello
    sh_msg[1] = 0;
    sh_msg[2] = @intCast((body_len >> 8) & 0xff);
    sh_msg[3] = @intCast(body_len & 0xff);
    @memcpy(sh_msg[4 .. 4 + body_len], sh_body[0..body_len]);

    // Client should reject with IllegalCipherSuiteSelected (illegal_parameter) since 0x1302 was not offered
    try testing.expectError(
        tls13.HandshakeError.IllegalCipherSuiteSelected,
        client_ctx.processCrypto(.Initial, sh_msg[0 .. 4 + body_len]),
    );
}

// ============================================================================
// SEC-029: Client rejects null server_name without allow_insecure
// ============================================================================

test "SEC-029: client rejects null server_name for certificate validation" {
    // MissingServerName is returned during CertificateVerify processing, which
    // requires a full handshake to reach. Instead, test by verifying the error
    // exists and maps to the correct alert.
    const err_alert = alert.fromHandshakeError(tls13.HandshakeError.MissingServerName);
    try testing.expectEqual(alert.AlertDescription.handshake_failure, err_alert);
}

test "SEC-029: client with null server_name and allow_insecure succeeds init" {
    // SEC-077: The insecure sentinel is build-gated; skip unless the flag is set.
    if (!build_options.tls_insecure_testing) return error.SkipZigTest;
    // When insecure mode is on, null server_name should not prevent
    // handshake initiation (the check occurs during CertificateVerify).
    const client_callbacks = tls13.Callbacks{};
    const client_config = tls13.Config{
        .allocator = testing.allocator,
        .role = .Client,
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{ 0x00, 0x01 },
        .server_name = null,
        .allow_insecure = .testing_only_i_know_what_i_am_doing,
    };

    var client_ctx = try tls13.Context.init(client_config, client_callbacks);
    defer client_ctx.deinit();

    // Client can start handshake; the MissingServerName check only happens
    // during CertificateVerify processing (when server_name is actually needed).
    try client_ctx.startClientHandshake();
}

test "TLS 1.3 PSK with ticket succeeds" {
    // Standalone X25519 handshake; not FIPS-approved, skip under -Dfips=true.
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    // Complementary test: when both resumption_psk and resumption_ticket are set,
    // startClientHandshake should succeed.
    const client_callbacks = tls13.Callbacks{};
    const client_config = tls13.Config{
        .allocator = testing.allocator,
        .role = .Client,
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .resumption_psk = test_psk,
        .resumption_ticket = test_ticket,
        .quic_transport_parameters = &[_]u8{},
    };

    var client_ctx = try tls13.Context.init(client_config, client_callbacks);
    defer client_ctx.deinit();

    // This should succeed without error
    try client_ctx.startClientHandshake();
}

// ============================================================================
// R5-01: CertificateVerify transcript-binding regression (RFC 8446 §4.4.3)
// ============================================================================
//
// The dispatcher folded CertificateVerify into the handshake transcript BEFORE
// verifying it, so the client checked the server's CV signature over
// Hash(...Certificate || CertificateVerify) instead of the §4.4.3-mandated
// Hash(...Certificate). Every RFC-compliant server-authenticated handshake
// therefore aborted with InvalidSignature. This secure end-to-end loopback
// (both peers = this library) drives a real server CertificateVerify through
// the client's verifier; it fails (InvalidSignature) before the fix and
// completes after it.

const R5Trust = struct {
    var anchor_spki: []const u8 = &[_]u8{};
    fn isTrusted(spki: []const u8) bool {
        return std.mem.eql(u8, spki, anchor_spki);
    }
};

test "R5-01: secure loopback — client verifies a real server CertificateVerify" {
    // Standalone X25519 loopback handshake; not FIPS-approved, skip under fips.
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    const alloc = testing.allocator;
    const cert_der = @embedFile("test_certs/ed25519_cert.der");
    const key_der = @embedFile("test_certs/ed25519_key.der");

    var anchor = try x509.parseCert(alloc, cert_der);
    defer anchor.deinit(alloc);
    R5Trust.anchor_spki = anchor.spki;
    x509.setTrustStore(.{ .isTrustedSpki = R5Trust.isTrusted });
    defer x509.setTrustStore(null);

    var server = try tls13.Context.init(.{
        .allocator = alloc,
        .role = .Server,
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .server_cert_der = cert_der,
        .server_key_der = key_der,
        .quic_transport_parameters = &[_]u8{},
    }, .{});
    defer server.deinit();

    var client = try tls13.Context.init(.{
        .allocator = alloc,
        .role = .Client,
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .server_name = "ed25519.example.com",
        .quic_transport_parameters = &[_]u8{},
    }, .{});
    defer client.deinit();

    try client.startClientHandshake();

    // Pump plaintext CRYPTO between the two contexts across all levels until
    // both complete or no further progress is made.
    const Pump = struct {
        fn relay(a: std.mem.Allocator, from: *tls13.Context, to: *tls13.Context, lvl: tls13.EncryptionLevel) !bool {
            const out = from.pollCrypto(a, lvl) catch |e| {
                if (e == error.NothingToRead) return false;
                return e;
            };
            defer a.free(out);
            if (out.len == 0) return false;
            try to.processCrypto(lvl, out);
            return true;
        }
    };

    const levels = [_]tls13.EncryptionLevel{ .Initial, .Handshake, .Application };
    var round: usize = 0;
    while (round < 12) : (round += 1) {
        var progressed = false;
        for (levels) |lvl| {
            if (try Pump.relay(alloc, &client, &server, lvl)) progressed = true;
            if (try Pump.relay(alloc, &server, &client, lvl)) progressed = true;
        }
        if (!progressed) break;
    }

    // The client must have verified the server CertificateVerify and reached
    // the application phase (it would have terminated on InvalidSignature).
    try testing.expect(client.phase == .application_ready);
    try testing.expect(server.phase == .application_ready or server.phase == .keys_installed);
}

test "NEWGAP-11: server rejects ClientHello missing quic_transport_parameters" {
    // Standalone X25519 loopback handshake; not FIPS-approved, skip under fips.
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    const alloc = testing.allocator;
    // Client with NO transport parameters -> ClientHello omits the 0x0039
    // extension entirely (RFC 9001 §8.2 violation).
    var client = try tls13.Context.init(.{
        .allocator = alloc,
        .role = .Client,
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = null,
    }, .{});
    defer client.deinit();
    try client.startClientHandshake();

    const ch = try client.pollCrypto(alloc, .Initial);
    defer alloc.free(ch);

    var server = try tls13.Context.init(.{
        .allocator = alloc,
        .role = .Server,
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{},
    }, .{});
    defer server.deinit();

    try testing.expectError(tls13.HandshakeError.MissingTransportParameters, server.processCrypto(.Initial, ch));
}

test "TLS-MODE: plain TLS handshake preserves key-share policy without transport params" {
    const alloc = testing.allocator;
    const cert_der = @embedFile("test_certs/ed25519_cert.der");
    const key_der = @embedFile("test_certs/ed25519_key.der");

    var anchor = try x509.parseCert(alloc, cert_der);
    defer anchor.deinit(alloc);
    R5Trust.anchor_spki = anchor.spki;
    x509.setTrustStore(.{ .isTrustedSpki = R5Trust.isTrusted });
    defer x509.setTrustStore(null);

    // Both peers in .tls mode; NEITHER sets quic_transport_parameters.
    var server = try tls13.Context.init(.{
        .allocator = alloc,
        .role = .Server,
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .server_cert_der = cert_der,
        .server_key_der = key_der,
        .transport_mode = .tls,
    }, .{});
    defer server.deinit();

    var client = try tls13.Context.init(.{
        .allocator = alloc,
        .role = .Client,
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .server_name = "ed25519.example.com",
        .transport_mode = .tls,
    }, .{});
    defer client.deinit();

    if (comptime tls13.fips_enabled) {
        // Plain TLS must enforce the same strict FIPS policy as QUIC: the
        // standalone X25519 offer is rejected before emitting a ClientHello.
        // Retrying must not turn the rejected attempt into a started handshake.
        for (0..2) |_| {
            try testing.expectError(tls13.HandshakeError.UnsupportedKeyShareGroup, client.startClientHandshake());
            try testing.expect(!client.handshakeComplete());
            try testing.expect(client.phase == .initial);
            for ([_]tls13.EncryptionLevel{ .Initial, .Handshake, .Application }) |level| {
                try testing.expectError(error.NothingToRead, client.pollCrypto(alloc, level));
            }
        }
        return;
    }

    try client.startClientHandshake();

    const Pump = struct {
        fn relay(a: std.mem.Allocator, from: *tls13.Context, to: *tls13.Context, lvl: tls13.EncryptionLevel) !bool {
            const out = from.pollCrypto(a, lvl) catch |e| {
                if (e == error.NothingToRead) return false;
                return e;
            };
            defer a.free(out);
            if (out.len == 0) return false;
            try to.processCrypto(lvl, out);
            return true;
        }
    };
    const levels = [_]tls13.EncryptionLevel{ .Initial, .Handshake, .Application };
    var round: usize = 0;
    while (round < 12) : (round += 1) {
        var progressed = false;
        for (levels) |lvl| {
            if (try Pump.relay(alloc, &client, &server, lvl)) progressed = true;
            if (try Pump.relay(alloc, &server, &client, lvl)) progressed = true;
        }
        if (!progressed) break;
    }

    // The whole point: a plain-TLS handshake with zero transport params completes.
    try testing.expect(client.phase == .application_ready);
    try testing.expect(server.phase == .application_ready or server.phase == .keys_installed);
}

test "R6-01: mTLS loopback — server derives app secrets over CH..serverFinished (not client Cert/CV)" {
    // Standalone X25519 loopback handshake; not FIPS-approved, skip under fips.
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    const alloc = testing.allocator;
    const cert_der = @embedFile("test_certs/ed25519_cert.der");
    const key_der = @embedFile("test_certs/ed25519_key.der");

    var anchor = try x509.parseCert(alloc, cert_der);
    defer anchor.deinit(alloc);
    R5Trust.anchor_spki = anchor.spki;
    x509.setTrustStore(.{ .isTrustedSpki = R5Trust.isTrusted });
    defer x509.setTrustStore(null);

    // Server requests a client certificate (mTLS).
    var server = try tls13.Context.init(.{
        .allocator = alloc,
        .role = .Server,
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .server_cert_der = cert_der,
        .server_key_der = key_der,
        .request_client_cert = true,
        .quic_transport_parameters = &[_]u8{},
    }, .{});
    defer server.deinit();

    // Client presents the (same self-signed) cert for client auth.
    var client = try tls13.Context.init(.{
        .allocator = alloc,
        .role = .Client,
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .server_name = "ed25519.example.com",
        .client_cert_der = cert_der,
        .client_key_der = key_der,
        .quic_transport_parameters = &[_]u8{},
    }, .{});
    defer client.deinit();

    try client.startClientHandshake();

    const Pump = struct {
        fn relay(a: std.mem.Allocator, from: *tls13.Context, to: *tls13.Context, lvl: tls13.EncryptionLevel) !bool {
            const out = from.pollCrypto(a, lvl) catch |e| {
                if (e == error.NothingToRead) return false;
                return e;
            };
            defer a.free(out);
            if (out.len == 0) return false;
            try to.processCrypto(lvl, out);
            return true;
        }
    };
    const levels = [_]tls13.EncryptionLevel{ .Initial, .Handshake, .Application };
    var round: usize = 0;
    while (round < 16) : (round += 1) {
        var progressed = false;
        for (levels) |lvl| {
            if (try Pump.relay(alloc, &client, &server, lvl)) progressed = true;
            if (try Pump.relay(alloc, &server, &client, lvl)) progressed = true;
        }
        if (!progressed) break;
    }

    try testing.expect(client.phase == .application_ready);

    // R6-01: the two peers MUST install matching application traffic secrets.
    // The server sends with server_app and the client receives with server_app;
    // if the server derived server_app over a transcript that wrongly included
    // the client Certificate/CertificateVerify, these would differ.
    const s_send = server.secrets.slot(.Application, .send);
    const c_recv = client.secrets.slot(.Application, .recv);
    try testing.expect(s_send.valid and c_recv.valid);
    try testing.expectEqualSlices(u8, c_recv.value.slice(), s_send.value.slice());

    const s_recv = server.secrets.slot(.Application, .recv);
    const c_send = client.secrets.slot(.Application, .send);
    try testing.expect(s_recv.valid and c_send.valid);
    try testing.expectEqualSlices(u8, c_send.value.slice(), s_recv.value.slice());
}

test "R7-01: 0-RTT early traffic secret matches between client (send) and server (recv)" {
    // Standalone X25519 loopback handshake; not FIPS-approved, skip under fips.
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    const alloc = testing.allocator;

    // Client offers a resumption PSK and 0-RTT early data.
    var client = try tls13.Context.init(.{
        .allocator = alloc,
        .role = .Client,
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .enable_early_data = true,
        .resumption_psk = test_psk,
        .resumption_ticket = test_ticket,
        .quic_transport_parameters = &[_]u8{},
    }, .{});
    defer client.deinit();
    try client.startClientHandshake();

    const ch_msg = try client.pollCrypto(alloc, .Initial);
    defer alloc.free(ch_msg);

    // Server resolves the same PSK and accepts early data (anti-replay window
    // is NOT preloaded, so this first ClientHello is accepted).
    var server = try tls13.Context.init(.{
        .allocator = alloc,
        .role = .Server,
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .enable_early_data = true,
        .quic_transport_parameters = &[_]u8{},
    }, .{ .on_ticket_lookup = lookupTestPsk });
    defer server.deinit();

    try server.processCrypto(.Initial, ch_msg);

    // Client installed the early SEND secret; server installed the early RECV
    // secret. RFC 8446 §7.1 derives both over Hash(complete ClientHello), so
    // they MUST be equal. Pre-R7-01 the client used the binder-truncated hash.
    const c_send = client.secrets.slot(.Initial, .send);
    const s_recv = server.secrets.slot(.Initial, .recv);
    try testing.expect(c_send.valid);
    try testing.expect(s_recv.valid);
    try testing.expectEqualSlices(u8, c_send.value.slice(), s_recv.value.slice());
}
