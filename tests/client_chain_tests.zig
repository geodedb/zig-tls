//! Chain completion from configured trust anchors (SONNY-6457).
//!
//! A peer may send only its leaf certificate. `Config.trusted_ca_der` lists
//! the CAs the verifier trusts; the verifier completes the leaf's path from
//! them (RFC 5280 §6.1) and trusts only them.
//!
//!   - Server verifying a client (mTLS): `handleClientCertificateVerify`
//!     validated the chain exactly as sent, against the process-global trust
//!     store, so a client leaf signed by a configured CA but sent without
//!     the CA was rejected.
//!   - Either side, more than one anchor: every anchor the peer did not send
//!     was appended to the chain, so the chain walk checked one anchor's
//!     signature against the next and failed as soon as a second, unrelated
//!     anchor was configured.
//!
//! Real in-memory TLS 1.3 handshakes over Ed25519 fixtures
//! (tests/test_certs/gen_client_chain.sh).

const std = @import("std");
const testing = std.testing;
const x509 = @import("x509");
const tls13 = @import("tls13");
const tls13_full = @import("tls13_full");

const server_cert = @embedFile("test_certs/ed25519_cert.der");
const server_key = @embedFile("test_certs/ed25519_key.der");
const client_ca = @embedFile("test_certs/client_chain_ca.der");
const other_ca = @embedFile("test_certs/client_chain_other_ca.der");
const client_leaf = @embedFile("test_certs/client_chain_leaf.der");
const client_leaf_key = @embedFile("test_certs/client_chain_leaf_key.der");

/// Process-global trust store holding only the server's self-signed
/// certificate: used by the client unless it configures trusted_ca_der.
const Global = struct {
    var anchor_spki: []const u8 = &[_]u8{};
    fn isTrusted(spki: []const u8) bool {
        return std.mem.eql(u8, spki, anchor_spki);
    }
};

fn loopback(alloc: std.mem.Allocator, client: *tls13.Context, server: *tls13.Context) !void {
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
            if (try Pump.relay(alloc, client, server, lvl)) progressed = true;
            if (try Pump.relay(alloc, server, client, lvl)) progressed = true;
        }
        if (!progressed) break;
    }
}

const Setup = struct {
    /// Anchors the server trusts for client certificates (null: none).
    server_client_anchors: ?[]const []const u8 = null,
    /// Anchors the client trusts for the server certificate (null: global).
    client_server_anchors: ?[]const []const u8 = null,
    mtls: bool = true,
};

/// Runs one handshake; true when both sides completed it and, with mTLS,
/// the server holds the client's CertificateVerify.
fn handshake(alloc: std.mem.Allocator, setup: Setup) !bool {
    var anchor = try x509.parseCert(alloc, server_cert);
    defer anchor.deinit(alloc);
    Global.anchor_spki = anchor.spki;
    x509.setTrustStore(.{ .isTrustedSpki = Global.isTrusted });
    defer x509.setTrustStore(null);

    var server = try tls13.Context.init(.{
        .allocator = alloc,
        .role = .Server,
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .server_cert_der = server_cert,
        .server_key_der = server_key,
        .request_client_cert = setup.mtls,
        .trusted_ca_der = setup.server_client_anchors,
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
        .client_cert_der = if (setup.mtls) client_leaf else null,
        .client_key_der = if (setup.mtls) client_leaf_key else null,
        .trusted_ca_der = setup.client_server_anchors,
        .quic_transport_parameters = &[_]u8{},
    }, .{});
    defer client.deinit();

    loopback(alloc, &client, &server) catch return false;
    if (client.phase != .application_ready) return false;
    if (!server.secrets.exporter_master.valid) return false;
    if (setup.mtls and server.peer_cert_verify_sig == null) return false;
    return true;
}

test "client chain: a leaf sent without its CA verifies against the configured client CA" {
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    try testing.expect(try handshake(testing.allocator, .{ .server_client_anchors = &.{client_ca} }));
}

test "client chain: the issuing CA is found among several configured anchors" {
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    try testing.expect(try handshake(testing.allocator, .{ .server_client_anchors = &.{ other_ca, client_ca } }));
    try testing.expect(try handshake(testing.allocator, .{ .server_client_anchors = &.{ client_ca, other_ca } }));
}

test "client chain: a leaf from a CA that is not configured is refused" {
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    try testing.expect(!try handshake(testing.allocator, .{ .server_client_anchors = &.{other_ca} }));
    // No configured anchors and a global store that does not hold the CA.
    try testing.expect(!try handshake(testing.allocator, .{}));
}

test "server chain: several configured anchors still verify a self-signed server certificate" {
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    try testing.expect(try handshake(testing.allocator, .{ .mtls = false, .client_server_anchors = &.{ other_ca, server_cert } }));
    try testing.expect(!try handshake(testing.allocator, .{ .mtls = false, .client_server_anchors = &.{other_ca} }));
}
