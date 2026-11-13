//! TLS 1.3 exporter regression (RFC 8446 §7.5).
//!
//!   TLS-Exporter(label, context_value, key_length) =
//!       HKDF-Expand-Label(Derive-Secret(Secret, label, ""),
//!                         "exporter", Hash(context_value), key_length)
//!
//! where Secret is the exporter_master_secret. Both ends of one connection
//! derive the same value. `Context.exportSecret` used Derive-Secret over the
//! label and the role's own "finished" transcript hash instead (client:
//! through its CertificateVerify, server: through server Finished), so the two
//! ends disagreed, and it zero-padded output past the hash length.
//!
//! The expected values are computed here independently with std.crypto HKDF.

const std = @import("std");
const testing = std.testing;
const x509 = @import("x509");
const tls13 = @import("tls13");
const tls13_full = @import("tls13_full");
const ks = @import("quic_tls");

/// HKDF-Expand-Label (RFC 8446 §7.1) over std.crypto, independent of the
/// library's key schedule.
fn refExpandLabel(comptime Hkdf: type, prk: []const u8, label: []const u8, context: []const u8, out: []u8) void {
    var info: [2 + 1 + 255 + 1 + 255]u8 = undefined;
    var n: usize = 0;
    std.mem.writeInt(u16, info[0..2], @intCast(out.len), .big);
    n = 2;
    const full_label_len = "tls13 ".len + label.len;
    info[n] = @intCast(full_label_len);
    n += 1;
    @memcpy(info[n..][0.."tls13 ".len], "tls13 ");
    n += "tls13 ".len;
    @memcpy(info[n..][0..label.len], label);
    n += label.len;
    info[n] = @intCast(context.len);
    n += 1;
    @memcpy(info[n..][0..context.len], context);
    n += context.len;
    var key: [Hkdf.prk_length]u8 = undefined;
    @memcpy(&key, prk[0..Hkdf.prk_length]);
    Hkdf.expand(out, info[0..n], key);
}

/// RFC 8446 §7.5 TLS-Exporter over std.crypto.
fn refExporter(comptime Hash: type, comptime Hkdf: type, exporter_master: []const u8, label: []const u8, context: []const u8, out: []u8) void {
    var empty_hash: [Hash.digest_length]u8 = undefined;
    Hash.hash("", &empty_hash, .{});
    var derived: [Hash.digest_length]u8 = undefined;
    refExpandLabel(Hkdf, exporter_master, label, &empty_hash, &derived);
    var context_hash: [Hash.digest_length]u8 = undefined;
    Hash.hash(context, &context_hash, .{});
    refExpandLabel(Hkdf, &derived, "exporter", &context_hash, out);
}

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);

fn contextWithExporterMaster(alloc: std.mem.Allocator, hash: ks.Hash, secret: []const u8) !tls13.Context {
    var ctx = try tls13.Context.init(.{ .allocator = alloc, .role = .Client }, .{});
    ctx.secrets.exporter_master.store(.Application, hash, ks.Secret.fromSlice(hash, secret));
    return ctx;
}

test "exporter: SHA-256 matches an independent RFC 8446 §7.5 computation" {
    const alloc = testing.allocator;
    const secret = [_]u8{0x5a} ** 32;
    var ctx = try contextWithExporterMaster(alloc, .sha256, &secret);
    defer ctx.deinit();

    // Output shorter than, equal to and longer than the hash length.
    inline for (.{ 16, 32, 80 }) |len| {
        var got: [len]u8 = undefined;
        var want: [len]u8 = undefined;
        try ctx.exportKeyingMaterial("EXPORTER-test", "some context", &got);
        refExporter(Sha256, HkdfSha256, &secret, "EXPORTER-test", "some context", &want);
        try testing.expectEqualSlices(u8, &want, &got);

        // exportSecret is the empty-context form (RFC 8446 §7.5: no context
        // and an empty context give the same value in TLS 1.3).
        try ctx.exportSecret("EXPORTER-test", &got);
        refExporter(Sha256, HkdfSha256, &secret, "EXPORTER-test", "", &want);
        try testing.expectEqualSlices(u8, &want, &got);
    }
}

test "exporter: SHA-384 matches an independent RFC 8446 §7.5 computation" {
    const alloc = testing.allocator;
    const secret = [_]u8{0xa5} ** 48;
    var ctx = try contextWithExporterMaster(alloc, .sha384, &secret);
    defer ctx.deinit();

    var got: [64]u8 = undefined;
    var want: [64]u8 = undefined;
    try ctx.exportKeyingMaterial("EXPORTER-Channel-Binding", "", &got);
    refExporter(Sha384, HkdfSha384, &secret, "EXPORTER-Channel-Binding", "", &want);
    try testing.expectEqualSlices(u8, &want, &got);
}

test "exporter: label and context separate the outputs; oversized requests are refused" {
    const alloc = testing.allocator;
    const secret = [_]u8{0x11} ** 32;
    var ctx = try contextWithExporterMaster(alloc, .sha256, &secret);
    defer ctx.deinit();

    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    var c: [32]u8 = undefined;
    try ctx.exportKeyingMaterial("EXPORTER-a", "", &a);
    try ctx.exportKeyingMaterial("EXPORTER-b", "", &b);
    try ctx.exportKeyingMaterial("EXPORTER-a", "x", &c);
    try testing.expect(!std.mem.eql(u8, &a, &b));
    try testing.expect(!std.mem.eql(u8, &a, &c));

    // HKDF-Expand yields at most 255 * Hash.length bytes.
    const too_long = try alloc.alloc(u8, 255 * 32 + 1);
    defer alloc.free(too_long);
    try testing.expectError(error.ExporterLengthTooLarge, ctx.exportKeyingMaterial("EXPORTER-a", "", too_long));
}

test "exporter: refused before the handshake has produced the exporter master secret" {
    var ctx = try tls13.Context.init(.{ .allocator = testing.allocator, .role = .Client }, .{});
    defer ctx.deinit();
    var out: [32]u8 = undefined;
    try testing.expectError(error.UnexpectedMessage, ctx.exportKeyingMaterial("EXPORTER-a", "", &out));
    try testing.expectError(error.UnexpectedMessage, ctx.exportSecret("EXPORTER-a", &out));
}

const Trust = struct {
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

fn expectPeersAgree(client: *tls13.Context, server: *tls13.Context) !void {
    try testing.expect(client.phase == .application_ready);
    try testing.expect(client.secrets.exporter_master.valid and server.secrets.exporter_master.valid);

    var c_out: [48]u8 = undefined;
    var s_out: [48]u8 = undefined;
    try client.exportSecret("EXPORTER-geode-test", &c_out);
    try server.exportSecret("EXPORTER-geode-test", &s_out);
    try testing.expectEqualSlices(u8, &c_out, &s_out);

    try client.exportKeyingMaterial("EXPORTER-geode-test", "ctx", &c_out);
    try server.exportKeyingMaterial("EXPORTER-geode-test", "ctx", &s_out);
    try testing.expectEqualSlices(u8, &c_out, &s_out);

    // And it is the RFC value over the connection's exporter master secret.
    var want: [48]u8 = undefined;
    refExporter(Sha256, HkdfSha256, client.secrets.exporter_master.slice(), "EXPORTER-geode-test", "ctx", &want);
    try testing.expectEqualSlices(u8, &want, &c_out);
}

fn handshakePair(alloc: std.mem.Allocator, mtls: bool) !void {
    const cert_der = @embedFile("test_certs/ed25519_cert.der");
    const key_der = @embedFile("test_certs/ed25519_key.der");
    var anchor = try x509.parseCert(alloc, cert_der);
    defer anchor.deinit(alloc);
    Trust.anchor_spki = anchor.spki;
    x509.setTrustStore(.{ .isTrustedSpki = Trust.isTrusted });
    defer x509.setTrustStore(null);

    var server = try tls13.Context.init(.{
        .allocator = alloc,
        .role = .Server,
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .server_cert_der = cert_der,
        .server_key_der = key_der,
        .request_client_cert = mtls,
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
        .client_cert_der = if (mtls) cert_der else null,
        .client_key_der = if (mtls) key_der else null,
        .quic_transport_parameters = &[_]u8{},
    }, .{});
    defer client.deinit();

    try loopback(alloc, &client, &server);
    try expectPeersAgree(&client, &server);
}

test "exporter: client and server of one handshake export the same value" {
    // Standalone X25519 loopback handshake; not FIPS-approved, skip under fips.
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    try handshakePair(testing.allocator, false);
}

test "exporter: client and server agree with client authentication (mTLS)" {
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    try handshakePair(testing.allocator, true);
}
