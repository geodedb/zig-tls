// SPDX-License-Identifier: Apache-2.0
//! NEWGAP-08 / QUAL-392: HelloRetryRequest carries the same ServerHello-shaped
//! fields as a normal ServerHello (RFC 8446 §4.1.4), so the §4.1.3 field MUSTs
//! apply equally. The non-HRR path (handleServerHello) enforces them
//! (NEWGAP-06/SEC-028/SEC-088) but the HRR branch ran before those checks and
//! skipped them. This suite drives both the pure parser and the live
//! processCrypto/handleHelloRetryRequest path.

const std = @import("std");
const testing = std.testing;
const tls13 = @import("tls13");
const tls13_full = @import("tls13_full");

fn writeU16(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, v: u16) !void {
    try buf.append(alloc, @intCast((v >> 8) & 0xff));
    try buf.append(alloc, @intCast(v & 0xff));
}

/// Build a HelloRetryRequest body with explicit field values so individual
/// §4.1.3 MUSTs can be violated one at a time. `random` lets callers use the
/// real HRR sentinel (for the full processCrypto path) or arbitrary filler
/// (for direct parseHelloRetryRequest unit checks).
const HrrFields = struct {
    legacy_version: u16 = 0x0303,
    random: [32]u8 = [_]u8{0xCF} ** 32,
    session_id: []const u8 = &[_]u8{},
    cipher_suite: u16 = 0x1301,
    compression: u8 = 0x00,
    extensions: []const u8,
};

fn buildHrr(alloc: std.mem.Allocator, f: HrrFields) ![]u8 {
    var b = std.ArrayList(u8).empty;
    errdefer b.deinit(alloc);
    try writeU16(&b, alloc, f.legacy_version);
    try b.appendSlice(alloc, &f.random);
    try b.append(alloc, @intCast(f.session_id.len));
    try b.appendSlice(alloc, f.session_id);
    try writeU16(&b, alloc, f.cipher_suite);
    try b.append(alloc, f.compression);
    try writeU16(&b, alloc, @intCast(f.extensions.len));
    try b.appendSlice(alloc, f.extensions);
    return b.toOwnedSlice(alloc);
}

// A minimal valid HRR key_share extension (selected_group x25519) so the parser
// reaches MissingKeyShare-free territory; field checks fire before/around it.
const hrr_key_share = [_]u8{ 0x00, 0x33, 0x00, 0x02, 0x00, 0x1d, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };

test "NEWGAP-08: HRR with legacy_version != 0x0303 is rejected" {
    const alloc = testing.allocator;
    const body = try buildHrr(alloc, .{ .legacy_version = 0x0302, .extensions = &hrr_key_share });
    defer alloc.free(body);
    try testing.expectError(tls13.HandshakeError.IllegalLegacyVersion, tls13.parseHelloRetryRequest(body));
}

test "NEWGAP-08: HRR with non-empty legacy_session_id_echo is rejected" {
    const alloc = testing.allocator;
    const body = try buildHrr(alloc, .{ .session_id = &[_]u8{ 0x01, 0x02, 0x03 }, .extensions = &hrr_key_share });
    defer alloc.free(body);
    try testing.expectError(tls13.HandshakeError.IllegalSessionIdEcho, tls13.parseHelloRetryRequest(body));
}

test "NEWGAP-08: HRR with non-zero legacy_compression_method is rejected" {
    const alloc = testing.allocator;
    const body = try buildHrr(alloc, .{ .compression = 0x01, .extensions = &hrr_key_share });
    defer alloc.free(body);
    try testing.expectError(tls13.HandshakeError.IllegalCompressionMethods, tls13.parseHelloRetryRequest(body));
}

test "NEWGAP-08: well-formed HRR still parses" {
    const alloc = testing.allocator;
    const body = try buildHrr(alloc, .{ .extensions = &hrr_key_share });
    defer alloc.free(body);
    const parsed = try tls13.parseHelloRetryRequest(body);
    try testing.expectEqual(tls13_full.NamedGroup.x25519, parsed.selected_group);
}

fn clientCtx() !tls13.Context {
    // Standalone-X25519 client config: not FIPS-approved, so the live
    // handshake fails closed under -Dfips=true. The live-HRR tests using this
    // helper skip in FIPS mode (the byte-level HRR-field tests above do not
    // start a handshake and run in both modes).
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    const cfg = tls13.Config{
        .allocator = testing.allocator,
        .role = .Client,
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{ 0x00, 0x01 },
        .server_name = "test.example.com",
    };
    return tls13.Context.init(cfg, tls13.Callbacks{});
}

fn frameHandshake(alloc: std.mem.Allocator, hs_type: u8, body: []const u8) ![]u8 {
    var m = std.ArrayList(u8).empty;
    errdefer m.deinit(alloc);
    try m.append(alloc, hs_type);
    try m.append(alloc, @intCast((body.len >> 16) & 0xff));
    try m.append(alloc, @intCast((body.len >> 8) & 0xff));
    try m.append(alloc, @intCast(body.len & 0xff));
    try m.appendSlice(alloc, body);
    return m.toOwnedSlice(alloc);
}

test "NEWGAP-08: live HRR with un-offered cipher_suite is rejected (illegal_parameter)" {
    const alloc = testing.allocator;
    var ctx = try clientCtx();
    defer ctx.deinit();
    try ctx.startClientHandshake();

    // Real HRR sentinel random so handleServerHello routes to the HRR handler;
    // cipher_suite 0x1302 was NOT offered by the client.
    const body = try buildHrr(alloc, .{
        .random = tls13_full.HELLO_RETRY_REQUEST_RANDOM,
        .cipher_suite = 0x1302,
        .extensions = &hrr_key_share,
    });
    defer alloc.free(body);
    const msg = try frameHandshake(alloc, 0x02, body);
    defer alloc.free(msg);

    try testing.expectError(tls13.HandshakeError.IllegalCipherSuiteSelected, ctx.processCrypto(.Initial, msg));
}

test "NEWGAP-13: live HRR with no cookie + already-offered group is rejected (no change)" {
    const alloc = testing.allocator;
    var ctx = try clientCtx();
    defer ctx.deinit();
    try ctx.startClientHandshake();

    // HRR selects x25519 (the only group the client offered/key_shared) with an
    // offered cipher and NO cookie -> ClientHello2 would be identical -> the
    // RFC 8446 §4.1.4 retry-loop prohibition.
    const body = try buildHrr(alloc, .{
        .random = tls13_full.HELLO_RETRY_REQUEST_RANDOM,
        .cipher_suite = 0x1301, // offered
        .extensions = &hrr_key_share, // key_share x25519, no cookie
    });
    defer alloc.free(body);
    const msg = try frameHandshake(alloc, 0x02, body);
    defer alloc.free(msg);

    try testing.expectError(tls13.HandshakeError.HrrNoChange, ctx.processCrypto(.Initial, msg));
}
