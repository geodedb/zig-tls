// SPDX-License-Identifier: Apache-2.0
//! GAP-0144 regression (= SEC-104 cross-ref): parseHelloRetryRequest must
//! reject a HelloRetryRequest body that contains two extensions of the same
//! type (RFC 8446 §4.2). Pre-fix the inner extension loop was last-wins on
//! `cookie` and `selected_group`, allowing a malicious peer to leak the
//! original cookie reference and substitute a controlled one for the CH2
//! echo. Twin of SEC-066 (ClientHello), SEC-092 (EE/SH), and SEC-079 (X.509).

const std = @import("std");
const tls13 = @import("tls13");
const tls13_full = @import("tls13_full");

fn writeU16(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, v: u16) !void {
    try buf.append(alloc, @intCast((v >> 8) & 0xff));
    try buf.append(alloc, @intCast(v & 0xff));
}

/// Encode a single HRR extension entry: ext_type(2) + ext_len(2) + ext_data.
fn encodeExt(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, etype: u16, data: []const u8) !void {
    try writeU16(buf, alloc, etype);
    try writeU16(buf, alloc, @intCast(data.len));
    try buf.appendSlice(alloc, data);
}

/// Build a minimal HelloRetryRequest body with the given pre-encoded
/// extensions blob. Uses the RFC 8446 §4.1.4 special HRR random and a
/// TLS_AES_128_GCM_SHA256 cipher_suite placeholder. Suitable for the
/// parseHelloRetryRequest dup-extension regression — the parser only walks
/// the extensions slab and does not validate the special random, so any
/// 32-byte filler suffices.
fn buildHrrBody(alloc: std.mem.Allocator, extensions_bytes: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(alloc);
    try buf.appendSlice(alloc, &.{ 0x03, 0x03 }); // legacy_version
    try buf.appendNTimes(alloc, 0xCF, 32); // random (parser is bounds-only on this slot)
    try buf.append(alloc, 0x00); // session_id len
    try buf.appendSlice(alloc, &.{ 0x13, 0x01 }); // cipher_suite
    try buf.append(alloc, 0x00); // legacy_compression_method
    try writeU16(&buf, alloc, @intCast(extensions_bytes.len));
    try buf.appendSlice(alloc, extensions_bytes);
    return try buf.toOwnedSlice(alloc);
}

test "GAP-0144: HRR with two cookie extensions is rejected" {
    const alloc = std.testing.allocator;

    // RFC 8446 §4.2.2 cookie ext_data = u16 length-prefix + cookie bytes.
    const cookie_data = [_]u8{ 0x00, 0x04, 0xCA, 0xFE, 0xF0, 0x0D };

    var exts = std.ArrayList(u8).empty;
    defer exts.deinit(alloc);
    // First, a valid key_share so the required `selected_group` is set.
    const ks_data = [_]u8{ 0x00, 0x1d }; // x25519
    try encodeExt(&exts, alloc, @intFromEnum(tls13_full.ExtensionType.key_share), &ks_data);
    try encodeExt(&exts, alloc, @intFromEnum(tls13_full.ExtensionType.cookie), &cookie_data);
    try encodeExt(&exts, alloc, @intFromEnum(tls13_full.ExtensionType.cookie), &cookie_data);

    const body = try buildHrrBody(alloc, exts.items);
    defer alloc.free(body);

    try std.testing.expectError(error.DuplicateExtension, tls13.parseHelloRetryRequest(body));
}

test "GAP-0144: HRR with two key_share extensions is rejected" {
    const alloc = std.testing.allocator;

    const ks_data = [_]u8{ 0x00, 0x1d }; // x25519

    var exts = std.ArrayList(u8).empty;
    defer exts.deinit(alloc);
    try encodeExt(&exts, alloc, @intFromEnum(tls13_full.ExtensionType.key_share), &ks_data);
    try encodeExt(&exts, alloc, @intFromEnum(tls13_full.ExtensionType.key_share), &ks_data);

    const body = try buildHrrBody(alloc, exts.items);
    defer alloc.free(body);

    try std.testing.expectError(error.DuplicateExtension, tls13.parseHelloRetryRequest(body));
}

test "GAP-0144: HRR with distinct key_share + cookie still parses" {
    const alloc = std.testing.allocator;

    const ks_data = [_]u8{ 0x00, 0x1d }; // x25519
    const cookie_data = [_]u8{ 0x00, 0x04, 0xCA, 0xFE, 0xF0, 0x0D };

    var exts = std.ArrayList(u8).empty;
    defer exts.deinit(alloc);
    try encodeExt(&exts, alloc, @intFromEnum(tls13_full.ExtensionType.key_share), &ks_data);
    try encodeExt(&exts, alloc, @intFromEnum(tls13_full.ExtensionType.cookie), &cookie_data);

    const body = try buildHrrBody(alloc, exts.items);
    defer alloc.free(body);

    const parsed = try tls13.parseHelloRetryRequest(body);
    try std.testing.expectEqual(tls13_full.NamedGroup.x25519, parsed.selected_group);
    try std.testing.expect(parsed.cookie != null);
    try std.testing.expectEqual(@as(usize, 4), parsed.cookie.?.len);
}
