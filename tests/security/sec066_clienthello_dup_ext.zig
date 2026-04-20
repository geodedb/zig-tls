// SPDX-License-Identifier: Apache-2.0
//! SEC-066 regression: parseClientHello must reject a ClientHello that
//! contains the same extension type twice with error.DecodeError, and must
//! not leak allocations from the first copy (RFC 8446 §4.2).

const std = @import("std");
const tls13_full = @import("tls13_full");

/// Wire helper: write big-endian u16.
fn writeU16(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, v: u16) !void {
    try buf.append(alloc, @intCast((v >> 8) & 0xff));
    try buf.append(alloc, @intCast(v & 0xff));
}

/// Build a minimal ClientHello body (no handshake header) that contains the
/// given raw extension bytes. `extensions_bytes` is the concatenation of
/// `ext_type(2) + ext_len(2) + ext_data` entries.
fn buildClientHelloWithExtensions(
    alloc: std.mem.Allocator,
    extensions_bytes: []const u8,
) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(alloc);

    // legacy_version (2) = TLS 1.2 (0x0303)
    try buf.appendSlice(alloc, &.{ 0x03, 0x03 });

    // random (32 bytes)
    try buf.appendNTimes(alloc, 0xA5, 32);

    // session_id (u8 len + 0)
    try buf.append(alloc, 0x00);

    // cipher_suites (u16 len + 0x1301 (TLS_AES_128_GCM_SHA256))
    try writeU16(&buf, alloc, 2);
    try buf.appendSlice(alloc, &.{ 0x13, 0x01 });

    // compression_methods (u8 len + null)
    try buf.appendSlice(alloc, &.{ 0x01, 0x00 });

    // extensions (u16 len + data)
    try writeU16(&buf, alloc, @intCast(extensions_bytes.len));
    try buf.appendSlice(alloc, extensions_bytes);

    return try buf.toOwnedSlice(alloc);
}

/// Construct the raw bytes of a single server_name extension (RFC 6066) for
/// host "example.com".
fn sniExtension(alloc: std.mem.Allocator) ![]u8 {
    const host = "example.com";
    var ext = std.ArrayList(u8).empty;
    errdefer ext.deinit(alloc);
    // ext_type = 0x0000 (server_name)
    try ext.appendSlice(alloc, &.{ 0x00, 0x00 });
    // ext_data: server_name_list
    //   list_len(2) + name_type(1=host_name) + host_name_len(2) + host bytes
    const inner_len: u16 = 1 + 2 + @as(u16, @intCast(host.len));
    const list_len: u16 = 2 + inner_len; // list_len + entry
    try writeU16(&ext, alloc, list_len); // outer ext_data_len
    try writeU16(&ext, alloc, inner_len); // server_name_list length
    try ext.append(alloc, 0x00); // host_name type
    try writeU16(&ext, alloc, @intCast(host.len));
    try ext.appendSlice(alloc, host);
    return try ext.toOwnedSlice(alloc);
}

/// Construct the raw bytes of an ALPN extension offering a single protocol.
fn alpnExtension(alloc: std.mem.Allocator, proto: []const u8) ![]u8 {
    var ext = std.ArrayList(u8).empty;
    errdefer ext.deinit(alloc);
    // ext_type = 0x0010 (application_layer_protocol_negotiation)
    try ext.appendSlice(alloc, &.{ 0x00, 0x10 });
    // ext_data = list_len(2) + proto_len(1) + proto bytes
    const inner_len: u16 = 1 + @as(u16, @intCast(proto.len));
    try writeU16(&ext, alloc, 2 + inner_len); // outer ext_data_len
    try writeU16(&ext, alloc, inner_len); // list_len
    try ext.append(alloc, @intCast(proto.len));
    try ext.appendSlice(alloc, proto);
    return try ext.toOwnedSlice(alloc);
}

/// Construct the raw bytes of a key_share extension offering a single
/// x25519 key share with dummy public bytes.
fn keyShareExtension(alloc: std.mem.Allocator) ![]u8 {
    var ext = std.ArrayList(u8).empty;
    errdefer ext.deinit(alloc);
    // ext_type = 0x0033 (key_share)
    try ext.appendSlice(alloc, &.{ 0x00, 0x33 });
    // ext_data = list_len(2) + entry(group(2) + key_len(2) + key(32))
    const entry_len: u16 = 2 + 2 + 32;
    const list_len: u16 = entry_len;
    try writeU16(&ext, alloc, 2 + list_len); // outer ext_data_len
    try writeU16(&ext, alloc, list_len); // entries list length
    try ext.appendSlice(alloc, &.{ 0x00, 0x1d }); // x25519 (0x001d)
    try writeU16(&ext, alloc, 32); // key_len
    try ext.appendNTimes(alloc, 0xBB, 32);
    return try ext.toOwnedSlice(alloc);
}

test "SEC-066: duplicate server_name extension is rejected with DecodeError" {
    const alloc = std.testing.allocator;
    const sni_a = try sniExtension(alloc);
    defer alloc.free(sni_a);
    const sni_b = try sniExtension(alloc);
    defer alloc.free(sni_b);

    var exts = std.ArrayList(u8).empty;
    defer exts.deinit(alloc);
    try exts.appendSlice(alloc, sni_a);
    try exts.appendSlice(alloc, sni_b);

    const body = try buildClientHelloWithExtensions(alloc, exts.items);
    defer alloc.free(body);

    const result = tls13_full.parseClientHello(alloc, body);
    try std.testing.expectError(error.DecodeError, result);
}

test "SEC-066: duplicate ALPN extension is rejected with DecodeError" {
    const alloc = std.testing.allocator;
    const a = try alpnExtension(alloc, "h3");
    defer alloc.free(a);
    const b = try alpnExtension(alloc, "h3");
    defer alloc.free(b);

    var exts = std.ArrayList(u8).empty;
    defer exts.deinit(alloc);
    try exts.appendSlice(alloc, a);
    try exts.appendSlice(alloc, b);

    const body = try buildClientHelloWithExtensions(alloc, exts.items);
    defer alloc.free(body);

    const result = tls13_full.parseClientHello(alloc, body);
    try std.testing.expectError(error.DecodeError, result);
}

test "SEC-066: duplicate key_share extension is rejected with DecodeError" {
    const alloc = std.testing.allocator;
    const a = try keyShareExtension(alloc);
    defer alloc.free(a);
    const b = try keyShareExtension(alloc);
    defer alloc.free(b);

    var exts = std.ArrayList(u8).empty;
    defer exts.deinit(alloc);
    try exts.appendSlice(alloc, a);
    try exts.appendSlice(alloc, b);

    const body = try buildClientHelloWithExtensions(alloc, exts.items);
    defer alloc.free(body);

    const result = tls13_full.parseClientHello(alloc, body);
    try std.testing.expectError(error.DecodeError, result);
}
