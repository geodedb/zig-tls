// SPDX-License-Identifier: Apache-2.0
//! SEC-088 regression: parseClientHello must enforce RFC 8446 §4.1.2 on the
//! `legacy_compression_methods` field. The vector MUST be exactly one byte
//! containing 0x00 (the null compression method); any other shape is a
//! protocol violation and MUST be rejected with a typed error
//! (`error.IllegalCompressionMethods`).
//!
//! Cases:
//!   1. `legacy_compression_methods` length == 0  -> reject
//!   2. `legacy_compression_methods` length  > 1  -> reject
//!   3. `legacy_compression_methods` length == 1 but value != 0x00 -> reject
//!   4. `legacy_compression_methods` length == 1 and value == 0x00 -> accept
//!
//! See RFC 8446 §4.1.2:
//!   "For every TLS 1.3 ClientHello, this vector MUST contain exactly
//!    one byte, set to zero, which corresponds to the 'null' compression
//!    method (RFC 3749). If a TLS 1.3 ClientHello is received with any
//!    other value in this field, the server MUST abort the handshake
//!    with an 'illegal_parameter' alert."

const std = @import("std");
const tls13_full = @import("tls13_full");

fn writeU16(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, v: u16) !void {
    try buf.append(alloc, @intCast((v >> 8) & 0xff));
    try buf.append(alloc, @intCast(v & 0xff));
}

/// Build a ClientHello body whose compression methods vector is exactly the
/// provided bytes. Caller-provided extension bytes go into the extensions
/// vector.
fn buildClientHelloWithCompression(
    alloc: std.mem.Allocator,
    compression: []const u8,
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
    // compression_methods (u8 len + raw bytes)
    try buf.append(alloc, @intCast(compression.len));
    try buf.appendSlice(alloc, compression);
    // extensions (u16 len + data)
    try writeU16(&buf, alloc, @intCast(extensions_bytes.len));
    try buf.appendSlice(alloc, extensions_bytes);

    return try buf.toOwnedSlice(alloc);
}

/// Construct a minimal `supported_versions` extension declaring TLS 1.3 so
/// that the otherwise-required extension is present in the accept case.
fn supportedVersionsExtension(alloc: std.mem.Allocator) ![]u8 {
    var ext = std.ArrayList(u8).empty;
    errdefer ext.deinit(alloc);
    // ext_type = 0x002b (supported_versions)
    try ext.appendSlice(alloc, &.{ 0x00, 0x2b });
    // ext_data: u8 list_len + entries (each 2 bytes); declare 0x0304 only.
    const inner_len: u16 = 1 + 2;
    try writeU16(&ext, alloc, inner_len);
    try ext.append(alloc, 0x02); // list length in bytes
    try ext.appendSlice(alloc, &.{ 0x03, 0x04 });
    return try ext.toOwnedSlice(alloc);
}

test "SEC-088: empty compression_methods rejected" {
    const alloc = std.testing.allocator;
    const sv = try supportedVersionsExtension(alloc);
    defer alloc.free(sv);
    const body = try buildClientHelloWithCompression(alloc, &.{}, sv);
    defer alloc.free(body);

    const result = tls13_full.parseClientHello(alloc, body);
    try std.testing.expectError(error.IllegalCompressionMethods, result);
}

test "SEC-088: compression_methods length > 1 rejected" {
    const alloc = std.testing.allocator;
    const sv = try supportedVersionsExtension(alloc);
    defer alloc.free(sv);
    const body = try buildClientHelloWithCompression(alloc, &.{ 0x00, 0x01 }, sv);
    defer alloc.free(body);

    const result = tls13_full.parseClientHello(alloc, body);
    try std.testing.expectError(error.IllegalCompressionMethods, result);
}

test "SEC-088: compression_methods length == 1 with non-null byte rejected" {
    const alloc = std.testing.allocator;
    const sv = try supportedVersionsExtension(alloc);
    defer alloc.free(sv);
    const body = try buildClientHelloWithCompression(alloc, &.{0x01}, sv);
    defer alloc.free(body);

    const result = tls13_full.parseClientHello(alloc, body);
    try std.testing.expectError(error.IllegalCompressionMethods, result);
}

test "SEC-088: compression_methods == [0x00] accepted" {
    const alloc = std.testing.allocator;
    const sv = try supportedVersionsExtension(alloc);
    defer alloc.free(sv);
    const body = try buildClientHelloWithCompression(alloc, &.{0x00}, sv);
    defer alloc.free(body);

    const ch = try tls13_full.parseClientHello(alloc, body);
    defer {
        if (ch.cipher_suites.len > 0) alloc.free(ch.cipher_suites);
        if (ch.supported_groups) |sg| alloc.free(sg);
        if (ch.signature_algorithms) |sa| alloc.free(sa);
        if (ch.alpn_list) |al| alloc.free(al);
        if (ch.pre_shared_key) |psk| {
            alloc.free(psk.identities);
            alloc.free(psk.binders);
        }
    }

    try std.testing.expectEqual(@as(usize, 1), ch.compression_methods.len);
    try std.testing.expectEqual(@as(u8, 0x00), ch.compression_methods[0]);
}
