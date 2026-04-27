// SPDX-License-Identifier: Apache-2.0
//! SEC-092 (subsumes SEC-078) regression: parseEncryptedExtensions must
//! reject a duplicate extension type per RFC 8446 §4.2 ("There MUST NOT be
//! more than one extension of the same type in a given extension block.").
//!
//! Mirrors the SEC-066 EnumSet pattern from ClientHello. Uses the public
//! `parseEncryptedExtensions` API so a malformed peer message surfaces a
//! typed error to the handshake layer.

const std = @import("std");
const tls13_full = @import("tls13_full");

fn writeU16(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, v: u16) !void {
    try buf.append(alloc, @intCast((v >> 8) & 0xff));
    try buf.append(alloc, @intCast(v & 0xff));
}

/// Build the EE body (no handshake header, just `extensions<u16>` per RFC
/// 8446 §4.3.1) containing two ALPN extensions.
fn buildEeWithDuplicateAlpn(alloc: std.mem.Allocator) ![]u8 {
    var ext = std.ArrayList(u8).empty;
    defer ext.deinit(alloc);

    // ALPN extension #1 — list of one protocol "h3"
    try ext.appendSlice(alloc, &.{ 0x00, 0x10 }); // ext_type=alpn
    try writeU16(&ext, alloc, 5); // ext_data_len = list_len_field(2) + entry_len(1) + "h3"(2)
    try writeU16(&ext, alloc, 3); // list_len = 3
    try ext.append(alloc, 2); // proto_len = 2
    try ext.appendSlice(alloc, "h3");

    // ALPN extension #2 — same shape, must trigger duplicate-detection
    try ext.appendSlice(alloc, &.{ 0x00, 0x10 });
    try writeU16(&ext, alloc, 5);
    try writeU16(&ext, alloc, 3);
    try ext.append(alloc, 2);
    try ext.appendSlice(alloc, "h3");

    var body = std.ArrayList(u8).empty;
    errdefer body.deinit(alloc);
    try writeU16(&body, alloc, @intCast(ext.items.len));
    try body.appendSlice(alloc, ext.items);
    return try body.toOwnedSlice(alloc);
}

/// Build the EE body containing two QUIC transport_parameters extensions.
fn buildEeWithDuplicateQtp(alloc: std.mem.Allocator) ![]u8 {
    var ext = std.ArrayList(u8).empty;
    defer ext.deinit(alloc);

    // QTP #1 — empty payload
    try ext.appendSlice(alloc, &.{ 0x00, 0x39 }); // ext_type=quic_transport_parameters
    try writeU16(&ext, alloc, 0);

    // QTP #2 — must trigger duplicate-detection
    try ext.appendSlice(alloc, &.{ 0x00, 0x39 });
    try writeU16(&ext, alloc, 0);

    var body = std.ArrayList(u8).empty;
    errdefer body.deinit(alloc);
    try writeU16(&body, alloc, @intCast(ext.items.len));
    try body.appendSlice(alloc, ext.items);
    return try body.toOwnedSlice(alloc);
}

test "SEC-092: EE duplicate ALPN extension is rejected" {
    const alloc = std.testing.allocator;
    const body = try buildEeWithDuplicateAlpn(alloc);
    defer alloc.free(body);

    const result = tls13_full.parseEncryptedExtensions(body);
    try std.testing.expectError(error.DuplicateExtension, result);
}

test "SEC-092: EE duplicate quic_transport_parameters is rejected" {
    const alloc = std.testing.allocator;
    const body = try buildEeWithDuplicateQtp(alloc);
    defer alloc.free(body);

    const result = tls13_full.parseEncryptedExtensions(body);
    try std.testing.expectError(error.DuplicateExtension, result);
}

test "SEC-092: EE single ALPN extension is accepted" {
    const alloc = std.testing.allocator;
    var ext = std.ArrayList(u8).empty;
    defer ext.deinit(alloc);

    try ext.appendSlice(alloc, &.{ 0x00, 0x10 });
    try writeU16(&ext, alloc, 5);
    try writeU16(&ext, alloc, 3);
    try ext.append(alloc, 2);
    try ext.appendSlice(alloc, "h3");

    var body = std.ArrayList(u8).empty;
    defer body.deinit(alloc);
    try writeU16(&body, alloc, @intCast(ext.items.len));
    try body.appendSlice(alloc, ext.items);

    const ee = try tls13_full.parseEncryptedExtensions(body.items);
    try std.testing.expect(ee.alpn != null);
}
