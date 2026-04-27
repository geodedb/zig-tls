// SPDX-License-Identifier: Apache-2.0
//! SEC-098 regression: parseClientHello must reject a `pre_shared_key`
//! extension whose `identities` and `binders` lists have unequal cardinality
//! (RFC 8446 §4.2.11). Pre-fix the parser stored both lists independently,
//! so a downstream PSK selection that indexed binders by the chosen identity
//! index could read out of bounds.
//!
//! Reference: `src/tls13/messages/client_hello_handlers.zig:438-498`.

const std = @import("std");
const tls13_full = @import("tls13_full");

fn writeU16(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, v: u16) !void {
    try buf.append(alloc, @intCast((v >> 8) & 0xff));
    try buf.append(alloc, @intCast(v & 0xff));
}

/// Build a minimal ClientHello body that carries a single attacker-controlled
/// extensions blob. `extensions_bytes` is the concatenation of
/// `ext_type(2) + ext_len(2) + ext_data` entries.
fn buildClientHelloWithExtensions(alloc: std.mem.Allocator, extensions_bytes: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(alloc);
    try buf.appendSlice(alloc, &.{ 0x03, 0x03 }); // legacy_version
    try buf.appendNTimes(alloc, 0xA5, 32); // random
    try buf.append(alloc, 0x00); // session_id len
    try writeU16(&buf, alloc, 2); // cipher_suites len
    try buf.appendSlice(alloc, &.{ 0x13, 0x01 });
    try buf.appendSlice(alloc, &.{ 0x01, 0x00 }); // compression_methods
    try writeU16(&buf, alloc, @intCast(extensions_bytes.len));
    try buf.appendSlice(alloc, extensions_bytes);
    return try buf.toOwnedSlice(alloc);
}

/// Encode a `pre_shared_key` extension with `n_identities` PskIdentity entries
/// and `n_binders` PskBinderEntry entries. Each identity and binder uses a
/// fixed shape (4-byte identity, 32-byte binder) so the only variable is the
/// list cardinality.
fn pskExtension(alloc: std.mem.Allocator, n_identities: usize, n_binders: usize) ![]u8 {
    const id_entry_size: usize = 2 + 4 + 4; // ident_len + ident + obfuscated_ticket_age
    const binder_entry_size: usize = 1 + 32; // binder_len + binder
    const identities_inner: usize = n_identities * id_entry_size;
    const binders_inner: usize = n_binders * binder_entry_size;
    const ext_data_len: usize = 2 + identities_inner + 2 + binders_inner;

    var ext = std.ArrayList(u8).empty;
    errdefer ext.deinit(alloc);
    try ext.appendSlice(alloc, &.{ 0x00, 0x29 }); // ext_type = pre_shared_key
    try writeU16(&ext, alloc, @intCast(ext_data_len));

    try writeU16(&ext, alloc, @intCast(identities_inner));
    var i: usize = 0;
    while (i < n_identities) : (i += 1) {
        try writeU16(&ext, alloc, 4);
        try ext.appendSlice(alloc, &.{ 'i', 'd', '0', @intCast('0' + i) });
        try ext.appendSlice(alloc, &.{ 0, 0, 0, 0 }); // obfuscated_ticket_age
    }

    try writeU16(&ext, alloc, @intCast(binders_inner));
    var j: usize = 0;
    while (j < n_binders) : (j += 1) {
        try ext.append(alloc, 32);
        try ext.appendNTimes(alloc, @intCast(0xB0 + j), 32);
    }

    return try ext.toOwnedSlice(alloc);
}

test "SEC-098: PSK with 2 identities + 1 binder is rejected" {
    const alloc = std.testing.allocator;
    const psk = try pskExtension(alloc, 2, 1);
    defer alloc.free(psk);
    const body = try buildClientHelloWithExtensions(alloc, psk);
    defer alloc.free(body);
    try std.testing.expectError(error.PskBinderMismatch, tls13_full.parseClientHello(alloc, body));
}

test "SEC-098: PSK with 1 identity + 2 binders is rejected" {
    const alloc = std.testing.allocator;
    const psk = try pskExtension(alloc, 1, 2);
    defer alloc.free(psk);
    const body = try buildClientHelloWithExtensions(alloc, psk);
    defer alloc.free(body);
    try std.testing.expectError(error.PskBinderMismatch, tls13_full.parseClientHello(alloc, body));
}

test "SEC-098: PSK with matched 2/2 cardinality still parses" {
    const alloc = std.testing.allocator;
    const psk = try pskExtension(alloc, 2, 2);
    defer alloc.free(psk);
    const body = try buildClientHelloWithExtensions(alloc, psk);
    defer alloc.free(body);

    const ch = try tls13_full.parseClientHello(alloc, body);
    defer {
        if (ch.cipher_suites.len > 0) alloc.free(ch.cipher_suites);
        if (ch.supported_groups) |sg| alloc.free(sg);
        if (ch.signature_algorithms) |sa| alloc.free(sa);
        if (ch.alpn_list) |al| alloc.free(al);
        if (ch.pre_shared_key) |p| {
            alloc.free(p.identities);
            alloc.free(p.binders);
        }
    }
    const psk_parsed = ch.pre_shared_key orelse return error.TestExpectedPsk;
    try std.testing.expectEqual(@as(usize, 2), psk_parsed.identities.len);
    try std.testing.expectEqual(@as(usize, 2), psk_parsed.binders.len);
}
