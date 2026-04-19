// SPDX-License-Identifier: Apache-2.0
//! SEC-057 regression: ClientHello with a signature_algorithms entry in the
//! 0x0401..0x080b range but NOT in the exhaustive SignatureScheme enum must
//! NOT panic. parseClientHello must either skip the unknown value or return
//! a recoverable error. See docs/SECURITY_GAP_ANALYSIS.md SEC-057.

const std = @import("std");
const tls13_full = @import("tls13_full");

/// Mirrors the private freeParsedClientHello in src/tls13/handshake_state.zig.
/// Copied here because that helper is not re-exported from tls13_full.
fn freeParsedClientHello(allocator: std.mem.Allocator, parsed: *tls13_full.ClientHello) void {
    if (parsed.cipher_suites.len != 0) allocator.free(parsed.cipher_suites);
    if (parsed.supported_groups) |groups| {
        if (groups.len != 0) allocator.free(groups);
    }
    if (parsed.signature_algorithms) |algs| {
        if (algs.len != 0) allocator.free(algs);
    }
    if (parsed.pre_shared_key) |psk| {
        if (psk.identities.len != 0) allocator.free(psk.identities);
        if (psk.binders.len != 0) allocator.free(psk.binders);
    }
    if (parsed.alpn_list) |list| {
        if (list.len != 0) allocator.free(list);
    }
}

fn makeClientHelloWithSigAlg(alloc: std.mem.Allocator, bad_alg: u16) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(alloc);

    // ClientHello body: legacy_version (2) + random (32) + session_id (1 len + 0)
    try buf.appendSlice(alloc, &.{ 0x03, 0x03 }); // legacy_version TLS 1.2
    try buf.appendNTimes(alloc, 0xAA, 32); // random
    try buf.append(alloc, 0x00); // session_id length = 0

    // cipher_suites: length(2) + one suite (TLS_AES_128_GCM_SHA256 = 0x13 0x01)
    try buf.appendSlice(alloc, &.{ 0x00, 0x02, 0x13, 0x01 });

    // compression_methods: length(1) + null(0)
    try buf.appendSlice(alloc, &.{ 0x01, 0x00 });

    // Extensions: placeholder length patched below.
    const ext_len_pos = buf.items.len;
    try buf.appendSlice(alloc, &.{ 0x00, 0x00 });

    const ext_start = buf.items.len;

    // signature_algorithms extension (0x000d)
    try buf.appendSlice(alloc, &.{ 0x00, 0x0d }); // ext_type
    try buf.appendSlice(alloc, &.{ 0x00, 0x06 }); // ext_data_len
    try buf.appendSlice(alloc, &.{ 0x00, 0x04 }); // sigalgs list_len
    try buf.append(alloc, @intCast((bad_alg >> 8) & 0xff)); // bad alg (attacker)
    try buf.append(alloc, @intCast(bad_alg & 0xff));
    try buf.appendSlice(alloc, &.{ 0x08, 0x07 }); // ed25519 (valid)

    // supported_versions (0x002b): length(2) + one version (TLS 1.3 = 0x0304)
    try buf.appendSlice(alloc, &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 });

    // supported_groups (0x000a): length(2) + x25519 (0x001d)
    try buf.appendSlice(alloc, &.{ 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d });

    // key_share (0x0033): minimal x25519 share
    try buf.appendSlice(alloc, &.{ 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20 });
    try buf.appendNTimes(alloc, 0x01, 32); // 32-byte pub key

    const ext_end = buf.items.len;
    const ext_len: u16 = @intCast(ext_end - ext_start);
    buf.items[ext_len_pos] = @intCast((ext_len >> 8) & 0xff);
    buf.items[ext_len_pos + 1] = @intCast(ext_len & 0xff);

    return try buf.toOwnedSlice(alloc);
}

test "SEC-057: sig_alg 0x0402 must not panic" {
    const alloc = std.testing.allocator;
    const body = try makeClientHelloWithSigAlg(alloc, 0x0402);
    defer alloc.free(body);

    // parseClientHello may return an error OR succeed with the valid ed25519
    // entry. Both are acceptable. Panicking is NOT acceptable.
    var result = tls13_full.parseClientHello(alloc, body) catch return;
    defer freeParsedClientHello(alloc, &result);

    // If it succeeded, confirm the unknown alg was dropped, not retained.
    if (result.signature_algorithms) |algs| {
        for (algs) |a| {
            try std.testing.expect(@intFromEnum(a) != 0x0402);
        }
    }
}

test "SEC-057: sweep invalid sig_alg values in accepted range must not panic" {
    const alloc = std.testing.allocator;
    // Derive the valid set at comptime from the enum so this test cannot drift
    // if a new SignatureScheme variant is added to core_types.zig.
    const scheme_fields = @typeInfo(tls13_full.SignatureScheme).@"enum".fields;

    var alg: u16 = 0x0401;
    while (alg <= 0x080b) : (alg += 1) {
        var is_valid = false;
        inline for (scheme_fields) |f| {
            if (@as(u16, f.value) == alg) {
                is_valid = true;
            }
        }
        if (is_valid) continue;

        const body = try makeClientHelloWithSigAlg(alloc, alg);
        defer alloc.free(body);

        var result = tls13_full.parseClientHello(alloc, body) catch continue;
        defer freeParsedClientHello(alloc, &result);
    }
}
