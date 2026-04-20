// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! QUAL-339: Table-driven extension dispatch for ClientHello parse/build.
//!
//! Each entry in `HANDLERS` binds an `ExtensionType` to a (parse, build)
//! function pair. The outer loop in `parseClientHello` / `buildClientHello`
//! iterates this table once; per-extension concerns live in the handler
//! functions.
//!
//! ## Security invariants preserved at OUTER (non-handler) scope
//!
//! - **SEC-054 errdefer**: cleanup of partially-allocated extension slices
//!   happens at the outer parse loop. Handlers only populate fields on
//!   `ctx.ch`; on error they propagate `!void` and the outer `errdefer`
//!   block performs the cleanup. Handler functions MUST NOT introduce
//!   their own `errdefer` blocks that could double-free.
//!
//! - **SEC-057 enum guard**: `std.enums.fromInt` rejects peer-chosen
//!   extension tags before the outer dispatch. Any in-handler decoding of
//!   nested enum tags (e.g. `SignatureScheme`, `NamedGroup`) MUST use the
//!   same `std.enums.fromInt(E, raw) orelse ...` pattern — never
//!   `@enumFromInt`, which panics on out-of-range discriminants.
//!
//! - **CWE-345 `psk_seen` ordering**: `pre_shared_key` MUST be the last
//!   extension in a ClientHello. The outer parse loop owns the `psk_seen`
//!   sentinel, checks it before dispatching any non-PSK handler, and
//!   assigns it immediately after `pre_shared_key` parses successfully.
//!   Handlers never read or write `psk_seen`.
//!
//! - **Build-side ordering**: `pre_shared_key` MUST be the LAST entry in
//!   the `HANDLERS` table so that `buildClientHello`'s ordered iteration
//!   emits it last on the wire.

const std = @import("std");
const client_hello = @import("client_hello.zig");
const core_types = @import("core_types.zig");
const helpers = @import("helpers.zig");

pub const ExtensionType = core_types.ExtensionType;
pub const ClientHello = client_hello.ClientHello;
pub const ClientHelloParams = client_hello.ClientHelloParams;
pub const KeyShareEntry = client_hello.KeyShareEntry;
pub const PreSharedKey = client_hello.PreSharedKey;
pub const PskIdentity = client_hello.PskIdentity;

/// State threaded through each per-extension parser.
///
/// The outer loop owns `ch` and `alloc`. Handlers only populate fields on
/// `ctx.ch` and never own or free anything on error — the outer-loop
/// `errdefer` (SEC-054) handles cleanup.
pub const ParseCtx = struct {
    ch: *ClientHello,
    alloc: std.mem.Allocator,
};

/// State threaded through each per-extension builder.
///
/// `params` carries the source of truth for which extensions to emit; the
/// build handler consults the corresponding field (e.g. `params.alpn_protocols`)
/// and silently skips emission when the field is null/empty.
///
/// `psk_binder_offset`, `psk_binder_len`, `psk_binders_tail_len` are populated
/// in place by the `pre_shared_key` build handler so the outer loop can
/// propagate the binder metadata into `ClientHelloResult` without the handler
/// needing to return a tuple.
pub const BuildCtx = struct {
    params: *const ClientHelloParams,
    psk_binder_offset: ?usize = null,
    psk_binder_len: u8 = 0,
    psk_binders_tail_len: usize = 0,
};

/// One row in the table-driven dispatch.
pub const ExtHandler = struct {
    tag: ExtensionType,
    /// Parse the body of one extension (extension-data bytes, already
    /// length-bounded by the outer loop). Handlers MUST NOT own cleanup
    /// responsibility on error — propagate via `!void` and let the outer
    /// loop's errdefer handle it.
    parse: *const fn (ctx: *ParseCtx, data: []const u8) anyerror!void,
    /// Append this extension's wire-format bytes (including its 4-byte
    /// header: u16 tag + u16 length) to `out`. Skip emission entirely if
    /// the extension is not present in `ctx.params`.
    build: *const fn (ctx: *BuildCtx, out: *std.ArrayList(u8), alloc: std.mem.Allocator) anyerror!void,
};

// ============================================================================
// server_name (RFC 6066 §3) — SNI hostname
// ============================================================================

fn parseServerName(ctx: *ParseCtx, data: []const u8) anyerror!void {
    if (data.len >= 5) {
        const list_len = helpers.readU16(data[0..2]);
        if (list_len > 0 and data.len >= 5) {
            const name_type = data[2];
            if (name_type == 0) { // host_name
                const name_len = helpers.readU16(data[3..5]);
                if (5 + name_len <= data.len) {
                    ctx.ch.server_name = data[5 .. 5 + name_len];
                }
            }
        }
    }
}

fn buildServerName(ctx: *BuildCtx, out: *std.ArrayList(u8), alloc: std.mem.Allocator) anyerror!void {
    // The current buildClientHello does NOT emit server_name (the extension is
    // managed by higher layers via Params only when a concrete hostname is
    // supplied). Preserve that behavior: skip entirely. Keeping the handler
    // slot so the table structure is uniform.
    _ = ctx;
    _ = out;
    _ = alloc;
}

// ============================================================================
// supported_groups (RFC 8446 §4.2.7) — Named groups for ECDHE/FFDHE
// ============================================================================

fn parseSupportedGroups(ctx: *ParseCtx, data: []const u8) anyerror!void {
    if (data.len >= 2) {
        const groups_len = helpers.readU16(data[0..2]);
        if (2 + groups_len <= data.len) {
            var groups = try std.ArrayList(core_types.NamedGroup).initCapacity(ctx.alloc, 4);
            defer groups.deinit(ctx.alloc);

            var g_pos: usize = 2;
            while (g_pos + 2 <= 2 + groups_len) : (g_pos += 2) {
                const group = helpers.readU16(data[g_pos .. g_pos + 2]);
                if (group == 0x001d) { // x25519
                    try groups.append(ctx.alloc, .x25519);
                }
            }

            if (groups.items.len > 0) {
                ctx.ch.supported_groups = try groups.toOwnedSlice(ctx.alloc);
            }
        }
    }
}

fn buildSupportedGroups(ctx: *BuildCtx, out: *std.ArrayList(u8), alloc: std.mem.Allocator) anyerror!void {
    const params = ctx.params;
    if (params.supported_groups.len == 0) return;

    const group_list_len: u16 = @intCast(params.supported_groups.len * 2);
    const group_ext_len: u16 = group_list_len + 2;
    try out.appendSlice(alloc, &.{
        0x00,
        0x0a,
        @intCast(group_ext_len >> 8),
        @intCast(group_ext_len & 0xff),
        @intCast(group_list_len >> 8),
        @intCast(group_list_len & 0xff),
    });
    for (params.supported_groups) |group| {
        const gval: u16 = @intFromEnum(group);
        try out.appendSlice(alloc, &.{ @intCast(gval >> 8), @intCast(gval & 0xff) });
    }
}

// ============================================================================
// signature_algorithms (RFC 8446 §4.2.3)
// ============================================================================

fn parseSignatureAlgorithms(ctx: *ParseCtx, data: []const u8) anyerror!void {
    if (data.len >= 2) {
        const algs_len = helpers.readU16(data[0..2]);
        if (2 + algs_len <= data.len) {
            var algs = try std.ArrayList(core_types.SignatureScheme).initCapacity(ctx.alloc, 8);
            defer algs.deinit(ctx.alloc);

            var a_pos: usize = 2;
            while (a_pos + 2 <= 2 + algs_len) : (a_pos += 2) {
                const alg = helpers.readU16(data[a_pos .. a_pos + 2]);
                // SEC-057: Only accept values that are actual enum tags.
                // The prior 0x0401..0x080b range check admitted ~2034 values
                // not in the exhaustive SignatureScheme enum, causing
                // @enumFromInt to panic on malicious input.
                if (std.enums.fromInt(core_types.SignatureScheme, alg)) |scheme| {
                    try algs.append(ctx.alloc, scheme);
                }
            }

            if (algs.items.len > 0) {
                ctx.ch.signature_algorithms = try algs.toOwnedSlice(ctx.alloc);
            }
        }
    }
}

fn buildSignatureAlgorithms(ctx: *BuildCtx, out: *std.ArrayList(u8), alloc: std.mem.Allocator) anyerror!void {
    const params = ctx.params;
    if (params.signature_algorithms.len == 0) return;

    const list_len: u16 = @intCast(params.signature_algorithms.len * 2);
    const ext_len: u16 = list_len + 2;
    try out.appendSlice(alloc, &.{
        0x00,
        0x0d,
        @intCast(ext_len >> 8),
        @intCast(ext_len & 0xff),
        @intCast(list_len >> 8),
        @intCast(list_len & 0xff),
    });
    for (params.signature_algorithms) |scheme| {
        const val: u16 = @intFromEnum(scheme);
        try out.appendSlice(alloc, &.{ @intCast(val >> 8), @intCast(val & 0xff) });
    }
}

// ============================================================================
// key_share (RFC 8446 §4.2.8) — ECDHE public key
// ============================================================================

fn parseKeyShare(ctx: *ParseCtx, data: []const u8) anyerror!void {
    if (data.len >= 2) {
        const shares_len = helpers.readU16(data[0..2]);
        if (2 + shares_len <= data.len) {
            var ks_pos: usize = 2;
            while (ks_pos + 4 <= 2 + shares_len) {
                const group = helpers.readU16(data[ks_pos .. ks_pos + 2]);
                const key_len = helpers.readU16(data[ks_pos + 2 .. ks_pos + 4]);
                ks_pos += 4;

                if (ks_pos + key_len <= 2 + shares_len) {
                    // We only support X25519
                    if (group == 0x001d and key_len == 32) {
                        ctx.ch.key_share = KeyShareEntry{
                            .group = .x25519,
                            .key_exchange = data[ks_pos .. ks_pos + key_len],
                        };
                        break;
                    }
                    ks_pos += key_len;
                } else {
                    break;
                }
            }
        }
    }
}

fn buildKeyShare(ctx: *BuildCtx, out: *std.ArrayList(u8), alloc: std.mem.Allocator) anyerror!void {
    const params = ctx.params;
    const group_val: u16 = @intFromEnum(params.key_share_group);
    const key_share_entry_len: u16 = 2 + 2 + 32; // group(2) + key_len(2) + key(32)
    const key_share_ext_len: u16 = key_share_entry_len + 2; // entries_list_len(2) + entry
    try out.appendSlice(alloc, &.{
        0x00,
        0x33,
        @intCast(key_share_ext_len >> 8),
        @intCast(key_share_ext_len & 0xff),
        @intCast(key_share_entry_len >> 8),
        @intCast(key_share_entry_len & 0xff),
        @intCast(group_val >> 8),
        @intCast(group_val & 0xff),
        0x00,
        32,
    });
    try out.appendSlice(alloc, &params.client_pub);
}

// ============================================================================
// cookie (RFC 8446 §4.2.2) — HelloRetryRequest cookie echo
// ============================================================================

fn parseCookie(ctx: *ParseCtx, data: []const u8) anyerror!void {
    // The current parser silently ignores cookie in ClientHello (falls
    // through the switch's `else` arm); the ClientHello struct has no
    // `cookie` field today. Preserve literal behavior.
    _ = ctx;
    _ = data;
}

fn buildCookie(ctx: *BuildCtx, out: *std.ArrayList(u8), alloc: std.mem.Allocator) anyerror!void {
    const params = ctx.params;
    const ck = params.cookie orelse return;
    const ck_len: u16 = @intCast(ck.len);
    try out.appendSlice(alloc, &.{ 0x00, 0x2c, @intCast(ck_len >> 8), @intCast(ck_len & 0xff) });
    try out.appendSlice(alloc, ck);
}

// ============================================================================
// alpn (RFC 7301) — Application-Layer Protocol Negotiation
// ============================================================================

fn parseAlpn(ctx: *ParseCtx, data: []const u8) anyerror!void {
    if (data.len >= 2) {
        const list_len = helpers.readU16(data[0..2]);
        if (2 + list_len <= data.len) {
            var alpn_list = try std.ArrayList([]const u8).initCapacity(ctx.alloc, 4);
            defer alpn_list.deinit(ctx.alloc);

            var a_pos: usize = 2;
            while (a_pos < 2 + list_len) {
                if (a_pos >= data.len) break;
                const proto_len = data[a_pos];
                a_pos += 1;
                if (a_pos + proto_len <= data.len) {
                    try alpn_list.append(ctx.alloc, data[a_pos .. a_pos + proto_len]);
                    a_pos += proto_len;
                } else {
                    break;
                }
            }

            if (alpn_list.items.len > 0) {
                ctx.ch.alpn_list = try alpn_list.toOwnedSlice(ctx.alloc);
            }
        }
    }
}

fn buildAlpn(ctx: *BuildCtx, out: *std.ArrayList(u8), alloc: std.mem.Allocator) anyerror!void {
    const params = ctx.params;
    const alpn_list = params.alpn_protocols orelse return;
    if (alpn_list.len == 0) return;

    var names_len: usize = 0;
    for (alpn_list) |p| names_len += 1 + p.len;
    const list_len: u16 = @intCast(names_len);
    const ext_len: u16 = list_len + 2;
    try out.appendSlice(alloc, &.{
        0x00,
        0x10,
        @intCast(ext_len >> 8),
        @intCast(ext_len & 0xff),
        @intCast(list_len >> 8),
        @intCast(list_len & 0xff),
    });
    for (alpn_list) |p| {
        try out.append(alloc, @intCast(p.len));
        try out.appendSlice(alloc, p);
    }
}

// ============================================================================
// quic_transport_parameters (RFC 9001 §8.2)
// ============================================================================

fn parseQuicTransportParameters(ctx: *ParseCtx, data: []const u8) anyerror!void {
    ctx.ch.quic_transport_parameters = data;
}

fn buildQuicTransportParameters(ctx: *BuildCtx, out: *std.ArrayList(u8), alloc: std.mem.Allocator) anyerror!void {
    const params = ctx.params;
    const tp = params.quic_transport_parameters orelse return;
    const tp_len: u16 = @intCast(tp.len);
    try out.appendSlice(alloc, &.{ 0x00, 0x39, @intCast(tp_len >> 8), @intCast(tp_len & 0xff) });
    try out.appendSlice(alloc, tp);
}

// ============================================================================
// early_data (RFC 8446 §4.2.10) — 0-RTT indication
// ============================================================================

fn parseEarlyData(ctx: *ParseCtx, data: []const u8) anyerror!void {
    _ = data;
    ctx.ch.early_data = true;
}

fn buildEarlyData(ctx: *BuildCtx, out: *std.ArrayList(u8), alloc: std.mem.Allocator) anyerror!void {
    const params = ctx.params;
    if (!params.include_early_data) return;
    try out.appendSlice(alloc, &.{ 0x00, 0x2a, 0x00, 0x00 });
}

// ============================================================================
// psk_key_exchange_modes (RFC 8446 §4.2.9)
// ============================================================================

fn parsePskKeyExchangeModes(ctx: *ParseCtx, data: []const u8) anyerror!void {
    ctx.ch.psk_key_exchange_modes = data;
}

fn buildPskKeyExchangeModes(ctx: *BuildCtx, out: *std.ArrayList(u8), alloc: std.mem.Allocator) anyerror!void {
    const params = ctx.params;
    if (!params.include_psk) return;
    // Current buildClientHello emits psk_dhe_ke(1) literal. Preserve
    // byte-identical output.
    try out.appendSlice(alloc, &.{ 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01 });
}

// ============================================================================
// pre_shared_key (RFC 8446 §4.2.11) — MUST be LAST in HANDLERS (CWE-345)
// ============================================================================

fn parsePreSharedKey(ctx: *ParseCtx, data: []const u8) anyerror!void {
    if (data.len < 2) return error.TooShort;
    const identities_len = helpers.readU16(data[0..2]);
    if (identities_len + 2 > data.len) return error.TooShort;

    var identities = try std.ArrayList(PskIdentity).initCapacity(ctx.alloc, 2);
    defer identities.deinit(ctx.alloc);

    var id_pos: usize = 2;
    const identities_end = 2 + identities_len;
    while (id_pos < identities_end) {
        if (id_pos + 2 > identities_end) return error.TooShort;
        const identity_len = helpers.readU16(data[id_pos .. id_pos + 2]);
        id_pos += 2;
        if (id_pos + identity_len > identities_end) return error.TooShort;
        const identity_bytes = data[id_pos .. id_pos + identity_len];
        id_pos += identity_len;
        if (id_pos + 4 > identities_end) return error.TooShort;
        const ticket_age = helpers.readU32(data[id_pos .. id_pos + 4]);
        id_pos += 4;
        try identities.append(ctx.alloc, .{
            .identity = identity_bytes,
            .obfuscated_ticket_age = ticket_age,
        });
    }
    if (id_pos != identities_end) return error.TooShort;

    if (id_pos + 2 > data.len) return error.TooShort;
    const binders_len = helpers.readU16(data[id_pos .. id_pos + 2]);
    id_pos += 2;
    if (id_pos + binders_len > data.len) return error.TooShort;

    var binders = try std.ArrayList([]const u8).initCapacity(ctx.alloc, 2);
    defer binders.deinit(ctx.alloc);

    var binder_pos: usize = 0;
    while (binder_pos < binders_len) {
        if (binder_pos >= binders_len) return error.TooShort;
        const binder_len = data[id_pos + binder_pos];
        binder_pos += 1;
        if (binder_pos + binder_len > binders_len) return error.TooShort;
        const binder_slice = data[id_pos + binder_pos .. id_pos + binder_pos + binder_len];
        binder_pos += binder_len;
        try binders.append(ctx.alloc, binder_slice);
    }
    if (binder_pos != binders_len) return error.TooShort;

    ctx.ch.pre_shared_key = PreSharedKey{
        .identities = try identities.toOwnedSlice(ctx.alloc),
        .binders = try binders.toOwnedSlice(ctx.alloc),
    };
    // NOTE: the outer parse loop sets `psk_seen = true` immediately after
    // dispatch returns when `tag == .pre_shared_key` (CWE-345 sentinel stays
    // at outer scope; handlers never touch it).
}

fn buildPreSharedKey(ctx: *BuildCtx, out: *std.ArrayList(u8), alloc: std.mem.Allocator) anyerror!void {
    const params = ctx.params;
    if (!params.include_psk) return;

    const identity = params.psk_identity orelse return error.MissingPskIdentity;
    const binder_len = params.psk_binder_len;
    if (binder_len == 0) return error.InvalidBinderLength;

    // pre_shared_key extension type
    try out.appendSlice(alloc, &.{ 0x00, 0x29 });

    const ext_data_start = out.items.len + 2; // after ext length field
    try out.appendSlice(alloc, &.{ 0x00, 0x00 }); // placeholder for ext length

    // Identities list: list_len(2) + identity_len(2) + identity + ticket_age(4)
    const identity_len: u16 = @intCast(identity.len);
    const identities_list_len: u16 = 2 + identity_len + 4;
    try out.appendSlice(alloc, &.{ @intCast(identities_list_len >> 8), @intCast(identities_list_len & 0xff) });
    try out.appendSlice(alloc, &.{ @intCast(identity_len >> 8), @intCast(identity_len & 0xff) });
    try out.appendSlice(alloc, identity);

    const ticket_age = params.psk_ticket_age;
    try out.appendSlice(alloc, &.{
        @intCast((ticket_age >> 24) & 0xff),
        @intCast((ticket_age >> 16) & 0xff),
        @intCast((ticket_age >> 8) & 0xff),
        @intCast(ticket_age & 0xff),
    });

    // Binders list: list_len(2) + binder_entry_len(1) + binder_data(binder_len)
    const binders_list_len: u16 = 1 + @as(u16, binder_len);
    try out.appendSlice(alloc, &.{ @intCast(binders_list_len >> 8), @intCast(binders_list_len & 0xff) });
    try out.append(alloc, binder_len);

    // Record binder placeholder position
    const binder_offset = out.items.len;

    // Write zero placeholder for binder
    const zeros = [_]u8{0} ** 64; // max digest length
    try out.appendSlice(alloc, zeros[0..binder_len]);

    // Patch PSK extension length
    const ext_data_len = out.items.len - ext_data_start;
    out.items[ext_data_start - 2] = @intCast((ext_data_len >> 8) & 0xff);
    out.items[ext_data_start - 1] = @intCast(ext_data_len & 0xff);

    // Propagate binder metadata back to the outer loop.
    ctx.psk_binder_offset = binder_offset;
    ctx.psk_binder_len = binder_len;
    ctx.psk_binders_tail_len = 2 + 1 + binder_len;
}

// ============================================================================
// supported_versions (RFC 8446 §4.2.1) — REQUIRED for TLS 1.3
// ============================================================================

fn parseSupportedVersions(ctx: *ParseCtx, data: []const u8) anyerror!void {
    // The current parser stores the raw payload slice; downstream code
    // treats the presence of the field as "client advertised TLS 1.3".
    ctx.ch.supported_versions = data;
}

fn buildSupportedVersions(ctx: *BuildCtx, out: *std.ArrayList(u8), alloc: std.mem.Allocator) anyerror!void {
    _ = ctx;
    // list_len=2 containing 0x0304 (TLS 1.3). Always emitted.
    try out.appendSlice(alloc, &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 });
}

// ============================================================================
// HANDLERS table
//
// Order constraint: `pre_shared_key` MUST appear LAST (CWE-345 build-side
// ordering per RFC 8446 §4.2.11). The outer build loop iterates this table
// in sequence and emits each extension's bytes.
// ============================================================================
pub const HANDLERS: []const ExtHandler = &.{
    // Build-order (RFC 8446 §4.2) authoritative:
    .{ .tag = .supported_versions, .parse = parseSupportedVersions, .build = buildSupportedVersions },
    .{ .tag = .supported_groups, .parse = parseSupportedGroups, .build = buildSupportedGroups },
    .{ .tag = .signature_algorithms, .parse = parseSignatureAlgorithms, .build = buildSignatureAlgorithms },
    .{ .tag = .key_share, .parse = parseKeyShare, .build = buildKeyShare },
    .{ .tag = .cookie, .parse = parseCookie, .build = buildCookie },
    .{ .tag = .alpn, .parse = parseAlpn, .build = buildAlpn },
    .{ .tag = .quic_transport_parameters, .parse = parseQuicTransportParameters, .build = buildQuicTransportParameters },
    .{ .tag = .early_data, .parse = parseEarlyData, .build = buildEarlyData },
    .{ .tag = .psk_key_exchange_modes, .parse = parsePskKeyExchangeModes, .build = buildPskKeyExchangeModes },
    // Parse-only extensions that have no build emission live at the tail
    // (before pre_shared_key). Their relative order among themselves is
    // inconsequential because their build handlers are no-ops.
    .{ .tag = .server_name, .parse = parseServerName, .build = buildServerName },
    // CWE-345 / RFC 8446 §4.2.11: pre_shared_key MUST be last on the wire
    // and in this table.
    .{ .tag = .pre_shared_key, .parse = parsePreSharedKey, .build = buildPreSharedKey },
};
