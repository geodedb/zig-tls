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
pub const BuildCtx = struct {
    params: *const ClientHelloParams,
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
    // Parse-only extensions that have no build emission live at the tail
    // (before pre_shared_key). Their relative order among themselves is
    // inconsequential because their build handlers are no-ops.
    .{ .tag = .server_name, .parse = parseServerName, .build = buildServerName },
};
