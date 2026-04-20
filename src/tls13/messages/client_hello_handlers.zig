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
    .{ .tag = .supported_versions, .parse = parseSupportedVersions, .build = buildSupportedVersions },
};
