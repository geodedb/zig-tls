// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! observability.zig -- single-file otel seam for tls.
//!
//! When `build_options.with_otel == false`, every public function in this
//! file collapses to a comptime-known no-op so the optimizer eliminates
//! the call site entirely. When true, calls forward to the appropriate
//! `otel.api.trace` / `otel.instrumentation.http` helper.
//!
//! INVARIANT: every emit is `catch {}`-discarded. A failing exporter
//! never reaches the caller -- telemetry must never break a TLS handshake.
//!
//! NOTE: deviation from template -- TLS handshakes don't fit the HTTP
//! `instrumentation.http.startClientSpan` shape (HTTP method/url is
//! lossy for TLS). We keep the generic `startClientSpan` /
//! `startServerSpan` helpers for symmetry with grpc-zig (and to keep the
//! seam template-compatible), AND a TLS-specific
//! `startHandshakeSpan(role)` helper that constructs a span via
//! `otel.api.trace.Tracer.startSpan` directly with a TLS-shaped span
//! name (`"TLS handshake"`) and the
//! `tls.protocol.version` / `tls.cipher_suite` semantic conventions.

const std = @import("std");
// 2026-05-02: hardcoded enabled=false and removed the build_options
// import + the conditional otel import. The previous pattern surfaced
// a Zig 0.16 module-dedup quirk when the lib was reached through
// multiple paths in a downstream build graph (geode), producing
// "build_options" vs "build_options0" diamonds at this file. The
// seam is preserved as a permanent no-op for forward-compat;
// restore the conditional once the upstream Zig dedup issue is
// resolved.
pub const enabled: bool = false;

const otel = struct {};

/// Opaque handle for an in-flight operation. When disabled, this is a
/// zero-sized struct the optimizer drops entirely. The no-op fallback's
/// `end` signature MUST match `otel.api.trace.Span.end(?u64) void` so
/// callers can write `span.end(null)` regardless of `enabled` state.
pub const Span = if (enabled) otel.api.trace.Span else struct {
    pub fn end(self: @This(), _: ?u64) void {
        _ = self;
    }
};

/// TLS handshake role; carried into the span as `tls.role` and used to
/// pick `.client` vs `.server` SpanKind.
pub const Role = enum { client, server };

/// Helper: reads either a `[]const u8` field OR a function-typed field
/// returning `[]const u8`, so the seam accepts both shapes -- the closure
/// shape the recipe template ships AND the plain-string-field shape used
/// at hot-path call sites.
inline fn accessOr(req: anytype, comptime field: []const u8) []const u8 {
    const T = @TypeOf(@field(req, field));
    return switch (@typeInfo(T)) {
        .pointer => @field(req, field),
        .@"fn" => @field(req, field)(),
        else => @compileError("observability: unsupported field type for " ++ field),
    };
}

/// Start a span for a generic outbound operation. Kept for template
/// symmetry; tls hot paths use `startHandshakeSpan` instead.
pub fn startClientSpan(req: anytype) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    const span = otel.instrumentation.http.startClientSpan(
        tracer.*,
        .empty(),
        .{
            .method = accessOr(req, "method"),
            .url = accessOr(req, "url"),
        },
    ) catch return Span{};
    return span;
}

pub fn endClientSpan(span: Span, status: u16) void {
    if (!enabled) return;
    otel.instrumentation.http.endClientSpan(span, .{ .status_code = status });
}

/// Start a span for a generic inbound operation. Kept for template
/// symmetry; tls hot paths use `startHandshakeSpan` instead.
pub fn startServerSpan(req: anytype) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    const span = otel.instrumentation.http.startServerSpan(
        tracer.*,
        .empty(),
        .{
            .method = accessOr(req, "method"),
            .route = accessOr(req, "route"),
            .url = accessOr(req, "url"),
        },
    ) catch return Span{};
    return span;
}

pub fn endServerSpan(span: Span, status: u16) void {
    if (!enabled) return;
    otel.instrumentation.http.endServerSpan(span, status);
}

/// Start a span for a TLS handshake.
///
/// Span shape:
///   - name: `"TLS handshake"`
///   - kind: `.client` for `role = .client`, `.server` for `.server`
///   - attributes:
///       * `tls.role = "client"` or `"server"`
///       * `network.protocol.name = "tls"`
///
/// `tls.protocol.version` and `tls.cipher_suite` are deliberately NOT
/// set here -- they aren't known at span start; both arrive on
/// completion via `endHandshakeSpan`.
pub fn startHandshakeSpan(role: Role) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    const span_kind: otel.api.trace.SpanKind = switch (role) {
        .client => .client,
        .server => .server,
    };
    const span = tracer.startSpan(.empty(), "TLS handshake", .{ .kind = span_kind }) catch return Span{};
    span.setStringAttribute("tls.role", @tagName(role)) catch {};
    span.setStringAttribute("network.protocol.name", "tls") catch {};
    return span;
}

/// Close a TLS handshake span, recording success/failure plus negotiated
/// protocol version and cipher suite when known.
///
/// On `ok = true` we set status `.ok`; on `ok = false` we set status
/// `.error_` (no description). The `version` and `suite` slices are
/// best-effort: pass empty strings when not yet negotiated (e.g. when
/// the handshake aborted before ServerHello). The seam attaches them as
/// `tls.protocol.version` and `tls.cipher_suite` semantic-convention
/// attributes only when non-empty.
pub fn endHandshakeSpan(span: Span, ok: bool, version: []const u8, suite: []const u8) void {
    if (!enabled) return;
    if (version.len > 0) {
        span.setStringAttribute("tls.protocol.version", version) catch {};
    }
    if (suite.len > 0) {
        span.setStringAttribute("tls.cipher_suite", suite) catch {};
    }
    if (ok) {
        span.setStatus(.ok, "");
    } else {
        // `StatusCode` uses `@"error"` (escaped keyword) for the
        // failure variant -- see otel/src/api/trace.zig.
        span.setStatus(.@"error", "");
    }
    span.end(null);
}

/// Set once at process start by `observability_init.Otel.installGlobals`.
/// Only referenced when `enabled == true`; otherwise the optimizer drops
/// the whole struct.
pub const global = if (enabled) struct {
    pub var tracer: ?*otel.api.trace.Tracer = null;
    pub var meter: ?*otel.api.metrics.Meter = null;
} else struct {};
