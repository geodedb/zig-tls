// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Verifies one TLS handshake span lands in an in-memory recorder when
//! `-Dwith_otel=true`. Skips under the disabled build.
//!
//! NOTE: deviation from template -- we exercise the seam directly via
//! the in-memory recorder rather than driving a real TLS handshake.
//! TLS handshakes require a working peer (real socket, certificate
//! chain, etc.); the seam's behaviour is identical:
//! `startHandshakeSpan` -> `endHandshakeSpan` enters and leaves one
//! tracer span.
//!
//! The `otel` module is only added to this test root when
//! `-Dwith_otel=true`. To compile cleanly under both flag values we
//! gate the otel-namespace identifiers behind `comptime if (enabled)`
//! and stub the alias to an empty struct when the flag is off -- that
//! branch is dead code in the disabled build but the import resolves.

const std = @import("std");
const build_options = @import("build_options");
const ztls = @import("ztls");

const otel = if (build_options.with_otel) @import("otel") else struct {};

test "one TLS handshake span recorded when otel enabled" {
    if (!ztls.observability.enabled) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var resource = try otel.sdk.resource.defaultResource(allocator);
    defer resource.deinit();
    try resource.attributes.putString(otel.semconv.service_name, "tls-test");

    var recorder = otel.exporters.in_memory.Recorder.init(allocator);
    defer recorder.deinit();
    var tp = try otel.sdk.trace.TracerProvider.init(allocator, .{
        .resource = &resource,
        .default_exporter = recorder.spanExporter(),
    });
    defer tp.deinit();

    var tracer = tp.tracer(.{ .name = "tls-test" });
    ztls.observability.global.tracer = &tracer;
    defer ztls.observability.global.tracer = null;

    const span = ztls.observability.startHandshakeSpan(.client);
    ztls.observability.endHandshakeSpan(span, true, "1.3", "TLS_AES_128_GCM_SHA256");

    try tp.forceFlush(1_000);
    try std.testing.expectEqual(@as(usize, 1), recorder.spans.items.len);

    // Verify span name shape: "TLS handshake".
    const recorded = recorder.spans.items[0];
    try std.testing.expectEqualStrings("TLS handshake", recorded.name);

    // Verify the tls.protocol.version + tls.cipher_suite + tls.role
    // attributes landed on the span. The in-memory recorder stores
    // attributes as `[]KV` (string-stringified key/value pairs) -- see
    // otel/src/exporters/in_memory.zig.
    var found_version: ?[]const u8 = null;
    var found_suite: ?[]const u8 = null;
    var found_role: ?[]const u8 = null;
    for (recorded.attribute_kv) |kv| {
        if (std.mem.eql(u8, kv.key, "tls.protocol.version")) found_version = kv.value;
        if (std.mem.eql(u8, kv.key, "tls.cipher_suite")) found_suite = kv.value;
        if (std.mem.eql(u8, kv.key, "tls.role")) found_role = kv.value;
    }
    try std.testing.expectEqualStrings("1.3", found_version orelse return error.MissingTlsProtocolVersion);
    try std.testing.expectEqualStrings("TLS_AES_128_GCM_SHA256", found_suite orelse return error.MissingTlsCipherSuite);
    try std.testing.expectEqualStrings("client", found_role orelse return error.MissingTlsRole);
}
