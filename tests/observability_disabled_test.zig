// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Verifies the no-op invariant when -Dwith_otel=false (the default).
//!
//! tls publishes its public surface as the "ztls" module rooted at
//! src/lib.zig. The seam is exposed as `ztls.observability` so this test
//! can drive the disabled-mode invariants through the public root.

const std = @import("std");
const ztls = @import("ztls");

test "build_options.with_otel exists and defaults to false" {
    const build_options = @import("build_options");
    try std.testing.expect(@hasDecl(build_options, "with_otel"));
    // The "default" assertion only holds for the disabled build. When
    // the operator forces -Dwith_otel=true, this test runs against the
    // enabled module and must skip rather than misreport the default.
    if (build_options.with_otel) return error.SkipZigTest;
    try std.testing.expectEqual(false, build_options.with_otel);
}

test "observability.enabled tracks build_options.with_otel" {
    const build_options = @import("build_options");
    try std.testing.expectEqual(build_options.with_otel, ztls.observability.enabled);
}

test "client/server seams are no-ops when otel disabled" {
    if (ztls.observability.enabled) return error.SkipZigTest;
    var span = ztls.observability.startClientSpan(.{
        .method = "GET",
        .url = "https://example.test/",
    });
    ztls.observability.endClientSpan(span, 200);
    // Belt-and-suspenders: the seam's `endClientSpan` already covers
    // the lifecycle; this line just verifies the no-op fallback's
    // signature matches the real API's `Span.end(?u64) void`.
    span.end(null);

    var sspan = ztls.observability.startServerSpan(.{
        .method = "GET",
        .route = "/",
        .url = "/",
    });
    ztls.observability.endServerSpan(sspan, 200);
    sspan.end(null);
}

test "TLS handshake span helpers are no-ops when otel disabled" {
    if (ztls.observability.enabled) return error.SkipZigTest;
    var client_span = ztls.observability.startHandshakeSpan(.client);
    ztls.observability.endHandshakeSpan(client_span, true, "1.3", "TLS_AES_128_GCM_SHA256");
    client_span.end(null);

    var server_span = ztls.observability.startHandshakeSpan(.server);
    // Failure path: empty version/suite (handshake aborted before
    // negotiation).
    ztls.observability.endHandshakeSpan(server_span, false, "", "");
    server_span.end(null);
}
