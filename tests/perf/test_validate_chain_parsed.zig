// SPDX-License-Identifier: Apache-2.0
//! PERF-207 regression: validateChainReturnParsed must return the parsed
//! leaf certificate so callers (e.g. src/tls13/context.zig handleCertificate
//! path) do not need to re-invoke parseCert(chain[0]). Asserts that the
//! new entrypoint exists and that the returned leaf has a non-empty `tbs`.

const std = @import("std");
const counting = @import("counting_allocator");
const x509 = @import("x509");
// SEC-077: build-gated insecure sentinel.
const build_options = @import("build_options");

test "PERF-207: validateChainReturnParsed returns leaf without caller re-parse" {
    // SEC-077: uses the insecure sentinel; skip unless the flag is set.
    if (!build_options.tls_insecure_testing) return error.SkipZigTest;

    const base = std.testing.allocator;

    // Self-signed ed25519 leaf. Fixture is mirrored from tests/test_certs/
    // into tests/perf/ because Zig scopes @embedFile to the module's
    // package root (the directory of this test's root_source_file).
    const leaf_bytes = @embedFile("ed25519_cert.der");
    const chain: []const []const u8 = &.{leaf_bytes};

    var ca = counting.CountingAllocator.init(base);
    const now_unix: i64 = 1_760_000_000; // well within typical test cert validity

    var leaf = try x509.validateChainReturnParsed(
        ca.allocator(),
        chain,
        now_unix,
        "", // empty server_name: skip hostname check
        .testing_only_i_know_what_i_am_doing, // self-signed w/o trust store
        x509.EkuPurpose.server_auth,
        null,
    );
    defer leaf.deinit(ca.allocator());

    try std.testing.expect(leaf.tbs.len > 0);
    // NOTE: do not call `ca.report()` here. `std.debug.print` inside a
    // test run under Zig's `--listen=-` test-runner protocol corrupts
    // the framed stdout channel and causes `zig build test` to emit a
    // spurious `failed command: ... --listen=-` diagnostic even though
    // the test itself passes (GAP-0123). Diagnostic output belongs in
    // a bench harness, not a test body.
    try std.testing.expect(ca.stats.alloc_count >= 1);
    try std.testing.expect(ca.stats.peak_live_bytes > 0);
}
