// SPDX-License-Identifier: Apache-2.0
//! PERF-207 regression: validateChainReturnParsed must return the parsed
//! leaf certificate so callers (e.g. src/tls13/context.zig handleCertificate
//! path) do not need to re-invoke parseCert(chain[0]). Asserts that the
//! new entrypoint exists and that the returned leaf has a non-empty `tbs`.

const std = @import("std");
const counting = @import("counting_allocator");
const x509 = @import("x509");

test "PERF-207: validateChainReturnParsed returns leaf without caller re-parse" {
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
        true, // allow_insecure: self-signed without trust store
        x509.EkuPurpose.server_auth,
        null,
    );
    defer leaf.deinit(ca.allocator());

    try std.testing.expect(leaf.tbs.len > 0);
    ca.report("validateChainReturnParsed(1-cert)");
}
