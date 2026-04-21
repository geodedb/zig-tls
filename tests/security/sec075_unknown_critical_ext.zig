// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! SEC-075: RFC 5280 §4.2 — A certificate-using system MUST reject
//! the certificate if it encounters a critical extension it does
//! not recognize.

const std = @import("std");
const x509 = @import("x509");

// Fixtures live under tests/security/fixtures/ because Zig 0.16's
// @embedFile is scoped to the test module's package path (tests/security/);
// the generator under tests/fixtures/generate_sec075.sh writes here.
const cert_with_unknown_critical: []const u8 = @embedFile(
    "fixtures/sec075_unknown_critical_ext.der",
);

const cert_with_unknown_noncritical: []const u8 = @embedFile(
    "fixtures/sec075_unknown_noncritical_ext.der",
);

test "SEC-075: unknown critical extension causes reject" {
    const alloc = std.testing.allocator;
    const result = x509.parseCert(alloc, cert_with_unknown_critical);
    try std.testing.expectError(error.UnknownCriticalExtension, result);
}

test "SEC-075: unknown NON-critical extension is accepted" {
    const alloc = std.testing.allocator;
    var parsed = try x509.parseCert(alloc, cert_with_unknown_noncritical);
    defer parsed.deinit(alloc);
}
