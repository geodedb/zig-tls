// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
//! Shared test helpers used across `tests/` unit / conformance / RFC suites.
//!
//! Introduced in Cycle 2 (2026-04-19) to close QUAL-205 which flagged 14
//! near-identical copies of `hexToBytes` scattered across test files.
//!
//! Keep this module *test-only*. Anything here is unconditionally imported
//! from `tests/` and must not leak into `src/` production code.

const std = @import("std");

/// Decode an ASCII hex string into `out`. `hex.len` must equal `out.len * 2`.
///
/// Accepts upper- or lower-case hex digits. Panics via `unreachable` on any
/// non-hex byte -- this is acceptable for test helpers where input is
/// literal / pinned and any malformedness is a bug in the test itself.
pub fn hexToBytes(hex: []const u8, out: []u8) void {
    std.debug.assert(hex.len == out.len * 2);
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        out[i / 2] = std.fmt.parseInt(u8, hex[i .. i + 2], 16) catch unreachable;
    }
}

test "hexToBytes: round-trip well-formed hex" {
    var out: [4]u8 = undefined;
    hexToBytes("deadbeef", &out);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, &out);
}

test "hexToBytes: uppercase hex digits accepted" {
    var out: [3]u8 = undefined;
    hexToBytes("CAFE01", &out);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xca, 0xfe, 0x01 }, &out);
}

test "hexToBytes: empty input -> empty output" {
    var out: [0]u8 = undefined;
    hexToBytes("", &out);
}
