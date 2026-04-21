// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! SEC-074: Regression test for RNG fail-closed semantics.

const std = @import("std");
const entropy = @import("entropy");

test "SEC-074: fillRandom produces non-zero bytes" {
    var buf: [32]u8 = undefined;
    @memset(&buf, 0);
    entropy.fillRandom(&buf);
    var all_zero = true;
    for (buf) |b| if (b != 0) {
        all_zero = false;
        break;
    };
    try std.testing.expect(!all_zero);
}

test "SEC-074: fillRandom overwrites caller buffer" {
    var buf: [16]u8 = undefined;
    @memset(&buf, 0xAA);
    entropy.fillRandom(&buf);
    var any_differ = false;
    for (buf) |b| if (b != 0xAA) {
        any_differ = true;
        break;
    };
    try std.testing.expect(any_differ);
}

test "SEC-074: fillRandom is not constant across calls" {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    entropy.fillRandom(&a);
    entropy.fillRandom(&b);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}
