// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const backend = @import("crypto_backend");

test "seam resolves and exposes the FIPS-approved API surface" {
    // fips_enabled tracks -Dfips; default build is false.
    try std.testing.expect(@TypeOf(backend.fips_enabled) == bool);
    // assertActive must be callable in both modes (no-op when off).
    backend.assertActive();
    // SHA2-256("abc") KAT routes through whichever backend is active.
    var out: [32]u8 = undefined;
    _ = try backend.Hash.digest(.sha256, "abc", &out);
    const expect = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    try std.testing.expectEqualSlices(u8, &expect, &out);
}
