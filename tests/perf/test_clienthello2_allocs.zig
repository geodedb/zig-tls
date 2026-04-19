// SPDX-License-Identifier: Apache-2.0
//! PERF-208 regression: `buildClientHello` with
//! `prepend_handshake_header=true` must allocate the framed handshake
//! message (4-byte handshake header + ClientHello body) in a single
//! owned buffer under std.testing.allocator. Pre-fix behavior
//! allocated the body, then a separate 4+body.len buffer with memcpy,
//! then freed both; post-fix the caller consumes `ch_result.body`
//! directly with no additional alloc/memcpy.
//!
//! Under std.testing.allocator (DebugAllocator never resizes in place)
//! the build path allocates:
//!   * ArrayList.initCapacity(256)            -> 1 alloc
//!   * toOwnedSlice shrink-to-fit             -> 1 alloc + 1 free
//! So total alloc_count is at most 2. Pre-fix, the caller added a
//! third alloc to prepend the header -- that allocation is gone.

const std = @import("std");
const counting = @import("counting_allocator");
const tls13_full = @import("tls13_full");

fn defaultParams() tls13_full.ClientHelloParams {
    const random = [_]u8{0xAA} ** 32;
    const client_pub = [_]u8{0xBB} ** 32;
    return .{
        .random = random,
        .client_pub = client_pub,
        .cipher_suites = &.{},
        .supported_groups = &.{},
        .signature_algorithms = &.{},
    };
}

test "PERF-208: buildClientHello with prepend_handshake_header allocates at most twice" {
    const base = std.testing.allocator;
    var ca = counting.CountingAllocator.init(base);

    var params = defaultParams();
    params.prepend_handshake_header = true;

    const result = try tls13_full.buildClientHello(ca.allocator(), params);
    defer ca.allocator().free(result.body);

    // The framed buffer must be at least 4 bytes (header) + some body.
    try std.testing.expect(result.body.len >= 4 + 2 + 32 + 1);

    // The first byte must be the ClientHello handshake type (0x01).
    try std.testing.expectEqual(@as(u8, 0x01), result.body[0]);

    // The 3-byte big-endian length field must equal body_len - 4.
    const declared_len: usize = (@as(usize, result.body[1]) << 16) |
        (@as(usize, result.body[2]) << 8) |
        @as(usize, result.body[3]);
    try std.testing.expectEqual(result.body.len - 4, declared_len);

    // Allocation bound: ArrayList initCapacity + toOwnedSlice
    // shrink-to-fit under DebugAllocator. Pre-fix, the caller
    // had to allocate a separate 4+body.len buffer (+1 alloc)
    // and memcpy into it -- that second allocation is gone.
    try std.testing.expect(ca.stats.alloc_count <= 2);
}

test "PERF-208: buildClientHello without prepend preserves legacy body-only semantics" {
    const base = std.testing.allocator;

    const params = defaultParams();
    const result = try tls13_full.buildClientHello(base, params);
    defer base.free(result.body);

    // Without the flag, body must start with legacy_version 0x0303 --
    // i.e. no handshake header has been written.
    try std.testing.expectEqual(@as(u8, 0x03), result.body[0]);
    try std.testing.expectEqual(@as(u8, 0x03), result.body[1]);
}
