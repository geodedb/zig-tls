// SPDX-License-Identifier: Apache-2.0
//! PERF-201 regression: ClientHelloInfo.parse must allocate no more than
//! 3 times for a minimal ClientHello. Pre-fix baseline (see
//! tests/bench_allocs.zig) was 8 allocs; target after the parse-then-copy
//! refactor is <=3 (one raw-body copy plus ownership-transferred inner
//! lists, with small slack for ALPN outer array).

const std = @import("std");
const counting = @import("counting_allocator");
const handshake_state = @import("handshake_state");

fn buildMinimalClientHello(alloc: std.mem.Allocator) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(alloc);
    try buf.appendSlice(alloc, &.{ 0x03, 0x03 });
    try buf.appendNTimes(alloc, 0xAA, 32);
    try buf.append(alloc, 0x00);
    try buf.appendSlice(alloc, &.{ 0x00, 0x02, 0x13, 0x01 });
    try buf.appendSlice(alloc, &.{ 0x01, 0x00 });
    const ext_pos = buf.items.len;
    try buf.appendSlice(alloc, &.{ 0x00, 0x00 });
    const start = buf.items.len;
    try buf.appendSlice(alloc, &.{ 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x07 });
    try buf.appendSlice(alloc, &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 });
    try buf.appendSlice(alloc, &.{ 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d });
    try buf.appendSlice(alloc, &.{ 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20 });
    try buf.appendNTimes(alloc, 0x01, 32);
    const end = buf.items.len;
    const ext_len: u16 = @intCast(end - start);
    buf.items[ext_pos] = @intCast((ext_len >> 8) & 0xff);
    buf.items[ext_pos + 1] = @intCast(ext_len & 0xff);
    return try buf.toOwnedSlice(alloc);
}

test "PERF-201: ClientHelloInfo.parse allocates at most 3 times" {
    const base = std.testing.allocator;
    const body = try buildMinimalClientHello(base);
    defer base.free(body);

    var ca = counting.CountingAllocator.init(base);
    var info = try handshake_state.ClientHelloInfo.parse(ca.allocator(), body);
    defer info.deinit(ca.allocator());

    // Target post-PERF-201: 1 raw-body copy + ownership-transferred inner
    // lists + small slack (at most 2 extra: cipher_suites outer + ALPN).
    // Pre-fix baseline was 8 (see tests/bench_allocs.zig).
    try std.testing.expect(ca.stats.alloc_count <= 3);
}
