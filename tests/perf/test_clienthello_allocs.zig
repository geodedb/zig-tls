// SPDX-License-Identifier: Apache-2.0
//! PERF-201 regression: ClientHelloInfo.parse must allocate no more than
//! 7 times for a minimal ClientHello under std.testing.allocator. Pre-fix
//! baseline (see tests/bench_allocs.zig) was 8 allocs; post-fix bench
//! (under page_allocator) is 4. The residual under testing.allocator is
//! higher because DebugAllocator never resizes in place, so each
//! std.ArrayList.toOwnedSlice shrink-to-fit inside parseClientHello
//! becomes an alloc+free pair rather than a single resize. The minimal
//! ClientHello allocs break down as:
//!   1. `raw` body dupe (ClientHelloInfo owns, re-sliced into).
//!   2..3. cipher_suites ArrayList initCapacity + shrink-on-toOwnedSlice
//!      (ownership transferred to ClientHelloInfo).
//!   4..5. signature_algorithms ArrayList initCapacity + shrink (transferred).
//!   6..7. supported_groups ArrayList initCapacity + shrink — parseClientHello
//!      allocates this unconditionally but ClientHelloInfo does not retain
//!      it, so freeParsedClientHello discards it. Out of PERF-201 scope;
//!      a follow-up would teach parseClientHello to skip the list when the
//!      caller does not consume it.
//! The 50% drop (8 -> 4 allocs under page_allocator) is what PERF-201
//! targeted; this test's bound is the testing.allocator upper bound.

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

test "PERF-201: ClientHelloInfo.parse allocates at most 7 times" {
    const base = std.testing.allocator;
    const body = try buildMinimalClientHello(base);
    defer base.free(body);

    var ca = counting.CountingAllocator.init(base);
    var info = try handshake_state.ClientHelloInfo.parse(ca.allocator(), body);
    defer info.deinit(ca.allocator());

    // Target post-PERF-201 under std.testing.allocator (DebugAllocator
    // never resizes in place): 7 allocs for a minimal ClientHello.
    //   1. `raw` body dupe (kept, re-sliced into).
    //   2..3. cipher_suites ArrayList initCapacity + shrink-on-toOwnedSlice
    //         (ownership transferred from parseClientHello).
    //   4..5. signature_algorithms ArrayList initCapacity + shrink
    //         (ownership transferred).
    //   6..7. supported_groups ArrayList initCapacity + shrink --
    //         parseClientHello allocates this unconditionally but
    //         ClientHelloInfo does not retain it, so freeParsedClientHello
    //         discards it. Out of PERF-201 scope; a follow-up would teach
    //         parseClientHello to skip the list when the caller doesn't
    //         consume it.
    //
    // Pre-fix baseline was 8 (see tests/bench_allocs.zig). The 50% drop
    // to 4 allocs under page_allocator is what PERF-201 targeted; this
    // test bounds the upper limit under the strict testing allocator.
    try std.testing.expect(ca.stats.alloc_count <= 7);
}
