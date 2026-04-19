// SPDX-License-Identifier: Apache-2.0
//! Allocation-count baseline for PERF-201 (ClientHelloInfo.parse) and future
//! PERF-207 validation. Run: zig build bench-allocs

const std = @import("std");
const counting = @import("counting_allocator");
const handshake_state = @import("handshake_state");

fn buildMinimalClientHello(alloc: std.mem.Allocator) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(alloc);

    // ClientHello body: legacy_version (2) + random (32) + session_id (1 len + 0)
    try buf.appendSlice(alloc, &.{ 0x03, 0x03 });
    try buf.appendNTimes(alloc, 0xAA, 32);
    try buf.append(alloc, 0x00);

    // cipher_suites: length(2) + one suite (TLS_AES_128_GCM_SHA256 = 0x13 0x01)
    try buf.appendSlice(alloc, &.{ 0x00, 0x02, 0x13, 0x01 });

    // compression_methods: length(1) + null(0)
    try buf.appendSlice(alloc, &.{ 0x01, 0x00 });

    // Extensions: placeholder length patched below.
    const ext_pos = buf.items.len;
    try buf.appendSlice(alloc, &.{ 0x00, 0x00 });
    const start = buf.items.len;

    // signature_algorithms (0x000d): ed25519 (0x0807)
    try buf.appendSlice(alloc, &.{ 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x07 });

    // supported_versions (0x002b): TLS 1.3 (0x0304)
    try buf.appendSlice(alloc, &.{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 });

    // supported_groups (0x000a): x25519 (0x001d)
    try buf.appendSlice(alloc, &.{ 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d });

    // key_share (0x0033): minimal x25519 share
    try buf.appendSlice(alloc, &.{ 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20 });
    try buf.appendNTimes(alloc, 0x01, 32);

    const end = buf.items.len;
    const ext_len: u16 = @intCast(end - start);
    buf.items[ext_pos] = @intCast((ext_len >> 8) & 0xff);
    buf.items[ext_pos + 1] = @intCast(ext_len & 0xff);

    return try buf.toOwnedSlice(alloc);
}

pub fn main() !void {
    const base_alloc = std.heap.page_allocator;

    const body = try buildMinimalClientHello(base_alloc);
    defer base_alloc.free(body);

    var ca = counting.CountingAllocator.init(base_alloc);
    var info = try handshake_state.ClientHelloInfo.parse(ca.allocator(), body);
    defer info.deinit(ca.allocator());
    ca.report("ClientHelloInfo.parse");
}
