// SPDX-License-Identifier: Apache-2.0
//! PERF-024 / PERF-201: Allocator wrapper that tracks allocation counts and
//! bytes against a wrapped allocator. Intended for test and benchmark use
//! only — never wire this into production.
//!
//! Usage:
//!   var ca = CountingAllocator.init(std.testing.allocator);
//!   defer ca.report("parseClientHello");
//!   const a = ca.allocator();
//!   _ = try a.alloc(u8, 16);

const std = @import("std");

pub const Stats = struct {
    alloc_count: u64 = 0,
    free_count: u64 = 0,
    resize_count: u64 = 0,
    total_alloc_bytes: u64 = 0,
    total_free_bytes: u64 = 0,
    current_live_bytes: i64 = 0,
    peak_live_bytes: u64 = 0,
};

pub const CountingAllocator = struct {
    parent: std.mem.Allocator,
    stats: Stats = .{},

    pub fn init(parent: std.mem.Allocator) CountingAllocator {
        return .{ .parent = parent };
    }

    pub fn allocator(self: *CountingAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = allocFn,
                .resize = resizeFn,
                .remap = remapFn,
                .free = freeFn,
            },
        };
    }

    fn bumpPeak(self: *CountingAllocator) void {
        const live_u64: u64 = if (self.stats.current_live_bytes > 0)
            @intCast(self.stats.current_live_bytes)
        else
            0;
        if (live_u64 > self.stats.peak_live_bytes) self.stats.peak_live_bytes = live_u64;
    }

    fn allocFn(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const result = self.parent.vtable.alloc(self.parent.ptr, len, alignment, ret_addr);
        if (result != null) {
            self.stats.alloc_count += 1;
            self.stats.total_alloc_bytes += len;
            self.stats.current_live_bytes += @as(i64, @intCast(len));
            self.bumpPeak();
        }
        return result;
    }

    fn resizeFn(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const ok = self.parent.vtable.resize(self.parent.ptr, buf, alignment, new_len, ret_addr);
        if (ok) {
            self.stats.resize_count += 1;
            const delta: i64 = @as(i64, @intCast(new_len)) - @as(i64, @intCast(buf.len));
            self.stats.current_live_bytes += delta;
            if (delta > 0) {
                self.stats.total_alloc_bytes += @intCast(delta);
                self.bumpPeak();
            } else if (delta < 0) {
                self.stats.total_free_bytes += @intCast(-delta);
            }
        }
        return ok;
    }

    fn remapFn(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        return self.parent.vtable.remap(self.parent.ptr, buf, alignment, new_len, ret_addr);
    }

    fn freeFn(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.parent.vtable.free(self.parent.ptr, buf, alignment, ret_addr);
        self.stats.free_count += 1;
        self.stats.total_free_bytes += buf.len;
        self.stats.current_live_bytes -= @intCast(buf.len);
    }

    pub fn reset(self: *CountingAllocator) void {
        self.stats = .{};
    }

    pub fn report(self: *const CountingAllocator, label: []const u8) void {
        std.debug.print("[allocs] {s}: {d} allocs ({d} bytes), {d} frees ({d} bytes), peak live {d} bytes\n", .{
            label,
            self.stats.alloc_count,
            self.stats.total_alloc_bytes,
            self.stats.free_count,
            self.stats.total_free_bytes,
            self.stats.peak_live_bytes,
        });
    }
};

test "CountingAllocator tracks alloc and free" {
    var ca = CountingAllocator.init(std.testing.allocator);
    const a = ca.allocator();

    const buf = try a.alloc(u8, 128);
    try std.testing.expectEqual(@as(u64, 1), ca.stats.alloc_count);
    try std.testing.expectEqual(@as(u64, 128), ca.stats.total_alloc_bytes);
    try std.testing.expectEqual(@as(u64, 128), ca.stats.peak_live_bytes);

    a.free(buf);
    try std.testing.expectEqual(@as(u64, 1), ca.stats.free_count);
    try std.testing.expectEqual(@as(u64, 128), ca.stats.total_free_bytes);
    try std.testing.expectEqual(@as(i64, 0), ca.stats.current_live_bytes);
}
