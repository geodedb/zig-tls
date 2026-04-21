// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! SEC-065/085: Regression tests for cross-connection anti-replay wiring.

const std = @import("std");
const zero_rtt = @import("zero_rtt");

const MockStore = struct {
    seen: std.ArrayList([32]u8) = .empty,
    allocator: std.mem.Allocator,
    fail_mode: enum { ok, backend_unavailable } = .ok,

    fn init(alloc: std.mem.Allocator) MockStore {
        return .{ .allocator = alloc };
    }

    fn deinit(self: *MockStore) void {
        self.seen.deinit(self.allocator);
    }

    fn checkAndAdd(ptr: *anyopaque, random: [32]u8) zero_rtt.PersistentAntiReplayStore.PersistentStoreError!bool {
        const self: *MockStore = @ptrCast(@alignCast(ptr));
        if (self.fail_mode == .backend_unavailable) return error.BackendUnavailable;
        for (self.seen.items) |prev| {
            if (std.mem.eql(u8, &prev, &random)) return false;
        }
        self.seen.append(self.allocator, random) catch return error.BackendUnavailable;
        return true;
    }

    fn asStore(self: *MockStore) zero_rtt.PersistentAntiReplayStore {
        const vtable = zero_rtt.PersistentAntiReplayStore.VTable{
            .checkAndAdd = checkAndAdd,
            .reset = null,
        };
        return .{ .ptr = self, .vtable = &vtable };
    }
};

test "SEC-065: persistent store accepts new random" {
    const alloc = std.testing.allocator;
    var store = MockStore.init(alloc);
    defer store.deinit();
    const s = store.asStore();

    const r1 = [_]u8{0x01} ** 32;
    try std.testing.expect(try s.checkAndAdd(r1));
}

test "SEC-065: persistent store rejects replayed random" {
    const alloc = std.testing.allocator;
    var store = MockStore.init(alloc);
    defer store.deinit();
    const s = store.asStore();

    const r1 = [_]u8{0x01} ** 32;
    _ = try s.checkAndAdd(r1);
    try std.testing.expect(!(try s.checkAndAdd(r1)));
}

test "SEC-065: backend unavailable returns error" {
    const alloc = std.testing.allocator;
    var store = MockStore.init(alloc);
    defer store.deinit();
    store.fail_mode = .backend_unavailable;
    const s = store.asStore();

    const r1 = [_]u8{0x01} ** 32;
    try std.testing.expectError(error.BackendUnavailable, s.checkAndAdd(r1));
}

test "SEC-065/085: cross-context replay behavior via shared store" {
    // This test exercises the store API (not full handshake drive yet).
    // A full integration test requires driving two Context instances
    // through 0-RTT accept with a shared MockStore; deferred until the
    // existing 0-RTT test harness in tests/rfc8446/section_8_zero_rtt.zig
    // is generalized.
    const alloc = std.testing.allocator;
    var store = MockStore.init(alloc);
    defer store.deinit();
    const s = store.asStore();

    const r = [_]u8{0x42} ** 32;
    try std.testing.expect(try s.checkAndAdd(r)); // Context A accepts
    try std.testing.expect(!(try s.checkAndAdd(r))); // Context B sees replay
}
