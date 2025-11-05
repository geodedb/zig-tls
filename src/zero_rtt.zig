//! 0-RTT ticket tracking and anti-replay per RFC 8446 §8.
//!
//! Provides the limited replay window and ticket state helpers referenced by
//! the QUIC handshake when enabling early data (RFC 9001 §4.6).
const std = @import("std");

/// RFC 8446 §8.2: Single-use tickets prevent replay across connections
pub const TicketState = enum {
    unused,
    used,
    revoked,
};

/// Simple sliding window anti-replay cache (RFC 8446 §8.1)
/// Tracks recently seen ClientHello random values to detect replays
pub const AntiReplayWindow = struct {
    const Self = @This();
    const window_size = 64; // Track last 64 randoms

    randoms: [window_size][32]u8 = undefined,
    count: usize = 0,
    allocator: std.mem.Allocator,

    /// Construct an empty anti-replay window backed by the provided allocator.
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .randoms = undefined,
            .count = 0,
            .allocator = allocator,
        };
    }

    /// Release any allocator-backed state held by the window (no-op today).
    pub fn deinit(_: *Self) void {
        // No heap allocations in this simple implementation
    }

    /// Check if a random value has been seen before (replay detection)
    pub fn contains(self: *const Self, random: [32]u8) bool {
        const limit = @min(self.count, window_size);
        var i: usize = 0;
        while (i < limit) : (i += 1) {
            if (std.mem.eql(u8, &self.randoms[i], &random)) {
                return true;
            }
        }
        return false;
    }

    /// Record a new random value (FIFO eviction when full)
    pub fn add(self: *Self, random: [32]u8) !void {
        if (self.contains(random)) {
            return error.ReplayDetected;
        }
        const idx = self.count % window_size;
        self.randoms[idx] = random;
        self.count += 1;
    }

    /// Clear all entries (for testing)
    pub fn reset(self: *Self) void {
        self.count = 0;
    }
};

/// RFC 8446 §8.3: Limits on 0-RTT usage
pub const ZeroRttLimits = struct {
    max_early_data_size: u32 = 16384, // 16KB default
    // Additional limits would go here (time window, etc.)
};

test "anti-replay window detects duplicates" {
    var window = AntiReplayWindow.init(std.testing.allocator);
    defer window.deinit();

    const random1: [32]u8 = .{0x01} ** 32;
    const random2: [32]u8 = .{0x02} ** 32;

    // Add first random
    try window.add(random1);
    try std.testing.expect(window.contains(random1));
    try std.testing.expect(!window.contains(random2));

    // Try to add same random again - should fail
    try std.testing.expectError(error.ReplayDetected, window.add(random1));

    // Add different random - should succeed
    try window.add(random2);
    try std.testing.expect(window.contains(random2));
}

test "anti-replay window FIFO eviction" {
    var window = AntiReplayWindow.init(std.testing.allocator);
    defer window.deinit();

    // Fill window beyond capacity
    var i: usize = 0;
    while (i < AntiReplayWindow.window_size + 10) : (i += 1) {
        var random: [32]u8 = undefined;
        @memset(&random, @as(u8, @intCast(i & 0xFF)));
        try window.add(random);
    }

    // Oldest entries should be evicted
    const old_random: [32]u8 = .{0x00} ** 32;
    try std.testing.expect(!window.contains(old_random));

    // Recent entries should still be present
    var recent_random: [32]u8 = undefined;
    @memset(&recent_random, @as(u8, @intCast((AntiReplayWindow.window_size + 9) & 0xFF)));
    try std.testing.expect(window.contains(recent_random));
}

test "anti-replay window reset" {
    var window = AntiReplayWindow.init(std.testing.allocator);
    defer window.deinit();

    const random: [32]u8 = .{0xAB} ** 32;
    try window.add(random);
    try std.testing.expect(window.contains(random));

    window.reset();
    try std.testing.expect(!window.contains(random));
    try std.testing.expectEqual(@as(usize, 0), window.count);
}
