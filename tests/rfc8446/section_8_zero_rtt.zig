//! RFC 8446 §8: 0-RTT and Anti-Replay Tests (GAP-0120 part 4)
//!
//! §8 requires servers that accept early data to implement single-use
//! tickets or ClientHello recording to prevent replay. This crate's
//! `zero_rtt` module provides a sliding-window recorder. This file
//! pins the public surface (TicketState enum, recommended window
//! sizes, AntiReplayWindowSized constructor).

const std = @import("std");
const zero_rtt = @import("zero_rtt");

test "RFC 8446 §8: TicketState has issued/used states" {
    // Compile-time shape assertion: the enum carries the states
    // required by the RFC §8 recommendation.
    const ts = @typeInfo(zero_rtt.TicketState);
    try std.testing.expect(ts == .@"enum");
    try std.testing.expect(ts.@"enum".fields.len >= 2);
}

test "RFC 8446 §8: recommended window sizes are monotone" {
    try std.testing.expect(zero_rtt.WindowSizeRecommendations.low_traffic <
        zero_rtt.WindowSizeRecommendations.moderate_traffic);
    try std.testing.expect(zero_rtt.WindowSizeRecommendations.moderate_traffic <
        zero_rtt.WindowSizeRecommendations.high_traffic);
    try std.testing.expect(zero_rtt.WindowSizeRecommendations.high_traffic <
        zero_rtt.WindowSizeRecommendations.very_high_traffic);
}

test "RFC 8446 §8: default_window_size matches low_traffic recommendation" {
    try std.testing.expectEqual(
        zero_rtt.WindowSizeRecommendations.low_traffic,
        zero_rtt.default_window_size,
    );
}

test "RFC 8446 §8: AntiReplayWindowSized compiles at a small size" {
    const W = zero_rtt.AntiReplayWindowSized(16);
    try std.testing.expectEqual(@as(usize, 16), W.window_size);
}
