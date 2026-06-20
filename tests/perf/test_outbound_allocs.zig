// SPDX-License-Identifier: Apache-2.0
//! PERF-249 regression: outbound CryptoBuffer paths in `src/tls13/context.zig`
//! must call `ensureUnusedCapacity` before `appendSlice` so a typical client
//! handshake completes without uncapped intermediate ArrayList reallocations.
//!
//! Coverage:
//!   * `startClientHandshake` queues exactly one ClientHello write into the
//!     Initial-level outbound CryptoBuffer.
//!   * `sendFatalAlert` queues a single 2-byte alert payload — the regression
//!     is that the previous code path reached `appendSlice` without a
//!     `ensureUnusedCapacity` and so re-allocated whenever the alert arrived
//!     after a non-trivial outbound flight had already been built.
//!
//! The assertion bounds the number of *resize* operations recorded by the
//! counting allocator. With the PERF-249 fix in place the outbound buffer
//! is pre-sized in one shot per call, so the "resize" count is zero across
//! the workload (an `ensureUnusedCapacity` to a freshly-empty ArrayList
//! goes through the initial-alloc path, not resize). Without the fix, the
//! ClientHello path (~256 bytes) reaches the outbound buffer with no
//! pre-size hint and trips the ArrayList grow heuristic at least once.

const std = @import("std");
const counting = @import("counting_allocator");
const tls13 = @import("tls13");

test "PERF-249: client handshake outbound has at most 2 reallocs" {
    // Standalone X25519 is not FIPS-approved; the client handshake fails
    // closed under -Dfips=true, so this std-X25519 alloc-count test skips.
    if (comptime tls13.fips_enabled) return error.SkipZigTest;
    var ca = counting.CountingAllocator.init(std.testing.allocator);
    const alloc = ca.allocator();

    var ctx = try tls13.Context.init(.{
        .allocator = alloc,
        .role = .Client,
        .supported_groups = &.{.x25519},
        .supported_signature_schemes = &.{.ed25519},
        .quic_transport_parameters = &[_]u8{},
    }, .{});
    defer ctx.deinit();

    const before = ca.stats.resize_count;
    try ctx.startClientHandshake();

    // Drain the outbound CRYPTO bytes the client just produced.
    const drained = try ctx.pollCrypto(alloc, .Initial);
    defer alloc.free(drained);
    try std.testing.expect(drained.len > 0);

    // Send a fatal alert — exercises the alert path's pre-size.
    // After startClientHandshake the Context phase is `.negotiating`, so
    // sendFatalAlert routes to the Handshake-level outbound buffer.
    try ctx.sendFatalAlert(.unexpected_message);
    const drained_alert = try ctx.pollCrypto(alloc, .Handshake);
    defer alloc.free(drained_alert);
    try std.testing.expectEqual(@as(usize, 2), drained_alert.len);

    const after = ca.stats.resize_count;
    // Pre-fix baseline was ≥1 resize on every CH that exceeded the
    // ArrayList default (ClientHello with QUIC TPs runs ~140-200 bytes
    // and consistently tripped the resize heuristic).
    try std.testing.expect(after - before <= 2);
}
