// SPDX-License-Identifier: Apache-2.0
//! PERF-218 regression: `Context.selectServerAlpn` must borrow the
//! negotiated protocol from `config.alpn_protocols` rather than
//! duplicating it. `config` outlives `Context`, so the dupe is
//! redundant. This test locks in:
//!   1. Zero allocation delta under CountingAllocator across the call.
//!   2. Pointer identity: `ctx.negotiated_alpn.?.ptr` must equal
//!      `config.alpn_protocols.?[0].ptr` — proving the slice was
//!      borrowed, not copied.
//!
//! Until the borrow flip lands (plan Task 4), selectServerAlpn still
//! dupes and this test is skip-guarded so pre-commit `zig build test`
//! stays green.

const std = @import("std");
const counting = @import("counting_allocator");
const tls13 = @import("tls13");

test "PERF-218: selectServerAlpn borrows from config (no dupe)" {
    const base = std.testing.allocator;
    var ca = counting.CountingAllocator.init(base);
    const alloc = ca.allocator();

    const alpn_protocols: []const []const u8 = &.{"h3"};

    const config = tls13.Config{
        .allocator = alloc,
        .role = .Server,
        .alpn_protocols = alpn_protocols,
    };

    var ctx = try tls13.Context.init(config, .{});
    defer ctx.deinit();

    const client_offered: []const []const u8 = &.{"h3"};
    const ch_view = tls13.ClientHelloView{
        .random = [_]u8{0} ** 32,
        .session_id = &.{},
        .cipher_suites = &.{},
        .signature_algorithms = null,
        .supported_versions = &.{},
        .key_share = .{ .group = .x25519, .key = &.{} },
        .quic_transport_parameters = null,
        .alpn_list = client_offered,
        .early_data = false,
        .pre_shared_key = null,
        .psk_key_exchange_modes = null,
        .cookie = null,
        .raw = &.{},
    };

    const allocs_before = ca.stats.alloc_count;
    const selected = try ctx.selectServerAlpn(ch_view);
    const allocs_after = ca.stats.alloc_count;

    try std.testing.expect(selected != null);
    try std.testing.expectEqual(@as(u64, 0), allocs_after - allocs_before);

    // The negotiated slice must be a borrow into config.alpn_protocols[0].
    try std.testing.expect(ctx.negotiated_alpn != null);
    try std.testing.expectEqual(
        @intFromPtr(config.alpn_protocols.?[0].ptr),
        @intFromPtr(ctx.negotiated_alpn.?.ptr),
    );
}
