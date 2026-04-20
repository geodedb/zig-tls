// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUAL-317: server-side ALPN selection.
//!
//! Returns a slice BORROWED from `supported` (the caller's config slice) —
//! lifetime contract: caller guarantees `supported` outlives the returned
//! slice. Mirrors Cycle 4 PERF-218 server-path borrow semantics.

const std = @import("std");

/// Match the first server-preferred protocol that the client also offered.
/// Returns a slice pointing into `supported` (NOT allocated). Returns null
/// if either list is empty or there is no overlap.
pub fn selectServerAlpn(
    client_protocols: []const []const u8,
    supported: []const []const u8,
) ?[]const u8 {
    if (supported.len == 0) return null;
    if (client_protocols.len == 0) return null;
    for (supported) |s| {
        for (client_protocols) |c| {
            if (std.mem.eql(u8, s, c)) return s;
        }
    }
    return null;
}

test "alpn_selection: first-match — server preference wins" {
    const server = [_][]const u8{ "h3", "h2" };
    const client = [_][]const u8{ "h2", "h3" };
    try std.testing.expectEqualStrings("h3", selectServerAlpn(&client, &server).?);
}

test "alpn_selection: borrow — returned slice is pointer-equal to supported[i]" {
    const server = [_][]const u8{ "h3", "h2" };
    const client = [_][]const u8{"h3"};
    const got = selectServerAlpn(&client, &server).?;
    try std.testing.expectEqual(@intFromPtr(server[0].ptr), @intFromPtr(got.ptr));
}

test "alpn_selection: no-match returns null" {
    const server = [_][]const u8{"h3"};
    const client = [_][]const u8{"h2"};
    try std.testing.expect(selectServerAlpn(&client, &server) == null);
}

test "alpn_selection: empty lists return null" {
    const empty: []const []const u8 = &.{};
    try std.testing.expect(selectServerAlpn(empty, empty) == null);

    const server = [_][]const u8{"h3"};
    try std.testing.expect(selectServerAlpn(empty, &server) == null);
    try std.testing.expect(selectServerAlpn(&server, empty) == null);
}
