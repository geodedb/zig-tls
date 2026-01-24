// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! TLS 1.3 Debug Logger
//!
//! Centralized logging control for TLS 1.3 debug output.
//! Set enable_debug_prints to false to disable all TLS debug output at compile time.

const std = @import("std");

/// Compile-time flag to enable/disable debug prints.
/// Set to false for production to eliminate all debug output.
pub const enable_debug_prints: bool = false;

/// Wrapper for std.debug.print that respects the enable_debug_prints flag.
/// When disabled, this becomes a no-op at compile time.
pub fn debugPrint(comptime fmt: []const u8, args: anytype) void {
    if (comptime !enable_debug_prints) return;
    std.debug.print(fmt, args);
}

/// Print hex bytes for debugging.
pub fn debugPrintHex(bytes: []const u8) void {
    if (comptime !enable_debug_prints) return;
    for (bytes) |b| {
        std.debug.print("{X:0>2} ", .{b});
    }
    std.debug.print("\n", .{});
}
