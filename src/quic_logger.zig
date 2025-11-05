//! Placeholder QUIC logger module
//!
//! This module provides a minimal logging interface for the TLS implementation.
//! In a real QUIC implementation, this would be replaced with the actual QUIC
//! stack's logging system.

const std = @import("std");

/// Log level enumeration
pub const Level = enum {
    debug,
    info,
    warn,
    err,
};

/// Log a message (no-op placeholder implementation)
pub fn log(comptime level: Level, comptime format: []const u8, args: anytype) void {
    _ = level;
    _ = format;
    _ = args;
    // In a real implementation, this would forward to the QUIC stack's logger
    // For now, we do nothing to keep the TLS library dependency-free
}

/// Debug-level log
pub fn debug(comptime format: []const u8, args: anytype) void {
    log(.debug, format, args);
}

/// Info-level log
pub fn info(comptime format: []const u8, args: anytype) void {
    log(.info, format, args);
}

/// Warning-level log
pub fn warn(comptime format: []const u8, args: anytype) void {
    log(.warn, format, args);
}

/// Error-level log
pub fn err(comptime format: []const u8, args: anytype) void {
    log(.err, format, args);
}
