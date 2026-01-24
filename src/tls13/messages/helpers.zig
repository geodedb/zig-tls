// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! TLS 1.3 Message Parsing and Building Helper Functions
//!
//! This module provides low-level byte manipulation utilities used across
//! all TLS 1.3 message parsing and building functions. These functions handle
//! big-endian integer reading/writing and TLS extension encoding.
//!
//! ## RFC Coverage
//!
//! - RFC 8446 §3: Presentation Language (big-endian encoding)
//! - RFC 8446 §4.2: Extension encoding format
//!
//! ## Functions
//!
//! - `readU16`: Read big-endian 16-bit integer
//! - `readU24`: Read big-endian 24-bit integer (used for length fields)
//! - `readU32`: Read big-endian 32-bit integer
//! - `writeExtension`: Encode TLS extension (type + length + data)

const std = @import("std");
const core_types = @import("core_types.zig");

/// Read big-endian 16-bit integer from buffer (RFC 8446 §3).
///
/// ## Parameters
///
/// - `data`: Buffer containing at least 2 bytes
///
/// ## Returns
///
/// - `u16`: Decoded 16-bit value
///
/// ## Usage
///
/// ```zig
/// const value = readU16(&[_]u8{0x03, 0x04}); // Returns 0x0304 (772)
/// ```
pub fn readU16(data: []const u8) u16 {
    return (@as(u16, data[0]) << 8) | data[1];
}

/// Read big-endian 24-bit integer from buffer (RFC 8446 §3).
///
/// TLS uses 24-bit length fields in several message types (Certificate, etc.).
/// This function decodes a 3-byte big-endian integer into a Zig u24 type.
///
/// ## Parameters
///
/// - `data`: Buffer containing at least 3 bytes
///
/// ## Returns
///
/// - `u24`: Decoded 24-bit value (0 to 16,777,215)
///
/// ## Usage
///
/// ```zig
/// const len = readU24(&[_]u8{0x00, 0x10, 0x00}); // Returns 4096
/// ```
pub fn readU24(data: []const u8) u24 {
    return (@as(u24, data[0]) << 16) | (@as(u24, data[1]) << 8) | data[2];
}

/// Read big-endian 32-bit integer from buffer (RFC 8446 §3).
///
/// ## Parameters
///
/// - `data`: Buffer containing at least 4 bytes
///
/// ## Returns
///
/// - `u32`: Decoded 32-bit value
///
/// ## Usage
///
/// ```zig
/// const value = readU32(&[_]u8{0x00, 0x00, 0x10, 0x00}); // Returns 4096
/// ```
pub fn readU32(data: []const u8) u32 {
    return (@as(u32, data[0]) << 24) | (@as(u32, data[1]) << 16) | (@as(u32, data[2]) << 8) | data[3];
}

/// Write a TLS extension to the extension list (RFC 8446 §4.2).
///
/// Encodes a TLS extension in the standard format:
/// ```
/// struct {
///     ExtensionType extension_type;  // 2 bytes
///     opaque extension_data<0..2^16-1>; // 2-byte length + data
/// } Extension;
/// ```
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for list growth
/// - `list`: ArrayList to append encoded extension to
/// - `ext_type`: TLS extension type identifier (ExtensionType enum)
/// - `data`: Extension payload data
///
/// ## Errors
///
/// - `error.OutOfMemory`: Failed to allocate memory for extension
///
/// ## Usage
///
/// ```zig
/// var exts = std.ArrayList(u8).init(allocator);
/// defer exts.deinit();
/// try writeExtension(allocator, &exts, .key_share, key_share_data);
/// try writeExtension(allocator, &exts, .supported_versions, &[_]u8{0x03, 0x04});
/// ```
///
/// ## Encoding Details
///
/// For `ext_type = .key_share` and `data = [0x00, 0x1d, 0x00, 0x20, ...]`:
/// - Bytes 0-1: Extension type (e.g., 0x0033 for key_share)
/// - Bytes 2-3: Data length (e.g., 0x0024 for 36 bytes)
/// - Bytes 4+: Extension data (e.g., named group + public key)
pub fn writeExtension(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(u8),
    ext_type: core_types.ExtensionType,
    data: []const u8,
) !void {
    const type_value = @intFromEnum(ext_type);
    try list.appendSlice(allocator, &[_]u8{
        @intCast(type_value >> 8),
        @intCast(type_value & 0xff),
        @intCast(data.len >> 8),
        @intCast(data.len & 0xff),
    });
    try list.appendSlice(allocator, data);
}
