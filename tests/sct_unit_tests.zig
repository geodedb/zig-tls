//! Unit tests for Signed Certificate Timestamp (SCT) parsing (RFC 6962)
//!
//! Tests the SCT list parsing functionality including:
//! - Basic SCT structure parsing
//! - Multiple SCT entries in a list
//! - Version validation
//! - Field extraction (log ID, timestamp, signature)
//! - Malformed data rejection
//! - Edge cases and boundary conditions

const std = @import("std");
const testing = std.testing;
const sct = @import("sct");

// Helper functions for building test SCTs
fn writeU16(writer: anytype, value: u16) !void {
    try writer.writeInt(u16, value, .big);
}

fn writeU64(writer: anytype, value: u64) !void {
    try writer.writeInt(u64, value, .big);
}

fn buildMinimalSct(allocator: std.mem.Allocator) ![]u8 {
    var sct_data = std.ArrayList(u8){};
    errdefer sct_data.deinit(allocator);

    // Version (1 byte) = 0
    try sct_data.writer(allocator).writeByte(0);

    // Log ID (32 bytes)
    try sct_data.writer(allocator).writeAll(&[_]u8{0x01} ** 32);

    // Timestamp (8 bytes) - Unix time in milliseconds
    try writeU64(sct_data.writer(allocator), 1609459200000); // 2021-01-01 00:00:00 UTC

    // Extensions length (2 bytes) = 0
    try writeU16(sct_data.writer(allocator), 0);

    // Hash algorithm (1 byte) = SHA-256 (4)
    try sct_data.writer(allocator).writeByte(4);

    // Signature algorithm (1 byte) = ECDSA (3)
    try sct_data.writer(allocator).writeByte(3);

    // Signature length (2 bytes) and signature data
    const sig_len: u16 = 71; // Typical ECDSA P-256 signature
    try writeU16(sct_data.writer(allocator), sig_len);
    try sct_data.writer(allocator).writeAll(&[_]u8{0xFF} ** sig_len);

    return sct_data.toOwnedSlice(allocator);
}

fn buildSctList(allocator: std.mem.Allocator, scts: []const []const u8) ![]u8 {
    var list = std.ArrayList(u8){};
    errdefer list.deinit(allocator);

    for (scts) |sct_bytes| {
        try writeU16(list.writer(allocator), @intCast(sct_bytes.len));
        try list.writer(allocator).writeAll(sct_bytes);
    }

    return list.toOwnedSlice(allocator);
}

// ============================================================================
// Basic SCT Parsing Tests
// ============================================================================

test "parseList - single minimal SCT" {
    const sct_bytes = try buildMinimalSct(testing.allocator);
    defer testing.allocator.free(sct_bytes);

    const list_bytes = try buildSctList(testing.allocator, &[_][]const u8{sct_bytes});
    defer testing.allocator.free(list_bytes);

    const parsed = try sct.parseList(testing.allocator, list_bytes);
    defer testing.allocator.free(parsed);

    try testing.expectEqual(@as(usize, 1), parsed.len);
    try testing.expectEqual(@as(u8, 0), parsed[0].version);
    try testing.expectEqual(@as(usize, 32), parsed[0].log_id.len);
    try testing.expectEqual(@as(u64, 1609459200000), parsed[0].timestamp);
    try testing.expectEqual(@as(usize, 0), parsed[0].extensions.len);
    try testing.expectEqual(@as(u8, 4), parsed[0].hash_algorithm);
    try testing.expectEqual(@as(u8, 3), parsed[0].signature_algorithm);
    try testing.expectEqual(@as(usize, 71), parsed[0].signature.len);
}

test "parseList - empty list" {
    const empty_list = [_]u8{};
    const parsed = try sct.parseList(testing.allocator, &empty_list);
    defer testing.allocator.free(parsed);
    try testing.expectEqual(@as(usize, 0), parsed.len);
}

test "parseList - multiple SCTs" {
    var scts_array: [3][]u8 = undefined;

    // Create 3 different SCTs with unique log IDs
    for (0..3) |i| {
        var sct_data = std.ArrayList(u8){};
        defer sct_data.deinit(testing.allocator);

        try sct_data.writer(testing.allocator).writeByte(0); // version

        // Unique log ID for each SCT
        var log_id: [32]u8 = undefined;
        @memset(&log_id, @intCast(i));
        try sct_data.writer(testing.allocator).writeAll(&log_id);

        try writeU64(sct_data.writer(testing.allocator), 1609459200000 + i); // unique timestamp
        try writeU16(sct_data.writer(testing.allocator), 0); // no extensions
        try sct_data.writer(testing.allocator).writeByte(4); // SHA-256
        try sct_data.writer(testing.allocator).writeByte(3); // ECDSA
        try writeU16(sct_data.writer(testing.allocator), 71); // signature length
        try sct_data.writer(testing.allocator).writeAll(&[_]u8{0xAA} ** 71); // signature

        scts_array[i] = try sct_data.toOwnedSlice(testing.allocator);
    }

    defer for (scts_array) |sct_bytes| {
        testing.allocator.free(sct_bytes);
    };

    const list_bytes = try buildSctList(testing.allocator, &scts_array);
    defer testing.allocator.free(list_bytes);

    const parsed = try sct.parseList(testing.allocator, list_bytes);
    defer testing.allocator.free(parsed);

    try testing.expectEqual(@as(usize, 3), parsed.len);

    // Verify each SCT has unique data
    for (0..3) |i| {
        try testing.expectEqual(@as(u8, @intCast(i)), parsed[i].log_id[0]);
        try testing.expectEqual(@as(u64, 1609459200000 + i), parsed[i].timestamp);
    }
}

// ============================================================================
// Field Extraction Tests
// ============================================================================

test "parseList - SCT with extensions" {
    var sct_data = std.ArrayList(u8){};
    defer sct_data.deinit(testing.allocator);

    try sct_data.writer(testing.allocator).writeByte(0); // version
    try sct_data.writer(testing.allocator).writeAll(&[_]u8{0x42} ** 32); // log ID
    try writeU64(sct_data.writer(testing.allocator), 1234567890000); // timestamp

    // Extensions with some data
    const ext_data = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    try writeU16(sct_data.writer(testing.allocator), ext_data.len);
    try sct_data.writer(testing.allocator).writeAll(&ext_data);

    try sct_data.writer(testing.allocator).writeByte(4); // SHA-256
    try sct_data.writer(testing.allocator).writeByte(3); // ECDSA
    try writeU16(sct_data.writer(testing.allocator), 71);
    try sct_data.writer(testing.allocator).writeAll(&[_]u8{0xBB} ** 71);

    const sct_bytes = try sct_data.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(sct_bytes);

    const list_bytes = try buildSctList(testing.allocator, &[_][]const u8{sct_bytes});
    defer testing.allocator.free(list_bytes);

    const parsed = try sct.parseList(testing.allocator, list_bytes);
    defer testing.allocator.free(parsed);

    try testing.expectEqual(@as(usize, 1), parsed.len);
    try testing.expectEqual(@as(usize, 4), parsed[0].extensions.len);
    try testing.expectEqualSlices(u8, &ext_data, parsed[0].extensions);
}

test "parseList - different signature algorithms" {
    const test_cases = [_]struct { hash: u8, sig: u8 }{
        .{ .hash = 4, .sig = 3 }, // SHA-256 + ECDSA
        .{ .hash = 5, .sig = 3 }, // SHA-384 + ECDSA
        .{ .hash = 6, .sig = 3 }, // SHA-512 + ECDSA
        .{ .hash = 4, .sig = 1 }, // SHA-256 + RSA
    };

    for (test_cases) |tc| {
        var sct_data = std.ArrayList(u8){};
        defer sct_data.deinit(testing.allocator);

        try sct_data.writer(testing.allocator).writeByte(0); // version
        try sct_data.writer(testing.allocator).writeAll(&[_]u8{0x55} ** 32); // log ID
        try writeU64(sct_data.writer(testing.allocator), 1609459200000);
        try writeU16(sct_data.writer(testing.allocator), 0); // no extensions
        try sct_data.writer(testing.allocator).writeByte(tc.hash);
        try sct_data.writer(testing.allocator).writeByte(tc.sig);
        try writeU16(sct_data.writer(testing.allocator), 71);
        try sct_data.writer(testing.allocator).writeAll(&[_]u8{0xCC} ** 71);

        const sct_bytes = try sct_data.toOwnedSlice(testing.allocator);
        defer testing.allocator.free(sct_bytes);

        const list_bytes = try buildSctList(testing.allocator, &[_][]const u8{sct_bytes});
        defer testing.allocator.free(list_bytes);

        const parsed = try sct.parseList(testing.allocator, list_bytes);
        defer testing.allocator.free(parsed);

        try testing.expectEqual(@as(u8, tc.hash), parsed[0].hash_algorithm);
        try testing.expectEqual(@as(u8, tc.sig), parsed[0].signature_algorithm);
    }
}

// ============================================================================
// Malformed Data Rejection Tests
// ============================================================================

test "parseList - truncated length field" {
    const bad_list = [_]u8{0x00}; // Only 1 byte of 2-byte length
    try testing.expectError(error.MalformedList, sct.parseList(testing.allocator, &bad_list));
}

test "parseList - length exceeds available data" {
    const bad_list = [_]u8{ 0x00, 0xFF, 0x00 }; // Claims 255 bytes but only has 1
    try testing.expectError(error.MalformedEntry, sct.parseList(testing.allocator, &bad_list));
}

test "parseList - zero-length SCT" {
    const bad_list = [_]u8{ 0x00, 0x00 }; // Zero-length entry
    try testing.expectError(error.MalformedEntry, sct.parseList(testing.allocator, &bad_list));
}

test "parseList - invalid version" {
    var sct_data = std.ArrayList(u8){};
    defer sct_data.deinit(testing.allocator);

    try sct_data.writer(testing.allocator).writeByte(1); // Invalid version (must be 0)
    try sct_data.writer(testing.allocator).writeAll(&[_]u8{0x00} ** 32);
    try writeU64(sct_data.writer(testing.allocator), 1609459200000);
    try writeU16(sct_data.writer(testing.allocator), 0);
    try sct_data.writer(testing.allocator).writeByte(4);
    try sct_data.writer(testing.allocator).writeByte(3);
    try writeU16(sct_data.writer(testing.allocator), 71);
    try sct_data.writer(testing.allocator).writeAll(&[_]u8{0x00} ** 71);

    const sct_bytes = try sct_data.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(sct_bytes);

    const list_bytes = try buildSctList(testing.allocator, &[_][]const u8{sct_bytes});
    defer testing.allocator.free(list_bytes);

    try testing.expectError(error.MalformedEntry, sct.parseList(testing.allocator, list_bytes));
}

test "parseList - SCT too short" {
    // SCT must be at least 43 bytes (1 + 32 + 8 + 2)
    var sct_data = std.ArrayList(u8){};
    defer sct_data.deinit(testing.allocator);

    try sct_data.writer(testing.allocator).writeByte(0); // version
    try sct_data.writer(testing.allocator).writeAll(&[_]u8{0x00} ** 32); // log ID
    // Missing rest of fields

    const sct_bytes = try sct_data.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(sct_bytes);

    const list_bytes = try buildSctList(testing.allocator, &[_][]const u8{sct_bytes});
    defer testing.allocator.free(list_bytes);

    try testing.expectError(error.MalformedEntry, sct.parseList(testing.allocator, list_bytes));
}

test "parseList - truncated signature" {
    var sct_data = std.ArrayList(u8){};
    defer sct_data.deinit(testing.allocator);

    try sct_data.writer(testing.allocator).writeByte(0);
    try sct_data.writer(testing.allocator).writeAll(&[_]u8{0x00} ** 32);
    try writeU64(sct_data.writer(testing.allocator), 1609459200000);
    try writeU16(sct_data.writer(testing.allocator), 0);
    try sct_data.writer(testing.allocator).writeByte(4);
    try sct_data.writer(testing.allocator).writeByte(3);
    try writeU16(sct_data.writer(testing.allocator), 100); // Claims 100 bytes
    try sct_data.writer(testing.allocator).writeAll(&[_]u8{0x00} ** 50); // But only provides 50

    const sct_bytes = try sct_data.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(sct_bytes);

    const list_bytes = try buildSctList(testing.allocator, &[_][]const u8{sct_bytes});
    defer testing.allocator.free(list_bytes);

    try testing.expectError(error.MalformedEntry, sct.parseList(testing.allocator, list_bytes));
}

test "parseList - zero-length signature" {
    var sct_data = std.ArrayList(u8){};
    defer sct_data.deinit(testing.allocator);

    try sct_data.writer(testing.allocator).writeByte(0);
    try sct_data.writer(testing.allocator).writeAll(&[_]u8{0x00} ** 32);
    try writeU64(sct_data.writer(testing.allocator), 1609459200000);
    try writeU16(sct_data.writer(testing.allocator), 0);
    try sct_data.writer(testing.allocator).writeByte(4);
    try sct_data.writer(testing.allocator).writeByte(3);
    try writeU16(sct_data.writer(testing.allocator), 0); // Zero-length signature

    const sct_bytes = try sct_data.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(sct_bytes);

    const list_bytes = try buildSctList(testing.allocator, &[_][]const u8{sct_bytes});
    defer testing.allocator.free(list_bytes);

    try testing.expectError(error.MalformedEntry, sct.parseList(testing.allocator, list_bytes));
}

test "parseList - extra data after SCT" {
    var sct_data = std.ArrayList(u8){};
    defer sct_data.deinit(testing.allocator);

    try sct_data.writer(testing.allocator).writeByte(0);
    try sct_data.writer(testing.allocator).writeAll(&[_]u8{0x00} ** 32);
    try writeU64(sct_data.writer(testing.allocator), 1609459200000);
    try writeU16(sct_data.writer(testing.allocator), 0);
    try sct_data.writer(testing.allocator).writeByte(4);
    try sct_data.writer(testing.allocator).writeByte(3);
    try writeU16(sct_data.writer(testing.allocator), 71);
    try sct_data.writer(testing.allocator).writeAll(&[_]u8{0x00} ** 71);
    try sct_data.writer(testing.allocator).writeAll(&[_]u8{ 0xFF, 0xFF }); // Extra data

    const sct_bytes = try sct_data.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(sct_bytes);

    const list_bytes = try buildSctList(testing.allocator, &[_][]const u8{sct_bytes});
    defer testing.allocator.free(list_bytes);

    try testing.expectError(error.MalformedEntry, sct.parseList(testing.allocator, list_bytes));
}

// ============================================================================
// Edge Cases and Boundary Conditions
// ============================================================================

test "parseList - maximum size signature" {
    var sct_data = std.ArrayList(u8){};
    defer sct_data.deinit(testing.allocator);

    try sct_data.writer(testing.allocator).writeByte(0);
    try sct_data.writer(testing.allocator).writeAll(&[_]u8{0xFF} ** 32);
    try writeU64(sct_data.writer(testing.allocator), 0xFFFFFFFFFFFFFFFF); // Max timestamp
    try writeU16(sct_data.writer(testing.allocator), 0);
    try sct_data.writer(testing.allocator).writeByte(6); // SHA-512
    try sct_data.writer(testing.allocator).writeByte(1); // RSA

    // Large RSA signature (e.g., 4096-bit RSA = 512 bytes)
    const sig_len: u16 = 512;
    try writeU16(sct_data.writer(testing.allocator), sig_len);
    var sig: [512]u8 = undefined;
    @memset(&sig, 0xEE);
    try sct_data.writer(testing.allocator).writeAll(&sig);

    const sct_bytes = try sct_data.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(sct_bytes);

    const list_bytes = try buildSctList(testing.allocator, &[_][]const u8{sct_bytes});
    defer testing.allocator.free(list_bytes);

    const parsed = try sct.parseList(testing.allocator, list_bytes);
    defer testing.allocator.free(parsed);

    try testing.expectEqual(@as(usize, 1), parsed.len);
    try testing.expectEqual(@as(u64, 0xFFFFFFFFFFFFFFFF), parsed[0].timestamp);
    try testing.expectEqual(@as(usize, 512), parsed[0].signature.len);
}

test "parseList - list with trailing data" {
    const sct_bytes = try buildMinimalSct(testing.allocator);
    defer testing.allocator.free(sct_bytes);

    var list = std.ArrayList(u8){};
    defer list.deinit(testing.allocator);

    try writeU16(list.writer(testing.allocator), @intCast(sct_bytes.len));
    try list.writer(testing.allocator).writeAll(sct_bytes);
    try list.writer(testing.allocator).writeByte(0xFF); // Extra byte after list

    const list_bytes = try list.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(list_bytes);

    try testing.expectError(error.MalformedList, sct.parseList(testing.allocator, list_bytes));
}

test "readU16 - endianness verification" {
    const bytes = [_]u8{ 0x12, 0x34 };
    const value = sct.readU16(&bytes);
    try testing.expectEqual(@as(u16, 0x1234), value);
}

test "readU64 - endianness verification" {
    const bytes = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    const value = sct.readU64(&bytes);
    try testing.expectEqual(@as(u64, 0x0123456789ABCDEF), value);
}

test "parseList - preserves reference to original buffer" {
    // Verify that returned SCTs reference the original buffer
    const sct_bytes = try buildMinimalSct(testing.allocator);
    defer testing.allocator.free(sct_bytes);

    const list_bytes = try buildSctList(testing.allocator, &[_][]const u8{sct_bytes});
    defer testing.allocator.free(list_bytes);

    const parsed = try sct.parseList(testing.allocator, list_bytes);
    defer testing.allocator.free(parsed);

    // Check that log_id points into the original buffer
    const log_id_ptr = @intFromPtr(parsed[0].log_id.ptr);
    const list_start = @intFromPtr(list_bytes.ptr);
    const list_end = @intFromPtr(list_bytes.ptr) + list_bytes.len;

    try testing.expect(log_id_ptr >= list_start);
    try testing.expect(log_id_ptr < list_end);
}
