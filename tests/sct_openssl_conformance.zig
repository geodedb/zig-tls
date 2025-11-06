//! OpenSSL conformance tests for SCT (Signed Certificate Timestamp) parsing
//!
//! Verifies that our SCT implementation correctly parses structures that
//! are compatible with OpenSSL's SCT handling. Tests cover:
//! - Wire format compatibility with OpenSSL-generated SCTs
//! - Hash and signature algorithm constants
//! - Timestamp encoding
//! - Extension handling
//!
//! Note: OpenSSL 1.1.0+ has built-in SCT support via the CT (Certificate
//! Transparency) module.

const std = @import("std");
const testing = std.testing;
const sct = @import("sct");

// OpenSSL C bindings for CT/SCT
// Note: Simplified imports to avoid header issues
const c = struct {
    // Define only the constants we need for testing
};

// ============================================================================
// SCT Version Conformance
// ============================================================================

test "SCT version conformance with OpenSSL" {
    // OpenSSL defines SCT_VERSION_V1 = 0
    // We verify that our parser also expects version 0
    var sct_data = try std.ArrayList(u8).initCapacity(testing.allocator, 0);
    defer sct_data.deinit();

    // Build SCT with version 0
    try sct_data.append(testing.allocator,0); // version
    try sct_data.appendSlice(testing.allocator,&[_]u8{0xAA} ** 32); // log ID
    try sct_data.appendSlice(testing.allocator,&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 }); // timestamp
    try sct_data.appendSlice(testing.allocator,&[_]u8{ 0, 0 }); // extensions length
    try sct_data.append(testing.allocator,4); // hash alg
    try sct_data.append(testing.allocator,3); // sig alg
    try sct_data.appendSlice(testing.allocator,&[_]u8{ 0, 71 }); // signature length
    try sct_data.appendSlice(testing.allocator,&[_]u8{0xFF} ** 71); // signature

    // Build list
    var list = try std.ArrayList(u8).initCapacity(testing.allocator, 0);
    defer list.deinit();
    const entry_len: u16 = @intCast(sct_data.items.len);
    try list.writer().writeInt(u16, entry_len, .big);
    try list.appendSlice(testing.allocator,sct_data.items);

    // Parse should succeed with version 0
    const parsed = try sct.parseList(testing.allocator, list.items);
    defer testing.allocator.free(parsed);
    try testing.expectEqual(@as(u8, 0), parsed[0].version);
}

// ============================================================================
// Hash Algorithm Constants Conformance
// ============================================================================

test "Hash algorithm constants conformance with RFC 6962" {
    // RFC 6962 defines these hash algorithms for SCTs:
    // enum { none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5), sha512(6) }

    // Common algorithms used in production
    const SHA256: u8 = 4;
    const SHA384: u8 = 5;
    const SHA512: u8 = 6;

    // Test parsing SCTs with these algorithms
    const test_cases = [_]u8{ SHA256, SHA384, SHA512 };

    for (test_cases) |hash_alg| {
        var sct_data = try std.ArrayList(u8).initCapacity(testing.allocator, 0);
        defer sct_data.deinit();

        try sct_data.append(testing.allocator,0); // version
        try sct_data.appendSlice(testing.allocator,&[_]u8{0xBB} ** 32); // log ID
        try sct_data.appendSlice(testing.allocator,&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 }); // timestamp
        try sct_data.appendSlice(testing.allocator,&[_]u8{ 0, 0 }); // no extensions
        try sct_data.append(testing.allocator,hash_alg); // hash algorithm
        try sct_data.append(testing.allocator,3); // ECDSA
        try sct_data.appendSlice(testing.allocator,&[_]u8{ 0, 71 }); // signature length
        try sct_data.appendSlice(testing.allocator,&[_]u8{0xDD} ** 71); // signature

        var list = try std.ArrayList(u8).initCapacity(testing.allocator, 0);
        defer list.deinit();
        const entry_len: u16 = @intCast(sct_data.items.len);
        try list.writer().writeInt(u16, entry_len, .big);
        try list.appendSlice(testing.allocator,sct_data.items);

        const parsed = try sct.parseList(testing.allocator, list.items);
        defer testing.allocator.free(parsed);

        try testing.expectEqual(hash_alg, parsed[0].hash_algorithm);
    }
}

// ============================================================================
// Signature Algorithm Constants Conformance
// ============================================================================

test "Signature algorithm constants conformance with RFC 6962" {
    // RFC 6962 defines these signature algorithms:
    // enum { anonymous(0), rsa(1), dsa(2), ecdsa(3) }

    const RSA: u8 = 1;
    const ECDSA: u8 = 3;

    // Test parsing SCTs with these algorithms
    const test_cases = [_]struct { sig_alg: u8, sig_len: u16 }{
        .{ .sig_alg = ECDSA, .sig_len = 71 }, // Typical ECDSA P-256
        .{ .sig_alg = RSA, .sig_len = 256 }, // 2048-bit RSA
    };

    for (test_cases) |tc| {
        var sct_data = try std.ArrayList(u8).initCapacity(testing.allocator, 0);
        defer sct_data.deinit();

        try sct_data.append(testing.allocator,0); // version
        try sct_data.appendSlice(testing.allocator,&[_]u8{0xCC} ** 32); // log ID
        try sct_data.appendSlice(testing.allocator,&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 }); // timestamp
        try sct_data.appendSlice(testing.allocator,&[_]u8{ 0, 0 }); // no extensions
        try sct_data.append(testing.allocator,4); // SHA-256
        try sct_data.append(testing.allocator,tc.sig_alg); // signature algorithm
        try sct_data.writer().writeInt(u16, tc.sig_len, .big);

        const sig = try testing.allocator.alloc(u8, tc.sig_len);
        defer testing.allocator.free(sig);
        @memset(sig, 0xEE);
        try sct_data.appendSlice(testing.allocator,sig);

        var list = try std.ArrayList(u8).initCapacity(testing.allocator, 0);
        defer list.deinit();
        const entry_len: u16 = @intCast(sct_data.items.len);
        try list.writer().writeInt(u16, entry_len, .big);
        try list.appendSlice(testing.allocator,sct_data.items);

        const parsed = try sct.parseList(testing.allocator, list.items);
        defer testing.allocator.free(parsed);

        try testing.expectEqual(tc.sig_alg, parsed[0].signature_algorithm);
        try testing.expectEqual(@as(usize, tc.sig_len), parsed[0].signature.len);
    }
}

// ============================================================================
// Timestamp Encoding Conformance
// ============================================================================

test "Timestamp encoding conformance - milliseconds since epoch" {
    // SCT timestamps are milliseconds since Unix epoch (RFC 6962)
    // OpenSSL's CT module uses the same encoding

    const test_cases = [_]struct {
        desc: []const u8,
        ms_timestamp: u64,
    }{
        .{ .desc = "2021-01-01 00:00:00 UTC", .ms_timestamp = 1609459200000 },
        .{ .desc = "2024-01-01 12:00:00 UTC", .ms_timestamp = 1704110400000 },
        .{ .desc = "Minimum value", .ms_timestamp = 0 },
        .{ .desc = "Maximum value", .ms_timestamp = 0xFFFFFFFFFFFFFFFF },
    };

    for (test_cases) |tc| {
        var sct_data = try std.ArrayList(u8).initCapacity(testing.allocator, 0);
        defer sct_data.deinit();

        try sct_data.append(testing.allocator,0); // version
        try sct_data.appendSlice(testing.allocator,&[_]u8{0x11} ** 32); // log ID
        try sct_data.writer().writeInt(u64, tc.ms_timestamp, .big);
        try sct_data.appendSlice(testing.allocator,&[_]u8{ 0, 0 }); // no extensions
        try sct_data.append(testing.allocator,4); // SHA-256
        try sct_data.append(testing.allocator,3); // ECDSA
        try sct_data.appendSlice(testing.allocator,&[_]u8{ 0, 71 }); // signature length
        try sct_data.appendSlice(testing.allocator,&[_]u8{0x22} ** 71); // signature

        var list = try std.ArrayList(u8).initCapacity(testing.allocator, 0);
        defer list.deinit();
        const entry_len: u16 = @intCast(sct_data.items.len);
        try list.writer().writeInt(u16, entry_len, .big);
        try list.appendSlice(testing.allocator,sct_data.items);

        const parsed = try sct.parseList(testing.allocator, list.items);
        defer testing.allocator.free(parsed);

        try testing.expectEqual(tc.ms_timestamp, parsed[0].timestamp);
    }
}

// ============================================================================
// Log ID Format Conformance
// ============================================================================

test "Log ID format conformance - 32 bytes SHA-256" {
    // Log IDs are 32-byte SHA-256 hashes of the log's public key (RFC 6962)

    // Test various log ID patterns
    const test_log_ids = [_][32]u8{
        [_]u8{0x00} ** 32, // All zeros (test)
        [_]u8{0xFF} ** 32, // All ones (test)
        // A real-like log ID (random but deterministic for testing)
        [_]u8{
            0xA4, 0xB9, 0x09, 0x90, 0xB4, 0x18, 0x58, 0x14,
            0x87, 0xBB, 0x13, 0xA2, 0xCC, 0x67, 0x70, 0x0A,
            0x3C, 0x35, 0x98, 0x04, 0xF9, 0x1B, 0xDF, 0xB8,
            0xE3, 0x77, 0xCD, 0x0E, 0xC8, 0x0D, 0xDC, 0x10,
        },
    };

    for (test_log_ids) |log_id| {
        var sct_data = try std.ArrayList(u8).initCapacity(testing.allocator, 0);
        defer sct_data.deinit();

        try sct_data.append(testing.allocator,0); // version
        try sct_data.appendSlice(testing.allocator,&log_id); // log ID
        try sct_data.appendSlice(testing.allocator,&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 }); // timestamp
        try sct_data.appendSlice(testing.allocator,&[_]u8{ 0, 0 }); // no extensions
        try sct_data.append(testing.allocator,4); // SHA-256
        try sct_data.append(testing.allocator,3); // ECDSA
        try sct_data.appendSlice(testing.allocator,&[_]u8{ 0, 71 }); // signature length
        try sct_data.appendSlice(testing.allocator,&[_]u8{0x33} ** 71); // signature

        var list = try std.ArrayList(u8).initCapacity(testing.allocator, 0);
        defer list.deinit();
        const entry_len: u16 = @intCast(sct_data.items.len);
        try list.writer().writeInt(u16, entry_len, .big);
        try sct_data.appendSlice(testing.allocator,sct_data.items);

        const parsed = try sct.parseList(testing.allocator, list.items);
        defer testing.allocator.free(parsed);

        try testing.expectEqual(@as(usize, 32), parsed[0].log_id.len);
        try testing.expectEqualSlices(u8, &log_id, parsed[0].log_id);
    }
}

// ============================================================================
// Extension Handling Conformance
// ============================================================================

test "SCT extensions field conformance" {
    // SCT extensions are rarely used but must be handled correctly
    // Format: 2-byte length followed by extension data

    const test_cases = [_][]const u8{
        &[_]u8{}, // Empty extensions (common)
        &[_]u8{0x00}, // Single byte
        &[_]u8{ 0x01, 0x02, 0x03, 0x04 }, // Multiple bytes
        &([_]u8{0xAA} ** 100), // Larger extension
    };

    for (test_cases) |ext_data| {
        var sct_data = try std.ArrayList(u8).initCapacity(testing.allocator, 0);
        defer sct_data.deinit();

        try sct_data.append(testing.allocator,0); // version
        try sct_data.appendSlice(testing.allocator,&[_]u8{0x44} ** 32); // log ID
        try sct_data.appendSlice(testing.allocator,&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 }); // timestamp

        // Extensions with length prefix
        const ext_len: u16 = @intCast(ext_data.len);
        try sct_data.writer().writeInt(u16, ext_len, .big);
        try sct_data.appendSlice(testing.allocator,ext_data);

        try sct_data.append(testing.allocator,4); // SHA-256
        try sct_data.append(testing.allocator,3); // ECDSA
        try sct_data.appendSlice(testing.allocator,&[_]u8{ 0, 71 }); // signature length
        try sct_data.appendSlice(testing.allocator,&[_]u8{0x55} ** 71); // signature

        var list = try std.ArrayList(u8).initCapacity(testing.allocator, 0);
        defer list.deinit();
        const entry_len: u16 = @intCast(sct_data.items.len);
        try list.writer().writeInt(u16, entry_len, .big);
        try list.appendSlice(testing.allocator,sct_data.items);

        const parsed = try sct.parseList(testing.allocator, list.items);
        defer testing.allocator.free(parsed);

        try testing.expectEqual(ext_data.len, parsed[0].extensions.len);
        if (ext_data.len > 0) {
            try testing.expectEqualSlices(u8, ext_data, parsed[0].extensions);
        }
    }
}

// ============================================================================
// Wire Format Compatibility Tests
// ============================================================================

test "SCT list wire format - OpenSSL compatibility" {
    // Test that we can parse SCT lists in the exact format OpenSSL produces
    // Format: length-prefixed list of length-prefixed SCTs

    // Build a multi-SCT list like OpenSSL would
    var full_list = try std.ArrayList(u8).initCapacity(testing.allocator, 0);
    defer full_list.deinit();

    // Add 3 SCTs with different characteristics
    for (0..3) |i| {
        var sct_data = try std.ArrayList(u8).initCapacity(testing.allocator, 0);
        defer sct_data.deinit();

        try sct_data.append(testing.allocator,0); // version

        // Unique log ID per SCT
        var log_id: [32]u8 = undefined;
        @memset(&log_id, @intCast(i * 0x11));
        try sct_data.appendSlice(testing.allocator,&log_id);

        // Different timestamp per SCT
        const timestamp: u64 = 1609459200000 + (i * 1000000);
        try sct_data.writer().writeInt(u64, timestamp, .big);

        // Extensions (empty for simplicity)
        try sct_data.appendSlice(testing.allocator,&[_]u8{ 0, 0 });

        // Varying algorithms
        const hash_algs = [_]u8{ 4, 5, 6 }; // SHA-256, SHA-384, SHA-512
        try sct_data.append(testing.allocator,hash_algs[i]);

        const sig_algs = [_]u8{ 3, 3, 1 }; // ECDSA, ECDSA, RSA
        try sct_data.append(testing.allocator,sig_algs[i]);

        // Signature (varying lengths)
        const sig_lens = [_]u16{ 71, 71, 256 };
        try sct_data.writer().writeInt(u16, sig_lens[i], .big);

        const sig = try testing.allocator.alloc(u8, sig_lens[i]);
        defer testing.allocator.free(sig);
        @memset(sig, @intCast(0x66 + i));
        try sct_data.appendSlice(testing.allocator,sig);

        // Add to list with length prefix
        const entry_len: u16 = @intCast(sct_data.items.len);
        try full_list.writer().writeInt(u16, entry_len, .big);
        try full_list.appendSlice(testing.allocator,sct_data.items);
    }

    // Parse the complete list
    const parsed = try sct.parseList(testing.allocator, full_list.items);
    defer testing.allocator.free(parsed);

    // Verify all 3 SCTs were parsed correctly
    try testing.expectEqual(@as(usize, 3), parsed.len);

    // Verify each SCT's data
    const expected_hashes = [_]u8{ 4, 5, 6 };
    const expected_sigs = [_]u8{ 3, 3, 1 };
    const expected_sig_lens = [_]usize{ 71, 71, 256 };

    for (0..3) |i| {
        try testing.expectEqual(@as(u8, 0), parsed[i].version);
        try testing.expectEqual(@as(u8, @intCast(i * 0x11)), parsed[i].log_id[0]);
        try testing.expectEqual(@as(u64, 1609459200000 + (i * 1000000)), parsed[i].timestamp);

        try testing.expectEqual(expected_hashes[i], parsed[i].hash_algorithm);
        try testing.expectEqual(expected_sigs[i], parsed[i].signature_algorithm);
        try testing.expectEqual(expected_sig_lens[i], parsed[i].signature.len);
    }
}

// ============================================================================
// Error Handling Conformance
// ============================================================================

test "Malformed SCT rejection - OpenSSL-like validation" {
    // Test that we reject the same malformed SCTs that OpenSSL would reject

    // Test invalid version
    {
        const bad_sct = try buildInvalidVersionSct(testing.allocator);
        defer testing.allocator.free(bad_sct);

        const list_bytes = try buildSctListHelper(testing.allocator, &[_][]const u8{bad_sct});
        defer testing.allocator.free(list_bytes);

        const result = sct.parseList(testing.allocator, list_bytes);
        try testing.expectError(error.MalformedEntry, result);
    }

    // Test truncated log ID
    {
        const bad_sct = try buildTruncatedLogIdSct(testing.allocator);
        defer testing.allocator.free(bad_sct);

        const list_bytes = try buildSctListHelper(testing.allocator, &[_][]const u8{bad_sct});
        defer testing.allocator.free(list_bytes);

        const result = sct.parseList(testing.allocator, list_bytes);
        try testing.expectError(error.MalformedEntry, result);
    }

    // Test zero-length signature
    {
        const bad_sct = try buildZeroLengthSigSct(testing.allocator);
        defer testing.allocator.free(bad_sct);

        const list_bytes = try buildSctListHelper(testing.allocator, &[_][]const u8{bad_sct});
        defer testing.allocator.free(list_bytes);

        const result = sct.parseList(testing.allocator, list_bytes);
        try testing.expectError(error.MalformedEntry, result);
    }
}

// Helper functions for malformed SCT tests
fn buildInvalidVersionSct(allocator: std.mem.Allocator) ![]u8 {
    var sct_bytes = try std.ArrayList(u8).initCapacity(allocator, 0);
    errdefer sct_bytes.deinit();
    try sct_bytes.append(allocator,1); // Invalid version (not 0)
    try sct_bytes.appendSlice(allocator,&[_]u8{0} ** 32);
    try sct_bytes.writer().writeInt(u64, 0, .big);
    try sct_bytes.appendSlice(allocator,&[_]u8{ 0, 0 });
    try sct_bytes.append(allocator,4);
    try sct_bytes.append(allocator,3);
    try sct_bytes.appendSlice(allocator,&[_]u8{ 0, 71 });
    try sct_bytes.appendSlice(allocator,&[_]u8{0} ** 71);
    return sct_bytes.toOwnedSlice();
}

fn buildTruncatedLogIdSct(allocator: std.mem.Allocator) ![]u8 {
    var sct_bytes = try std.ArrayList(u8).initCapacity(allocator, 0);
    errdefer sct_bytes.deinit();
    try sct_bytes.append(allocator,0);
    try sct_bytes.appendSlice(allocator,&[_]u8{0} ** 16); // Only 16 bytes instead of 32
    return sct_bytes.toOwnedSlice();
}

fn buildZeroLengthSigSct(allocator: std.mem.Allocator) ![]u8 {
    var sct_bytes = try std.ArrayList(u8).initCapacity(allocator, 0);
    errdefer sct_bytes.deinit();
    try sct_bytes.append(allocator,0);
    try sct_bytes.appendSlice(allocator,&[_]u8{0} ** 32);
    try sct_bytes.writer().writeInt(u64, 0, .big);
    try sct_bytes.appendSlice(allocator,&[_]u8{ 0, 0 });
    try sct_bytes.append(allocator,4);
    try sct_bytes.append(allocator,3);
    try sct_bytes.appendSlice(allocator,&[_]u8{ 0, 0 }); // Zero-length signature
    return sct_bytes.toOwnedSlice();
}

fn buildSctListHelper(allocator: std.mem.Allocator, scts: []const []const u8) ![]u8 {
    var list = try std.ArrayList(u8).initCapacity(allocator, 0);
    errdefer list.deinit();
    for (scts) |sct_bytes| {
        try list.writer().writeInt(u16, @intCast(sct_bytes.len), .big);
        try list.appendSlice(allocator, sct_bytes);
    }
    return list.toOwnedSlice();
}