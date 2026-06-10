// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUAL-317: pure byte parsers for ServerHello post-struct helpers.
//!
//! These used to live at file scope in src/tls13/context.zig after the
//! Context struct. Moved here verbatim with no semantic change. SEC-057
//! enum-guard pattern preserved (std.enums.fromInt on peer wire bytes
//! where applicable — these specific parsers use @intFromEnum comparison,
//! not fromInt).

const std = @import("std");
const tls13_full = @import("tls13_full");
const types = @import("../types.zig");

const HandshakeError = types.HandshakeError;
const readU16 = tls13_full.readU16;
const ExtensionType = tls13_full.ExtensionType;

/// Validate the supported_versions extension in a ServerHello extensions block.
///
/// RFC 8446 Section 4.2.1: The ServerHello MUST contain a supported_versions
/// extension with the selected version set to 0x0304 (TLS 1.3).
///
/// TEST-ONLY MIRROR: this function has NO production caller — the live
/// ServerHello path is `Context.handleServerHello` (which carries the
/// authoritative supported_versions + raw-u16 duplicate-extension logic).
/// This helper exists only as a focused, directly-drivable fixture for the
/// SEC-092 regression tests below; keep its dedup logic in sync with
/// `handleServerHello`. It scans the extensions starting at the given offset
/// within the body and checks:
///   - The supported_versions extension (0x002B) is present
///   - Its data is exactly 2 bytes (selected version)
///   - The selected version is 0x0304 (TLS 1.3)
///
/// Returns the selected version if valid, or an error otherwise.
///
/// SEC-092 (subsumes SEC-078): The walk also enforces RFC 8446 §4.2 — every
/// extension type may appear at most once in a given block. A duplicate
/// type returns `HandshakeError.DuplicateExtension`.
pub fn validateSupportedVersions(body: []const u8, ext_start: usize, exts_len: usize) HandshakeError!u16 {
    var pos = ext_start;
    const exts_end = ext_start + exts_len;
    if (exts_end > body.len) return HandshakeError.UnexpectedMessage;

    var found = false;
    var version: u16 = 0;
    // NEWGAP-05: raw-u16 tracking rejects duplicate UNKNOWN extension types
    // too (RFC 8446 §4.2), not just known ones.
    var seen_extensions: [tls13_full.MAX_EXTENSION_TYPES]u16 = undefined;
    var seen_count: usize = 0;
    while (pos + 4 <= exts_end) {
        const etype = readU16(body[pos .. pos + 2]);
        const elen: usize = readU16(body[pos + 2 .. pos + 4]);
        pos += 4;
        if (pos + elen > exts_end) return HandshakeError.UnexpectedMessage;
        for (seen_extensions[0..seen_count]) |s| {
            if (s == etype) return HandshakeError.DuplicateExtension;
        }
        if (seen_count == seen_extensions.len) return HandshakeError.TooManyExtensions;
        seen_extensions[seen_count] = etype;
        seen_count += 1;
        if (etype == @intFromEnum(tls13_full.ExtensionType.supported_versions)) {
            if (elen != 2) return HandshakeError.UnsupportedVersion;
            version = readU16(body[pos .. pos + 2]);
            if (version != 0x0304) return HandshakeError.UnsupportedVersion;
            found = true;
        }
        pos += elen;
    }
    if (!found) return HandshakeError.UnsupportedVersion;
    return version;
}

/// Parse pre_shared_key extension from a ServerHello body.
/// Returns the selected PSK identity index if found, null otherwise.
/// This mirrors the parsing logic in handleServerHello for testability.
///
/// SEC-092 (subsumes SEC-078): walk now rejects duplicate extension types
/// per RFC 8446 §4.2 with `HandshakeError.DuplicateExtension`.
pub fn parsePskExtension(body: []const u8) !?u16 {
    if (body.len < 2 + 32 + 1) return HandshakeError.UnexpectedMessage;
    var pos: usize = 2 + 32; // skip legacy_version + random
    if (pos >= body.len) return HandshakeError.UnexpectedMessage;
    const sid_len: usize = body[pos];
    pos += 1 + sid_len;
    if (pos + 2 + 1 > body.len) return HandshakeError.UnexpectedMessage;
    pos += 2; // cipher_suite
    pos += 1; // compression
    if (pos + 2 > body.len) return HandshakeError.UnexpectedMessage;
    const exts_len: usize = readU16(body[pos .. pos + 2]);
    pos += 2;
    if (pos + exts_len > body.len) return HandshakeError.UnexpectedMessage;
    const exts_end = pos + exts_len;
    var selected_psk_index: ?u16 = null;
    // NEWGAP-05: raw-u16 tracking rejects duplicate UNKNOWN extension types
    // too (RFC 8446 §4.2), not just known ones.
    var seen_extensions: [tls13_full.MAX_EXTENSION_TYPES]u16 = undefined;
    var seen_count: usize = 0;
    while (pos + 4 <= exts_end) {
        const etype = readU16(body[pos .. pos + 2]);
        const elen: usize = readU16(body[pos + 2 .. pos + 4]);
        pos += 4;
        if (pos + elen > exts_end) return HandshakeError.UnexpectedMessage;
        for (seen_extensions[0..seen_count]) |s| {
            if (s == etype) return HandshakeError.DuplicateExtension;
        }
        if (seen_count == seen_extensions.len) return HandshakeError.TooManyExtensions;
        seen_extensions[seen_count] = etype;
        seen_count += 1;
        if (etype == @intFromEnum(tls13_full.ExtensionType.pre_shared_key)) {
            if (elen != 2) return HandshakeError.UnexpectedMessage;
            selected_psk_index = readU16(body[pos .. pos + 2]);
        }
        pos += elen;
    }
    return selected_psk_index;
}

// ---- Tests ported from src/tls13/context.zig (4 tests) ----

test "RFC 8446 §4.2.1: ServerHello supported_versions=0x0304 is accepted" {
    // Build a minimal extensions block with supported_versions=0x0304 and key_share
    var exts: [50]u8 = [_]u8{0} ** 50;
    // supported_versions: type=0x002b, len=0x0002, value=0x0304
    exts[0] = 0x00;
    exts[1] = 0x2b;
    exts[2] = 0x00;
    exts[3] = 0x02;
    exts[4] = 0x03;
    exts[5] = 0x04;

    const version = try validateSupportedVersions(&exts, 0, 6);
    try std.testing.expectEqual(@as(u16, 0x0304), version);
}

test "RFC 8446 §4.2.1: ServerHello missing supported_versions returns error" {
    // Build extensions block with only key_share (0x0033), no supported_versions
    var exts: [44]u8 = [_]u8{0} ** 44;
    // key_share: type=0x0033, len=0x0024 (36 bytes), group=0x001d, klen=0x0020, key=32 zeros
    exts[0] = 0x00;
    exts[1] = 0x33;
    exts[2] = 0x00;
    exts[3] = 0x24;
    exts[4] = 0x00;
    exts[5] = 0x1d;
    exts[6] = 0x00;
    exts[7] = 0x20;
    // key data is already zeroed

    const result = validateSupportedVersions(&exts, 0, 40);
    try std.testing.expectError(HandshakeError.UnsupportedVersion, result);
}

test "RFC 8446 §4.2.1: ServerHello supported_versions with non-TLS-1.3 version returns error" {
    // Build extensions block with supported_versions=0x0303 (TLS 1.2)
    var exts: [6]u8 = [_]u8{0} ** 6;
    exts[0] = 0x00;
    exts[1] = 0x2b;
    exts[2] = 0x00;
    exts[3] = 0x02;
    exts[4] = 0x03;
    exts[5] = 0x03; // TLS 1.2

    const result = validateSupportedVersions(&exts, 0, 6);
    try std.testing.expectError(HandshakeError.UnsupportedVersion, result);
}

test "RFC 8446 §4.2.1: ServerHello supported_versions with wrong length returns error" {
    // Build extensions block with supported_versions with 3-byte data (invalid)
    var exts: [7]u8 = [_]u8{0} ** 7;
    exts[0] = 0x00;
    exts[1] = 0x2b;
    exts[2] = 0x00;
    exts[3] = 0x03; // wrong length (should be 2)
    exts[4] = 0x03;
    exts[5] = 0x04;
    exts[6] = 0x00;

    const result = validateSupportedVersions(&exts, 0, 7);
    try std.testing.expectError(HandshakeError.UnsupportedVersion, result);
}

// ---- New boundary-condition tests ----

test "validateSupportedVersions: exts_end past body rejected" {
    var exts: [4]u8 = [_]u8{ 0x00, 0x2b, 0x00, 0x02 };
    const result = validateSupportedVersions(&exts, 0, 10); // exts_len=10 but body=4
    try std.testing.expectError(HandshakeError.UnexpectedMessage, result);
}

test "parsePskExtension: absent returns null" {
    var body: [100]u8 = [_]u8{0} ** 100;
    body[2 + 32] = 0; // sid_len = 0
    body[35 + 2] = 0x00;
    body[35 + 3] = 0x00; // exts_len = 0
    const result = try parsePskExtension(&body);
    try std.testing.expect(result == null);
}

test "parsePskExtension: present returns selected index" {
    var body: [100]u8 = [_]u8{0} ** 100;
    var p: usize = 0;
    body[p] = 0x03;
    body[p + 1] = 0x03;
    p += 2; // legacy_version
    p += 32; // random
    body[p] = 0;
    p += 1; // sid_len
    p += 2; // cipher_suite
    p += 1; // compression
    body[p] = 0x00;
    body[p + 1] = 0x06;
    p += 2; // exts_len = 6
    body[p] = 0x00;
    body[p + 1] = 0x29;
    p += 2; // pre_shared_key (0x0029)
    body[p] = 0x00;
    body[p + 1] = 0x02;
    p += 2; // ext_len = 2
    body[p] = 0x00;
    body[p + 1] = 0x07;
    p += 2; // idx = 7
    const result = try parsePskExtension(body[0..p]);
    try std.testing.expectEqual(@as(?u16, 7), result);
}

test "parsePskExtension: truncated body rejected" {
    var short: [30]u8 = [_]u8{0} ** 30;
    try std.testing.expectError(HandshakeError.UnexpectedMessage, parsePskExtension(&short));
}

test "parsePskExtension: wrong PSK ext length rejected" {
    var body: [100]u8 = [_]u8{0} ** 100;
    var p: usize = 2 + 32;
    body[p] = 0;
    p += 1;
    p += 3;
    body[p] = 0x00;
    body[p + 1] = 0x06;
    p += 2;
    body[p] = 0x00;
    body[p + 1] = 0x29;
    p += 2;
    body[p] = 0x00;
    body[p + 1] = 0x03;
    p += 2; // wrong len = 3
    body[p] = 0;
    body[p + 1] = 0;
    body[p + 2] = 0;
    p += 3;
    try std.testing.expectError(HandshakeError.UnexpectedMessage, parsePskExtension(body[0..p]));
}

test "validateSupportedVersions: trailing truncated ext after valid supported_versions accepts version" {
    var exts: [8]u8 = [_]u8{0} ** 8;
    exts[0] = 0x00;
    exts[1] = 0x2b;
    exts[2] = 0x00;
    exts[3] = 0x02;
    exts[4] = 0x03;
    exts[5] = 0x04;
    exts[6] = 0x00;
    exts[7] = 0x33; // next ext type (truncated — no length)
    const version = try validateSupportedVersions(&exts, 0, 8);
    try std.testing.expectEqual(@as(u16, 0x0304), version);
}

// ---- SEC-092: ServerHello duplicate-extension regressions ----

test "SEC-092: validateSupportedVersions rejects duplicate supported_versions" {
    // Two adjacent supported_versions extensions of the same type.
    const exts = [_]u8{
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, // #1
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, // #2
    };
    const result = validateSupportedVersions(&exts, 0, exts.len);
    try std.testing.expectError(HandshakeError.DuplicateExtension, result);
}

test "SEC-092: parsePskExtension rejects duplicate pre_shared_key" {
    const exts = [_]u8{
        0x00, 0x29, 0x00, 0x02, 0x00, 0x00, // pre_shared_key #1
        0x00, 0x29, 0x00, 0x02, 0x00, 0x00, // pre_shared_key #2
    };
    var body = std.ArrayList(u8).empty;
    defer body.deinit(std.testing.allocator);
    try body.appendSlice(std.testing.allocator, &.{ 0x03, 0x03 }); // legacy_version
    try body.appendNTimes(std.testing.allocator, 0xA5, 32); // random
    try body.append(std.testing.allocator, 0); // session_id_len = 0
    try body.appendSlice(std.testing.allocator, &.{ 0x13, 0x01 }); // cipher_suite
    try body.append(std.testing.allocator, 0); // compression
    try body.append(std.testing.allocator, @intCast(exts.len >> 8));
    try body.append(std.testing.allocator, @intCast(exts.len & 0xff));
    try body.appendSlice(std.testing.allocator, &exts);

    try std.testing.expectError(HandshakeError.DuplicateExtension, parsePskExtension(body.items));
}

test "SEC-092: validateSupportedVersions accepts non-duplicate" {
    // supported_versions followed by key_share (different types) — no dup.
    const exts = [_]u8{
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
        0x00, 0x33, 0x00, 0x00, // key_share with empty payload
    };
    const v = try validateSupportedVersions(&exts, 0, exts.len);
    try std.testing.expectEqual(@as(u16, 0x0304), v);
}
