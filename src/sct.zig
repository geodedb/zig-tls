// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Signed Certificate Timestamp (SCT) parsing utilities (RFC 6962)
//!
//! Provides basic parsing of the SCT list delivered via the
//! signed_certificate_timestamp TLS extension. Verification of SCT signatures
//! is delegated to the application via higher-level callbacks.
const std = @import("std");

pub const SctError = error{
    MalformedList,
    MalformedEntry,
    OutOfMemory,
};

pub const SignedCertificateTimestamp = struct {
    version: u8,
    log_id: []const u8,
    timestamp: u64,
    extensions: []const u8,
    hash_algorithm: u8,
    signature_algorithm: u8,
    signature: []const u8,
};

// Canonical readU16 lives in tls13/messages/helpers.zig.
// These thin wrappers delegate to std.mem.readInt to avoid
// duplicating the manual bit-shift logic and to avoid pulling
// in the heavyweight tls13_full module dependency.
pub fn readU16(bytes: []const u8) u16 {
    return std.mem.readInt(u16, bytes[0..2], .big);
}

pub fn readU64(bytes: []const u8) u64 {
    return std.mem.readInt(u64, bytes[0..8], .big);
}

/// Parse a SignedCertificateTimestampList (without the outer length field) into
/// an owned slice of SCT views. Each view references the original `list`
/// buffer; callers must retain `list` for the lifetime of the returned slice.
pub fn parseList(allocator: std.mem.Allocator, list: []const u8) SctError![]SignedCertificateTimestamp {
    var items = std.ArrayList(SignedCertificateTimestamp).empty;
    errdefer items.deinit(allocator);

    var offset: usize = 0;
    while (offset < list.len) {
        if (offset + 2 > list.len) return SctError.MalformedList;
        const sct_len = readU16(list[offset .. offset + 2]);
        offset += 2;
        if (sct_len == 0 or offset + sct_len > list.len) return SctError.MalformedEntry;
        const sct_bytes = list[offset .. offset + sct_len];
        offset += sct_len;

        if (sct_bytes.len < 43) return SctError.MalformedEntry; // minimum length
        var pos: usize = 0;
        const version = sct_bytes[pos];
        pos += 1;
        if (version != 0) return SctError.MalformedEntry;

        const log_id = sct_bytes[pos .. pos + 32];
        pos += 32;

        const timestamp = readU64(sct_bytes[pos .. pos + 8]);
        pos += 8;

        if (pos + 2 > sct_bytes.len) return SctError.MalformedEntry;
        const ext_len = readU16(sct_bytes[pos .. pos + 2]);
        pos += 2;
        if (pos + ext_len > sct_bytes.len) return SctError.MalformedEntry;
        const extensions = sct_bytes[pos .. pos + ext_len];
        pos += ext_len;

        if (pos + 2 > sct_bytes.len) return SctError.MalformedEntry;
        const hash_alg = sct_bytes[pos];
        pos += 1;
        const sig_alg = sct_bytes[pos];
        pos += 1;

        if (pos + 2 > sct_bytes.len) return SctError.MalformedEntry;
        const sig_len = readU16(sct_bytes[pos .. pos + 2]);
        pos += 2;
        if (sig_len == 0 or pos + sig_len > sct_bytes.len) return SctError.MalformedEntry;
        const signature = sct_bytes[pos .. pos + sig_len];
        pos += sig_len;

        if (pos != sct_bytes.len) return SctError.MalformedEntry;

        try items.append(allocator, .{
            .version = version,
            .log_id = log_id,
            .timestamp = timestamp,
            .extensions = extensions,
            .hash_algorithm = hash_alg,
            .signature_algorithm = sig_alg,
            .signature = signature,
        });
    }

    if (offset != list.len) return SctError.MalformedList;
    return try items.toOwnedSlice(allocator);
}
