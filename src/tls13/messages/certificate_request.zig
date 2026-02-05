// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! TLS 1.3 CertificateRequest Message
//!
//! Implements CertificateRequest message construction and parsing per RFC 8446 §4.3.2.
//! The CertificateRequest message is sent by the server to request client authentication.
//!
//! ## RFC Coverage
//!
//! - RFC 8446 §4.3.2: CertificateRequest message structure
//! - RFC 8446 §4.2.3: signature_algorithms extension (required in CertificateRequest)
//! - RFC 8446 §4.2.4: certificate_authorities extension (optional)
//!
//! ## Message Flow (mTLS)
//!
//! ```
//! Server                                           Client
//!   EncryptedExtensions
//!   CertificateRequest    -------->
//!   Certificate           -------->
//!   CertificateVerify     -------->
//!   Finished              -------->
//!                         <--------  Certificate
//!                         <--------  CertificateVerify
//!                         <--------  Finished
//! ```
//!
//! ## Wire Format (RFC 8446 §4.3.2)
//!
//! ```
//! struct {
//!     opaque certificate_request_context<0..2^8-1>;
//!     Extension extensions<2..2^16-1>;
//! } CertificateRequest;
//! ```
//!
//! The extensions MUST include signature_algorithms (0x000d).

const std = @import("std");
const core_types = @import("core_types.zig");
const helpers = @import("helpers.zig");

/// Parsed CertificateRequest message (RFC 8446 §4.3.2).
pub const ParsedCertificateRequest = struct {
    /// Opaque context for matching Certificate response.
    /// Empty for initial handshake, non-empty for post-handshake (not used in QUIC).
    context: []const u8,
    /// Signature algorithms the server is willing to accept (from signature_algorithms extension).
    signature_algorithms: []const core_types.SignatureScheme,
};

/// Build a CertificateRequest message body (RFC 8446 §4.3.2).
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for message buffer
/// - `sig_schemes`: Signature algorithms the server accepts
/// - `ca_certs`: Optional CA certificates for certificate_authorities extension
///
/// ## Returns
///
/// - `[]u8`: Serialized CertificateRequest body (caller owns, must free)
///
/// ## Wire Format
///
/// ```
/// [context_len:1][context:0][extensions_len:2][extensions...]
/// ```
///
/// Extensions always include signature_algorithms (0x000d, required).
pub fn buildCertificateRequest(
    allocator: std.mem.Allocator,
    sig_schemes: []const core_types.SignatureScheme,
    ca_certs: ?[]const []const u8,
) ![]u8 {
    var msg = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer msg.deinit(allocator);

    // certificate_request_context: empty for initial handshake (RFC 8446 §4.3.2)
    try msg.append(allocator, 0); // context length = 0

    // Build extensions
    var exts = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer exts.deinit(allocator);

    // signature_algorithms extension (0x000d) - REQUIRED
    // Format: [list_len:2][scheme1:2][scheme2:2]...
    {
        var sig_data = try std.ArrayList(u8).initCapacity(allocator, 0);
        defer sig_data.deinit(allocator);

        const list_len: u16 = @intCast(sig_schemes.len * 2);
        try sig_data.appendSlice(allocator, &[_]u8{
            @intCast(list_len >> 8),
            @intCast(list_len & 0xff),
        });
        for (sig_schemes) |scheme| {
            const val = @intFromEnum(scheme);
            try sig_data.appendSlice(allocator, &[_]u8{
                @intCast(val >> 8),
                @intCast(val & 0xff),
            });
        }

        try helpers.writeExtension(allocator, &exts, .signature_algorithms, sig_data.items);
    }

    // certificate_authorities extension (0x002f) - OPTIONAL
    if (ca_certs) |certs| {
        if (certs.len > 0) {
            var ca_data = try std.ArrayList(u8).initCapacity(allocator, 0);
            defer ca_data.deinit(allocator);

            // Compute total length of DN list
            var total_len: usize = 0;
            for (certs) |cert| {
                total_len += 2 + cert.len; // 2-byte length prefix + cert data
            }

            // Write DN list length (2 bytes)
            try ca_data.appendSlice(allocator, &[_]u8{
                @intCast((total_len >> 8) & 0xff),
                @intCast(total_len & 0xff),
            });

            // Write each CA cert as a DistinguishedName
            for (certs) |cert| {
                try ca_data.appendSlice(allocator, &[_]u8{
                    @intCast((cert.len >> 8) & 0xff),
                    @intCast(cert.len & 0xff),
                });
                try ca_data.appendSlice(allocator, cert);
            }

            try helpers.writeExtension(allocator, &exts, .certificate_authorities, ca_data.items);
        }
    }

    // Write extensions length (2 bytes) + extensions data
    const ext_len: u16 = @intCast(exts.items.len);
    try msg.appendSlice(allocator, &[_]u8{
        @intCast(ext_len >> 8),
        @intCast(ext_len & 0xff),
    });
    try msg.appendSlice(allocator, exts.items);

    return msg.toOwnedSlice(allocator);
}

/// Parse a CertificateRequest message body (RFC 8446 §4.3.2).
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for signature_algorithms array
/// - `data`: CertificateRequest message body (without Handshake header)
///
/// ## Returns
///
/// - `ParsedCertificateRequest`: Parsed context and signature algorithms
///   - `signature_algorithms` is allocated (caller must free)
///   - `context` references input data (no allocation)
///
/// ## Errors
///
/// - `error.TooShort`: Message too short
/// - `error.MalformedCertificateRequest`: Invalid encoding
pub fn parseCertificateRequest(
    allocator: std.mem.Allocator,
    data: []const u8,
) !ParsedCertificateRequest {
    if (data.len < 3) return error.TooShort; // 1 byte context_len + 2 bytes ext_len minimum

    var pos: usize = 0;

    // Parse certificate_request_context
    const ctx_len: usize = data[pos];
    pos += 1;
    if (pos + ctx_len > data.len) return error.TooShort;
    const context = data[pos .. pos + ctx_len];
    pos += ctx_len;

    // Parse extensions length
    if (pos + 2 > data.len) return error.TooShort;
    const ext_len: usize = helpers.readU16(data[pos .. pos + 2]);
    pos += 2;
    if (pos + ext_len > data.len) return error.MalformedCertificateRequest;
    const ext_end = pos + ext_len;

    // Parse extensions to find signature_algorithms
    var sig_algs = try std.ArrayList(core_types.SignatureScheme).initCapacity(allocator, 0);
    errdefer sig_algs.deinit(allocator);

    while (pos + 4 <= ext_end) {
        const etype = helpers.readU16(data[pos .. pos + 2]);
        const elen: usize = helpers.readU16(data[pos + 2 .. pos + 4]);
        pos += 4;
        if (pos + elen > ext_end) return error.MalformedCertificateRequest;

        if (etype == 0x000d) { // signature_algorithms
            if (elen < 2) return error.MalformedCertificateRequest;
            const list_len: usize = helpers.readU16(data[pos .. pos + 2]);
            var spos: usize = pos + 2;
            const send = pos + 2 + list_len;
            if (send > pos + elen) return error.MalformedCertificateRequest;

            while (spos + 2 <= send) {
                const scheme_val = helpers.readU16(data[spos .. spos + 2]);
                spos += 2;
                const scheme = std.meta.intToEnum(core_types.SignatureScheme, scheme_val) catch continue;
                try sig_algs.append(allocator, scheme);
            }
        }

        pos += elen;
    }

    return ParsedCertificateRequest{
        .context = context,
        .signature_algorithms = try sig_algs.toOwnedSlice(allocator),
    };
}

// ============================================================================
// Tests
// ============================================================================

test "CertificateRequest: build and parse roundtrip" {
    const alloc = std.testing.allocator;

    const schemes = [_]core_types.SignatureScheme{ .ed25519, .ecdsa_secp256r1_sha256 };
    const body = try buildCertificateRequest(alloc, &schemes, null);
    defer alloc.free(body);

    const parsed = try parseCertificateRequest(alloc, body);
    defer alloc.free(parsed.signature_algorithms);

    try std.testing.expectEqual(@as(usize, 0), parsed.context.len);
    try std.testing.expectEqual(@as(usize, 2), parsed.signature_algorithms.len);
    try std.testing.expectEqual(core_types.SignatureScheme.ed25519, parsed.signature_algorithms[0]);
    try std.testing.expectEqual(core_types.SignatureScheme.ecdsa_secp256r1_sha256, parsed.signature_algorithms[1]);
}

test "CertificateRequest: build with CA certs" {
    const alloc = std.testing.allocator;

    const schemes = [_]core_types.SignatureScheme{.ed25519};
    const ca_cert = [_]u8{ 0x30, 0x82, 0x01, 0x00 }; // Mock DER
    const ca_certs = [_][]const u8{&ca_cert};
    const body = try buildCertificateRequest(alloc, &schemes, &ca_certs);
    defer alloc.free(body);

    const parsed = try parseCertificateRequest(alloc, body);
    defer alloc.free(parsed.signature_algorithms);

    try std.testing.expectEqual(@as(usize, 1), parsed.signature_algorithms.len);
    try std.testing.expectEqual(core_types.SignatureScheme.ed25519, parsed.signature_algorithms[0]);
}

test "CertificateRequest: parse too short" {
    const alloc = std.testing.allocator;
    const short = [_]u8{0x00};
    const result = parseCertificateRequest(alloc, &short);
    try std.testing.expectError(error.TooShort, result);
}
