// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! TLS 1.3 Certificate Message
//!
//! Implements Certificate message parsing and construction per RFC 8446 §4.4.2.
//! The Certificate message contains the endpoint's certificate chain and
//! optional per-entry extensions (OCSP stapling, SCT).
//!
//! ## RFC Coverage
//!
//! - RFC 8446 §4.4.2: Certificate message structure
//! - RFC 8446 §4.4.2.1: OCSP status_request extension
//! - RFC 6960: OCSP (Online Certificate Status Protocol)
//! - RFC 6962 §3.3: Signed Certificate Timestamp (SCT) extension
//! - RFC 5280: X.509 certificate format
//!
//! ## Message Flow
//!
//! Certificate is sent by the server (and optionally client) during the handshake:
//! ```
//! Server                                           Client
//!   ...
//!   EncryptedExtensions
//!   Certificate           -------->
//!   CertificateVerify     -------->
//!   Finished              -------->
//!                         <--------  Finished
//! ```
//!
//! ## Security Considerations
//!
//! - Certificate must be validated (see x509.zig)
//! - OCSP stapling provides revocation status
//! - SCT provides transparency log proof

const std = @import("std");
const helpers = @import("helpers.zig");

/// Parsed TLS 1.3 Certificate message with per-entry extension data (RFC 8446 §4.4.2).
///
/// The Certificate message contains a certificate chain (leaf first) and
/// optional per-certificate extensions like OCSP responses and SCTs.
///
/// ## Message Format
///
/// ```
/// struct {
///     opaque certificate_request_context<0..2^8-1>;
///     CertificateEntry certificate_list<0..2^24-1>;
/// } Certificate;
///
/// struct {
///     opaque cert_data<1..2^24-1>;     // DER-encoded X.509 certificate
///     Extension extensions<0..2^16-1>; // Per-certificate extensions
/// } CertificateEntry;
/// ```
///
/// ## Certificate Request Context
///
/// - Empty (0 bytes) for server Certificate
/// - Non-empty for client Certificate in response to CertificateRequest
/// - Used to match Certificate to CertificateRequest (RFC 8446 §4.4.2)
///
/// ## Certificate List Order
///
/// The certificate chain is sent in order:
/// 1. Leaf certificate (endpoint's certificate)
/// 2. Intermediate CA certificates
/// 3. (Optional) Root CA certificate
///
/// ## Per-Certificate Extensions (RFC 8446 §4.4.2.1)
///
/// - **status_request** (0x0005): OCSP response (RFC 6066 §8, RFC 6960)
/// - **signed_certificate_timestamp** (0x0012): SCT list (RFC 6962 §3.3)
///
/// ## Usage
///
/// ```zig
/// const cert_msg = try parseCertificate(allocator, cert_msg_bytes);
/// defer {
///     allocator.free(cert_msg.entries);
/// }
///
/// for (cert_msg.entries) |entry| {
///     // Validate entry.cert using x509.zig
///     if (entry.ocsp_response) |ocsp| {
///         // Verify OCSP response
///     }
///     if (entry.sct_list) |sct| {
///         // Verify SCT
///     }
/// }
/// ```
pub const ParsedCertificateMessage = struct {
    context: []const u8,
    entries: []CertificateEntryData,
};

/// Certificate entry containing DER and optional OCSP/SCT extensions (RFC 8446 §4.4.2).
///
/// Each certificate in the chain can have per-certificate extensions for
/// OCSP stapling and Signed Certificate Timestamps (SCT).
///
/// ## Fields
///
/// - `cert`: DER-encoded X.509 certificate (RFC 5280)
/// - `ocsp_response`: OCSP response bytes (RFC 6960), if stapled
/// - `sct_list`: SignedCertificateTimestampList (RFC 6962 §3.3), if present
///
/// ## OCSP Response Format (RFC 6960)
///
/// The OCSP response is a DER-encoded OCSPResponse structure containing
/// the certificate's revocation status.
///
/// ## SCT List Format (RFC 6962 §3.3)
///
/// The SCT list is a serialized SignedCertificateTimestampList containing
/// one or more SCTs from Certificate Transparency logs.
pub const CertificateEntryData = struct {
    cert: []const u8,
    ocsp_response: ?[]const u8 = null,
    sct_list: ?[]const u8 = null,
};

/// Parse a TLS 1.3 Certificate message including OCSP stapling and SCT extensions (RFC 8446 §4.4.2).
///
/// Parses the Certificate message wire format, extracting the certificate chain
/// and per-entry extensions (OCSP, SCT).
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for entry array
/// - `data`: Certificate message bytes (without Handshake header)
///
/// ## Returns
///
/// - `ParsedCertificateMessage`: Parsed structure with certificate chain
/// - `error.TooShort`: Message too short to be valid
/// - `error.MalformedCertificateList`: Invalid certificate list encoding
/// - `error.MalformedStatusRequest`: Invalid OCSP response format
/// - `error.UnsupportedStatusType`: Non-OCSP status type (only OCSP supported)
/// - `error.MalformedSctList`: Invalid SCT list format
///
/// ## Wire Format
///
/// ```
/// uint8 certificate_request_context_length;
/// opaque certificate_request_context[certificate_request_context_length];
/// uint24 certificate_list_length;
/// CertificateEntry certificate_list[certificate_list_length];
/// ```
///
/// Each CertificateEntry:
/// ```
/// uint24 cert_data_length;
/// opaque cert_data[cert_data_length];
/// uint16 extensions_length;
/// Extension extensions[extensions_length];
/// ```
///
/// ## Memory Management
///
/// - Allocates: `entries` array (caller must free)
/// - Zero-copy: All slices reference input buffer (must remain valid)
///
/// ## RFC Compliance
///
/// - RFC 8446 §4.4.2: Certificate message structure
/// - RFC 8446 §4.4.2.1: OCSP status_request extension
/// - RFC 6960: OCSP response format
/// - RFC 6962 §3.3: SCT extension format
pub fn parseCertificate(
    allocator: std.mem.Allocator,
    data: []const u8,
) !ParsedCertificateMessage {
    if (data.len < 4) return error.TooShort;

    var pos: usize = 0;
    const ctx_len = data[pos];
    pos += 1;
    if (pos + ctx_len > data.len) return error.TooShort;
    const context = data[pos .. pos + ctx_len];
    pos += ctx_len;

    if (pos + 3 > data.len) return error.TooShort;
    const list_len_u24 = helpers.readU24(data[pos .. pos + 3]);
    const list_len: usize = @intCast(list_len_u24);
    pos += 3;
    if (pos + list_len > data.len) return error.MalformedCertificateList;
    const list_end = pos + list_len;

    var entries = try std.ArrayList(CertificateEntryData).initCapacity(allocator, 0);
    errdefer entries.deinit(allocator);

    while (pos < list_end) {
        if (pos + 3 > list_end) return error.MalformedCertificateList;
        const cert_len_u24 = helpers.readU24(data[pos .. pos + 3]);
        const cert_len: usize = @intCast(cert_len_u24);
        pos += 3;
        if (pos + cert_len > list_end) return error.MalformedCertificateList;
        const cert_slice = data[pos .. pos + cert_len];
        pos += cert_len;

        if (pos + 2 > list_end) return error.MalformedCertificateList;
        const ext_len = helpers.readU16(data[pos .. pos + 2]);
        pos += 2;
        if (pos + ext_len > list_end) return error.MalformedCertificateList;
        const ext_slice = data[pos .. pos + ext_len];
        pos += ext_len;

        var ocsp_resp: ?[]const u8 = null;
        var sct_list: ?[]const u8 = null;

        var ext_pos: usize = 0;
        while (ext_pos + 4 <= ext_len) {
            const ext_type = helpers.readU16(ext_slice[ext_pos .. ext_pos + 2]);
            const ext_size = helpers.readU16(ext_slice[ext_pos + 2 .. ext_pos + 4]);
            ext_pos += 4;
            if (ext_pos + ext_size > ext_len) return error.MalformedCertificateList;
            const ext_value = ext_slice[ext_pos .. ext_pos + ext_size];

            switch (ext_type) {
                0x0005 => { // status_request (RFC 6066 §8, RFC 8446 §4.4.2.1)
                    if (ext_value.len < 4) return error.MalformedStatusRequest;
                    const status_type = ext_value[0];
                    if (status_type != 1) return error.UnsupportedStatusType; // only OCSP supported
                    const resp_len = (@as(usize, ext_value[1]) << 16) | (@as(usize, ext_value[2]) << 8) | ext_value[3];
                    if (resp_len + 4 > ext_value.len or resp_len == 0) return error.MalformedStatusRequest;
                    ocsp_resp = ext_value[4 .. 4 + resp_len];
                },
                0x0012 => { // signed_certificate_timestamp (RFC 6962 §3.3)
                    if (ext_value.len < 2) return error.MalformedSctList;
                    const sct_vec_len = helpers.readU16(ext_value[0..2]);
                    if (sct_vec_len == 0 or sct_vec_len + 2 != ext_value.len) return error.MalformedSctList;
                    sct_list = ext_value[2 .. 2 + sct_vec_len];
                },
                else => {},
            }

            ext_pos += ext_size;
        }

        if (ext_pos != ext_len) return error.MalformedCertificateList;
        try entries.append(allocator, .{ .cert = cert_slice, .ocsp_response = ocsp_resp, .sct_list = sct_list });
    }

    if (pos != list_end) return error.MalformedCertificateList;

    return .{
        .context = context,
        .entries = try entries.toOwnedSlice(allocator),
    };
}

/// Build Certificate message (RFC 8446 §4.4.2) with optional OCSP and SCT extensions.
///
/// Constructs a Certificate message containing the certificate chain and per-entry
/// extensions for OCSP stapling (status_request) and Signed Certificate Timestamps.
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for message buffer
/// - `context`: Certificate request context (empty for server, non-empty for client response)
/// - `entries`: Certificate chain with optional OCSP/SCT data
///
/// ## Returns
///
/// - `[]u8`: Serialized Certificate message (caller owns memory, must free)
/// - `error.CertificateContextTooLong`: Context exceeds 255 bytes
/// - `error.CertificateTooLarge`: Individual certificate exceeds 16MB (2^24-1)
/// - `error.OcspResponseTooLarge`: OCSP response too large
/// - `error.SctListTooLarge`: SCT list too large
/// - `error.CertificateExtensionsTooLarge`: Total extensions exceed 64KB
/// - `error.CertificateListTooLarge`: Total certificate list exceeds 16MB
///
/// ## Wire Format
///
/// ```
/// uint8 certificate_request_context_length;
/// opaque certificate_request_context[certificate_request_context_length];
/// uint24 certificate_list_length;
/// // For each entry:
/// uint24 cert_data_length;
/// opaque cert_data[cert_data_length];
/// uint16 extensions_length;
/// Extension extensions[extensions_length];
/// ```
///
/// ## OCSP Stapling Extension (RFC 6066 §8)
///
/// ```
/// Extension:
///   type: 0x0005 (status_request)
///   data:
///     uint8 status_type = 1 (OCSP)
///     uint24 ocsp_response_length
///     opaque ocsp_response[ocsp_response_length]
/// ```
///
/// ## SCT Extension (RFC 6962 §3.3)
///
/// ```
/// Extension:
///   type: 0x0012 (signed_certificate_timestamp)
///   data:
///     uint16 sct_list_length
///     opaque sct_list[sct_list_length]
/// ```
///
/// ## Usage
///
/// ```zig
/// const entries = [_]CertificateEntryData{
///     .{ .cert = leaf_cert_der, .ocsp_response = ocsp_bytes, .sct_list = sct_bytes },
///     .{ .cert = intermediate_cert_der },
/// };
/// const cert_msg = try buildCertificate(allocator, &[_]u8{}, &entries);
/// defer allocator.free(cert_msg);
/// ```
pub fn buildCertificate(
    allocator: std.mem.Allocator,
    context: []const u8,
    entries: []const CertificateEntryData,
) ![]u8 {
    if (context.len > 255) return error.CertificateContextTooLong;

    var msg = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer msg.deinit(allocator);

    // certificate_request_context length (1 byte) + value
    try msg.append(allocator, @intCast(context.len));
    if (context.len > 0) try msg.appendSlice(allocator, context);

    // Precompute certificate_list length to encode as u24
    var total_len: usize = 0;
    for (entries) |entry| {
        const cert_len = entry.cert.len;
        if (cert_len > 0xFFFFFF) return error.CertificateTooLarge;

        var ext_len: usize = 0;
        if (entry.ocsp_response) |resp| {
            if (resp.len == 0 or resp.len > 0xFFFFFF) return error.OcspResponseTooLarge;
            const payload_len = 1 + 3 + resp.len;
            if (payload_len > 0xFFFF) return error.OcspResponseTooLarge;
            ext_len += 4 + payload_len; // extension header + payload
        }
        if (entry.sct_list) |sct| {
            if (sct.len == 0 or sct.len > 0xFFFF) return error.SctListTooLarge;
            const payload_len = 2 + sct.len;
            ext_len += 4 + payload_len;
        }
        if (ext_len > 0xFFFF) return error.CertificateExtensionsTooLarge;

        total_len += 3 + cert_len + 2 + ext_len;
    }

    if (total_len > 0xFFFFFF) return error.CertificateListTooLarge;
    try msg.appendSlice(allocator, &[_]u8{
        @intCast((total_len >> 16) & 0xff),
        @intCast((total_len >> 8) & 0xff),
        @intCast(total_len & 0xff),
    });

    // Emit certificate entries with extensions
    for (entries) |entry| {
        const cert_len = entry.cert.len;
        try msg.appendSlice(allocator, &[_]u8{
            @intCast((cert_len >> 16) & 0xff),
            @intCast((cert_len >> 8) & 0xff),
            @intCast(cert_len & 0xff),
        });
        try msg.appendSlice(allocator, entry.cert);

        var ext_len: usize = 0;
        if (entry.ocsp_response) |resp| {
            const payload_len = 1 + 3 + resp.len;
            ext_len += 4 + payload_len;
        }
        if (entry.sct_list) |sct| {
            const payload_len = 2 + sct.len;
            ext_len += 4 + payload_len;
        }

        try msg.appendSlice(allocator, &[_]u8{ @intCast(ext_len >> 8), @intCast(ext_len & 0xff) });

        if (entry.ocsp_response) |resp| {
            const payload_len = 1 + 3 + resp.len;
            try msg.appendSlice(allocator, &[_]u8{ 0x00, 0x05 });
            try msg.appendSlice(allocator, &[_]u8{ @intCast(payload_len >> 8), @intCast(payload_len & 0xff) });
            try msg.append(allocator, 0x01);
            try msg.appendSlice(allocator, &[_]u8{
                @intCast(resp.len >> 16),
                @intCast((resp.len >> 8) & 0xff),
                @intCast(resp.len & 0xff),
            });
            try msg.appendSlice(allocator, resp);
        }

        if (entry.sct_list) |sct| {
            const payload_len = 2 + sct.len;
            try msg.appendSlice(allocator, &[_]u8{ 0x00, 0x12 });
            try msg.appendSlice(allocator, &[_]u8{ @intCast(payload_len >> 8), @intCast(payload_len & 0xff) });
            try msg.appendSlice(allocator, &[_]u8{ @intCast(sct.len >> 8), @intCast(sct.len & 0xff) });
            try msg.appendSlice(allocator, sct);
        }
    }

    return msg.toOwnedSlice(allocator);
}
