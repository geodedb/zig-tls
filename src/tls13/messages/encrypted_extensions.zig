// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! TLS 1.3 EncryptedExtensions Message
//!
//! Implements EncryptedExtensions message construction per RFC 8446 §4.3.1.
//! This message contains server extensions that are not needed for key exchange
//! and are encrypted with handshake traffic keys.
//!
//! ## RFC Coverage
//!
//! - RFC 8446 §4.3.1: EncryptedExtensions structure
//! - RFC 9001 §8.2: QUIC transport parameters placement (MUST be in EncryptedExtensions)
//! - RFC 7301: ALPN extension format
//!
//! ## Message Flow
//!
//! EncryptedExtensions is sent by the server immediately after ServerHello:
//! ```
//! Server                                           Client
//!   ServerHello           -------->
//!     + key_share
//!     + supported_versions
//!   EncryptedExtensions   -------->
//!     + alpn
//!     + quic_transport_parameters
//!   Certificate           -------->
//!   ...
//! ```
//!
//! ## Security Considerations
//!
//! - This message is encrypted with handshake_traffic_secret
//! - Extensions here are authenticated but not visible to passive observers
//! - QUIC parameters include critical transport settings (initial flow control, etc.)

const std = @import("std");
const helpers = @import("helpers.zig");
const core_types = @import("core_types.zig");

/// Build EncryptedExtensions message (RFC 8446 §4.3.1).
///
/// Constructs an EncryptedExtensions message containing server extensions
/// that are not needed for key exchange. This message is encrypted with
/// handshake traffic keys.
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for message buffer
/// - `alpn`: Selected ALPN protocol (e.g., "h3" for HTTP/3)
/// - `quic_params`: QUIC transport parameters (RFC 9001 §8.2, REQUIRED for QUIC)
///
/// ## Returns
///
/// - `[]u8`: Serialized EncryptedExtensions message (caller owns memory, must free)
///
/// ## Message Format (RFC 8446 §4.3.1)
///
/// ```
/// struct {
///     Extension extensions<0..2^16-1>;
/// } EncryptedExtensions;
/// ```
///
/// ## Extensions Included
///
/// - **alpn** (0x0010): Selected application protocol (RFC 7301)
/// - **quic_transport_parameters** (0x0039): QUIC transport parameters (RFC 9001 §8.2)
///
/// ## ALPN Format (RFC 7301)
///
/// The ALPN extension contains a single selected protocol:
/// ```
/// opaque ProtocolName<1..2^8-1>;
/// struct {
///     ProtocolName protocol_name_list<2..2^16-1>;
/// } ProtocolNameList;
/// ```
///
/// For HTTP/3, the protocol name is "h3" (2 bytes).
///
/// ## QUIC Transport Parameters (RFC 9001 §8.2)
///
/// QUIC transport parameters MUST appear in EncryptedExtensions (not ServerHello):
/// - Extension type: 0x0039 (quic_transport_parameters)
/// - Contains server's initial flow control limits, max streams, etc.
/// - Format defined in RFC 9000 §18 (Transport Parameter Encoding)
///
/// ## RFC Compliance
///
/// - RFC 8446 §4.3.1: EncryptedExtensions structure
/// - RFC 9001 §8.2: QUIC transport parameters MUST appear in EncryptedExtensions (not ServerHello)
/// - RFC 7301: ALPN extension format
///
/// ## Security Notes
///
/// - This message is encrypted with handshake_traffic_secret
/// - Extensions here are authenticated but not visible to passive observers
/// - QUIC parameters include critical transport settings (initial flow control, etc.)
///
/// ## Usage
///
/// ```zig
/// const ee_msg = try buildEncryptedExtensions(
///     allocator,
///     "h3",              // ALPN for HTTP/3
///     quic_params_bytes  // Encoded QUIC transport parameters
/// );
/// defer allocator.free(ee_msg);
/// ```
pub fn buildEncryptedExtensions(
    allocator: std.mem.Allocator,
    alpn: ?[]const u8,
    quic_params: ?[]const u8,
) ![]u8 {
    // PERF-031: Pre-size for typical extension data (~64 bytes for ALPN + QUIC params).
    var exts = try std.ArrayList(u8).initCapacity(allocator, 64);
    defer exts.deinit(allocator);

    // ALPN
    if (alpn) |proto| {
        // PERF-031: Pre-size for ALPN list: 2-byte list_len + 1-byte proto_len + proto bytes.
        var alpn_data = try std.ArrayList(u8).initCapacity(allocator, 3 + proto.len);
        defer alpn_data.deinit(allocator);

        const alpn_list_len = 1 + proto.len;
        try alpn_data.appendSlice(allocator, &[_]u8{
            @intCast(alpn_list_len >> 8),
            @intCast(alpn_list_len & 0xff),
        });
        try alpn_data.append(allocator, @intCast(proto.len));
        try alpn_data.appendSlice(allocator, proto);

        try helpers.writeExtension(allocator, &exts, .alpn, alpn_data.items);
    }

    // QUIC transport parameters
    if (quic_params) |params| {
        try helpers.writeExtension(allocator, &exts, .quic_transport_parameters, params);
    }

    // Build the message
    // PERF-031: Pre-size for 2-byte extensions length + extension data.
    var msg = try std.ArrayList(u8).initCapacity(allocator, 2 + exts.items.len);
    defer msg.deinit(allocator);

    // Extensions length
    try msg.appendSlice(allocator, &[_]u8{
        @intCast(exts.items.len >> 8),
        @intCast(exts.items.len & 0xff),
    });
    try msg.appendSlice(allocator, exts.items);

    return msg.toOwnedSlice(allocator);
}

/// EncryptedExtensions parsing result.
///
/// Contains the parsed ALPN protocol and QUIC transport parameters
/// extracted from an EncryptedExtensions message.
pub const EncryptedExtensions = struct {
    /// Selected ALPN protocol (e.g., "h3")
    /// This is a view into the input buffer, not owned memory
    alpn: ?[]const u8 = null,

    /// QUIC transport parameters from extension 0x0039
    /// This is a view into the input buffer, not owned memory
    quic_transport_parameters: ?[]const u8 = null,
};

/// Parse EncryptedExtensions message (RFC 8446 §4.3.1).
///
/// Extracts ALPN and QUIC transport parameters from an EncryptedExtensions message.
/// This function does not allocate memory; all returned slices are views into the input buffer.
///
/// ## Parameters
///
/// - `body`: The EncryptedExtensions message body (after the handshake message header)
///
/// ## Returns
///
/// - `EncryptedExtensions`: Parsed extension data (views into input buffer)
///
/// ## Errors
///
/// - `error.TooShort`: Message too short to contain valid EncryptedExtensions
/// - `error.MalformedExtensions`: Extension data is corrupted
///
/// ## RFC Compliance
///
/// - RFC 8446 §4.3.1: EncryptedExtensions structure
/// - RFC 9001 §8.2: QUIC transport parameters MUST appear in EncryptedExtensions
/// - RFC 7301: ALPN extension format
///
/// ## Message Format
///
/// ```
/// struct {
///     Extension extensions<0..2^16-1>;
/// } EncryptedExtensions;
/// ```
pub fn parseEncryptedExtensions(body: []const u8) !EncryptedExtensions {
    var result = EncryptedExtensions{};

    // Minimum size: 2 bytes for extensions length
    if (body.len < 2) return error.TooShort;

    // Read extensions length
    const ext_len = helpers.readU16(body[0..2]);
    if (body.len < 2 + ext_len) return error.TooShort;

    // Parse extensions
    var offset: usize = 2;
    const ext_end = 2 + ext_len;

    // SEC-092 / GAP-0145 (subsumes SEC-078): RFC 8446 §4.2 forbids duplicate extension
    // types in the same block. Track known types via an EnumSet so a
    // crafted EE message cannot leak a previously-stored extension pointer
    // by overwriting it with a second copy.
    // We use a fixed-size array of raw u16 types to ensure unknown extensions are
    // also tracked and rejected if duplicated, preventing GAP-0145 evasion.
    var seen: [core_types.MAX_EXTENSION_TYPES]u16 = undefined;
    var seen_count: usize = 0;

    while (offset < ext_end) {
        // Need at least 4 bytes for type (2) and length (2)
        if (offset + 4 > ext_end) return error.MalformedExtensions;

        const ext_type = helpers.readU16(body[offset .. offset + 2]);
        const data_len = helpers.readU16(body[offset + 2 .. offset + 4]);
        offset += 4;

        if (offset + data_len > ext_end) return error.MalformedExtensions;

        const ext_data = body[offset .. offset + data_len];
        offset += data_len;

        // GAP-0145: Reject duplicate extension types.
        for (seen[0..seen_count]) |s| {
            if (s == ext_type) return error.DuplicateExtension;
        }
        // APPSEC-04: capacity cap is distinct from a duplicate.
        if (seen_count == seen.len) return error.TooManyExtensions;
        seen[seen_count] = ext_type;
        seen_count += 1;

        // NEWGAP-09: RFC 8446 §4.3.1 — the client MUST reject any extension in
        // EncryptedExtensions that is not permitted there. We deny the
        // extensions defined for ClientHello/ServerHello/HRR/CertificateRequest
        // (and friends) that have no place in EE; unknown/GREASE types remain
        // ignorable for forward compatibility (they are not "forbidden").
        switch (ext_type) {
            0x000d, // signature_algorithms (CH, CR)
            0x0029, // pre_shared_key (CH, SH)
            0x002b, // supported_versions (CH, SH, HRR)
            0x002c, // cookie (CH, HRR)
            0x002d, // psk_key_exchange_modes (CH)
            0x002f, // certificate_authorities (CH, CR)
            0x0030, // oid_filters (CR)
            0x0031, // post_handshake_auth (CH)
            0x0032, // signature_algorithms_cert (CH, CR)
            0x0033, // key_share (CH, SH, HRR)
            => return error.ForbiddenExtension,
            else => {},
        }

        switch (ext_type) {
            // ALPN (0x0010) - RFC 7301
            0x0010 => {
                // ALPN format: ProtocolNameList with 2-byte length prefix
                if (ext_data.len < 2) continue;
                const list_len = helpers.readU16(ext_data[0..2]);
                if (ext_data.len < 2 + list_len) continue;

                // Parse first protocol in the list (server selects one)
                if (list_len > 0) {
                    const proto_len = ext_data[2];
                    if (2 + 1 + proto_len <= ext_data.len) {
                        result.alpn = ext_data[3 .. 3 + proto_len];
                    }
                }
            },
            // QUIC transport parameters (0x0039) - RFC 9001 §8.2
            0x0039 => {
                result.quic_transport_parameters = ext_data;
            },
            // Skip unknown extensions (forward compatibility)
            else => {},
        }
    }

    return result;
}
