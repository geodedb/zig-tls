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
    var exts = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer exts.deinit(allocator);

    // ALPN
    if (alpn) |proto| {
        var alpn_data = try std.ArrayList(u8).initCapacity(allocator, 0);
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
    var msg = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer msg.deinit(allocator);

    // Extensions length
    try msg.appendSlice(allocator, &[_]u8{
        @intCast(exts.items.len >> 8),
        @intCast(exts.items.len & 0xff),
    });
    try msg.appendSlice(allocator, exts.items);

    return msg.toOwnedSlice(allocator);
}
