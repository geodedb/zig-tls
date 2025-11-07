//! TLS 1.3 ServerHello Message
//!
//! Implements ServerHello message construction per RFC 8446 §4.1.3.
//! ServerHello is the server's response to ClientHello, containing the
//! selected cipher suite, key share, and supported version.
//!
//! ## RFC Coverage
//!
//! - RFC 8446 §4.1.3: ServerHello structure
//! - RFC 8446 §4.2.8: key_share extension (MANDATORY for ECDHE)
//! - RFC 8446 §4.2.1: supported_versions extension (MANDATORY for TLS 1.3)
//! - RFC 9001 §8.2: QUIC transport parameters MUST NOT appear in ServerHello
//!
//! ## Message Flow
//!
//! ServerHello is sent immediately after receiving ClientHello:
//! ```
//! Client                                           Server
//!   ClientHello           -------->
//!                         <--------  ServerHello
//!                                      + key_share
//!                                      + supported_versions
//!                         <--------  EncryptedExtensions
//!                         <--------  Certificate
//!                         ...
//! ```
//!
//! ## Security Considerations
//!
//! - Extension order is CRITICAL for transcript hash consistency
//! - Session ID echo required for middlebox compatibility
//! - Downgrade protection via random sentinel (not implemented in this function)

const std = @import("std");
const core_types = @import("core_types.zig");
const helpers = @import("helpers.zig");

/// Build a TLS 1.3 ServerHello message (RFC 8446 §4.1.3).
///
/// Constructs a ServerHello in wire format, containing the server's chosen
/// cipher suite, key share, and supported version. Extension order is CRITICAL
/// for transcript hash consistency (affects interoperability).
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for message buffer
/// - `server_random`: 32-byte server random value
/// - `cipher_suite`: Selected cipher suite (must be from client's list)
/// - `key_share_group`: Selected named group for ECDHE (must be from client's supported_groups)
/// - `key_share_data`: Server's ephemeral public key for the selected group
/// - `client_session_id`: Echo of client's session ID (RFC 8446 §4.1.3 middlebox compatibility)
/// - `quic_params`: IGNORED (transport params go in EncryptedExtensions per RFC 9001 §8.2)
///
/// ## Returns
///
/// - `[]u8`: Serialized ServerHello message (caller owns memory, must free)
///
/// ## Message Format (RFC 8446 §4.1.3)
///
/// ```
/// struct {
///     ProtocolVersion legacy_version = 0x0303; // TLS 1.2 for compatibility
///     Random random;                            // 32 bytes
///     opaque legacy_session_id_echo<0..32>;    // Echo from ClientHello
///     CipherSuite cipher_suite;                 // Selected cipher suite
///     uint8 legacy_compression_method = 0;     // Always 0 in TLS 1.3
///     Extension extensions<6..2^16-1>;         // MUST contain key_share + supported_versions
/// } ServerHello;
/// ```
///
/// ## Extension Order (CRITICAL for Interop)
///
/// This implementation follows BoringSSL/Quiche extension order for transcript hash compatibility:
/// 1. **key_share** (0x0033): Server's ECDHE public key
/// 2. **supported_versions** (0x002b): TLS 1.3 version (0x0304)
///
/// Changing this order will break handshake with implementations that hardcode expected order!
///
/// ## Key Share Extension (RFC 8446 §4.2.8)
///
/// The key_share extension contains the server's ephemeral public key:
/// ```
/// struct {
///     NamedGroup group;                // Selected group (e.g., 0x001d for X25519)
///     opaque key_exchange<1..2^16-1>;  // Public key bytes
/// } KeyShareServerHello;
/// ```
///
/// For X25519, key_exchange is 32 bytes.
///
/// ## RFC Compliance
///
/// - RFC 8446 §4.1.3: ServerHello structure
/// - RFC 8446 §4.2.8: key_share extension (MANDATORY for ECDHE)
/// - RFC 8446 §4.2.1: supported_versions extension (MANDATORY for TLS 1.3)
/// - RFC 9001 §8.2: QUIC transport parameters MUST NOT appear in ServerHello
///
/// ## Security Considerations
///
/// - legacy_version set to 0x0303 (TLS 1.2) for middlebox compatibility
/// - legacy_compression_method set to 0x00 (no compression in TLS 1.3)
/// - Session ID echoed from client for middlebox compatibility (RFC 8446 §4.1.3)
/// - Downgrade protection (random sentinel) not implemented in this function
///
/// ## Transcript Hash Impact
///
/// Extension order affects the transcript hash:
/// ```
/// transcript_hash = SHA256(ClientHello || ServerHello)
/// ```
///
/// Different extension orders produce different ServerHello bytes, which changes
/// the transcript hash and breaks handshake verification!
///
/// ## Usage
///
/// ```zig
/// const server_hello = try buildServerHello(
///     allocator,
///     server_random,
///     .TLS_AES_128_GCM_SHA256,
///     .x25519,
///     server_public_key,
///     client_session_id,
///     null  // quic_params ignored (goes in EncryptedExtensions)
/// );
/// defer allocator.free(server_hello);
/// ```
pub fn buildServerHello(
    allocator: std.mem.Allocator,
    server_random: [32]u8,
    cipher_suite: core_types.CipherSuite,
    key_share_group: core_types.NamedGroup,
    key_share_data: []const u8,
    client_session_id: ?[]const u8,
    quic_params: ?[]const u8,
) ![]u8 {
    var msg = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer msg.deinit(allocator);

    // Legacy version (TLS 1.2 for compatibility)
    try msg.appendSlice(allocator, &[_]u8{ 0x03, 0x03 });

    // Random
    try msg.appendSlice(allocator, &server_random);

    // Legacy session ID (echo from client per RFC 8446 Section 4.1.3)
    if (client_session_id) |session_id| {
        // Echo the client's session ID
        try msg.append(allocator, @intCast(session_id.len));
        try msg.appendSlice(allocator, session_id);
    } else {
        // No session ID from client
        try msg.append(allocator, 0);
    }

    // Cipher suite
    const cs_value = @intFromEnum(cipher_suite);
    try msg.appendSlice(allocator, &[_]u8{
        @intCast(cs_value >> 8),
        @intCast(cs_value & 0xff),
    });

    // Legacy compression method
    try msg.append(allocator, 0);

    // Extensions
    var exts = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer exts.deinit(allocator);

    // CRITICAL: Extension order must match BoringSSL/Quiche for interoperability.
    // BoringSSL order (ssl/tls13_server.cc:938-941):
    //   1. pre_shared_key (if resuming)
    //   2. pake (if using PAKE)
    //   3. key_share
    //   4. supported_versions
    // We only support key_share and supported_versions, so our order is:
    //   1. key_share
    //   2. supported_versions
    // This is CRITICAL because transcript hash = SHA256(ClientHello || ServerHello)
    // and extension order affects the byte representation.

    // key_share (mandatory for ECDHE) - MUST BE FIRST (after PSK/PAKE if present)
    var ks_data = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer ks_data.deinit(allocator);
    const group_value = @intFromEnum(key_share_group);
    try ks_data.appendSlice(allocator, &[_]u8{
        @intCast(group_value >> 8),
        @intCast(group_value & 0xff),
    });
    try ks_data.appendSlice(allocator, &[_]u8{
        @intCast(key_share_data.len >> 8),
        @intCast(key_share_data.len & 0xff),
    });
    try ks_data.appendSlice(allocator, key_share_data);
    try helpers.writeExtension(allocator, &exts, .key_share, ks_data.items);

    // supported_versions (mandatory for TLS 1.3) - MUST BE AFTER key_share
    try helpers.writeExtension(allocator, &exts, .supported_versions, &[_]u8{ 0x03, 0x04 }); // TLS 1.3

    // NOTE: RFC 9001 §8.2 mandates that quic_transport_parameters goes in
    // EncryptedExtensions, NOT ServerHello. The quic_params parameter is
    // ignored here (and should always be null). Transport parameters are
    // added in buildEncryptedExtensions() instead.
    _ = quic_params; // Explicitly ignore to make it clear this is intentional

    // Write extensions length
    try msg.appendSlice(allocator, &[_]u8{
        @intCast(exts.items.len >> 8),
        @intCast(exts.items.len & 0xff),
    });
    try msg.appendSlice(allocator, exts.items);

    return msg.toOwnedSlice(allocator);
}
