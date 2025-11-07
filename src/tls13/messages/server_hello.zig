//! TLS 1.3 ServerHello Message
//!
//! Implements ServerHello message construction per RFC 8446 §4.1.3.
//! ServerHello is the server's response to ClientHello, containing the
//! selected cipher suite, key share, and supported version.
//!
//! HelloRetryRequest (RFC 8446 §4.1.4) is a special case of ServerHello
//! with a specific random value, used when the server needs the client
//! to retry with different parameters (e.g., a different named group).
//!
//! ## RFC Coverage
//!
//! - RFC 8446 §4.1.3: ServerHello structure
//! - RFC 8446 §4.1.4: HelloRetryRequest (special ServerHello)
//! - RFC 8446 §4.2.2: Cookie extension (for HelloRetryRequest)
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

// ============================================================================
// HelloRetryRequest and Downgrade Protection Constants (RFC 8446)
// ============================================================================

/// RFC 8446 §4.1.3: Special random value identifying HelloRetryRequest.
///
/// HelloRetryRequest is not a separate message type - it's a ServerHello with
/// this specific random value. The value is the SHA-256 hash of the string
/// "HelloRetryRequest":
///
/// ```
/// SHA-256("HelloRetryRequest") =
///   CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
///   C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
/// ```
///
/// When a client receives a ServerHello with this random value, it must:
/// 1. Recognize it as HelloRetryRequest
/// 2. Update the transcript hash with a synthetic "message_hash" message
/// 3. Retry the handshake with the server's requested parameters (e.g., new key_share group)
/// 4. Include the cookie extension (if server sent one) in the retry ClientHello
///
/// ## Security Note
///
/// Using a fixed value instead of actual randomness is safe because:
/// - HelloRetryRequest is authenticated via the Finished message's transcript hash
/// - The cookie extension provides replay protection if needed
/// - The synthetic message in the transcript binds the retry to the original ClientHello
pub const HELLO_RETRY_REQUEST_RANDOM: [32]u8 = .{
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

/// RFC 8446 §4.1.3: Downgrade protection sentinel for TLS 1.2.
///
/// If a server supports TLS 1.3 but negotiates TLS 1.2 or below (due to client
/// limitations), it MUST set the last 8 bytes of ServerHello.random to this value.
/// A TLS 1.3 client that receives a TLS 1.2 ServerHello MUST check for this
/// sentinel and abort with illegal_parameter alert if detected.
///
/// This prevents downgrade attacks where a MITM forces a TLS 1.2 connection
/// even though both endpoints support TLS 1.3.
///
/// The value spells "DOWNGRD\x01" in ASCII (0x44 0x4F 0x57 0x4E = "DOWN",
/// 0x47 0x52 0x44 = "GRD", 0x01 = version indicator for TLS 1.2).
///
/// ## QUIC Note
///
/// QUIC mandates TLS 1.3, so this downgrade scenario cannot occur in QUIC.
/// However, the client-side check is still implemented for defense-in-depth.
pub const TLS12_DOWNGRADE_SENTINEL: [8]u8 = .{
    0x44, 0x4F, 0x57, 0x4E, // "DOWN"
    0x47, 0x52, 0x44, 0x01, // "GRD" + 0x01
};

/// RFC 8446 §4.1.3: Downgrade protection sentinel for TLS 1.1 and below.
///
/// Similar to TLS12_DOWNGRADE_SENTINEL, but indicates negotiation of TLS 1.1
/// or earlier. The last byte is 0x00 instead of 0x01.
///
/// The value spells "DOWNGRD\x00" in ASCII.
///
/// ## QUIC Note
///
/// QUIC mandates TLS 1.3, so this cannot occur. Included for completeness.
pub const TLS11_DOWNGRADE_SENTINEL: [8]u8 = .{
    0x44, 0x4F, 0x57, 0x4E, // "DOWN"
    0x47, 0x52, 0x44, 0x00, // "GRD" + 0x00
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if a ServerHello is actually a HelloRetryRequest.
///
/// RFC 8446 §4.1.4: HelloRetryRequest is distinguished by the special random value.
///
/// # Parameters
/// - `random`: The 32-byte random field from ServerHello
///
/// # Returns
/// - `true`: This is a HelloRetryRequest (client must retry with new parameters)
/// - `false`: This is a normal ServerHello (proceed with handshake)
///
/// # Usage
/// ```zig
/// if (isHelloRetryRequest(server_hello.random)) {
///     // Handle HelloRetryRequest flow
///     try handleHelloRetryRequest(ctx, server_hello);
/// } else {
///     // Handle normal ServerHello
///     try handleServerHello(ctx, server_hello);
/// }
/// ```
pub fn isHelloRetryRequest(random: [32]u8) bool {
    return std.mem.eql(u8, &random, &HELLO_RETRY_REQUEST_RANDOM);
}

/// Check if ServerHello random contains a TLS 1.2 downgrade sentinel.
///
/// RFC 8446 §4.1.3: Client MUST abort if it detects a downgrade attack.
///
/// # Parameters
/// - `random`: The 32-byte random field from ServerHello
///
/// # Returns
/// - `true`: Downgrade to TLS 1.2 detected (client MUST abort with illegal_parameter)
/// - `false`: No downgrade sentinel detected
///
/// # Usage
/// ```zig
/// if (containsTls12DowngradeSentinel(server_hello.random)) {
///     return error.Tls12DowngradeDetected; // Maps to illegal_parameter alert
/// }
/// ```
pub fn containsTls12DowngradeSentinel(random: [32]u8) bool {
    const last_8 = random[24..32];
    return std.mem.eql(u8, last_8, &TLS12_DOWNGRADE_SENTINEL);
}

/// Check if ServerHello random contains a TLS 1.1 or below downgrade sentinel.
///
/// RFC 8446 §4.1.3: Client MUST abort if it detects a downgrade attack.
///
/// # Parameters
/// - `random`: The 32-byte random field from ServerHello
///
/// # Returns
/// - `true`: Downgrade to TLS 1.1 or below detected (client MUST abort)
/// - `false`: No downgrade sentinel detected
///
/// # Usage
/// ```zig
/// if (containsTls11DowngradeSentinel(server_hello.random)) {
///     return error.Tls11DowngradeDetected; // Maps to illegal_parameter alert
/// }
/// ```
pub fn containsTls11DowngradeSentinel(random: [32]u8) bool {
    const last_8 = random[24..32];
    return std.mem.eql(u8, last_8, &TLS11_DOWNGRADE_SENTINEL);
}

/// Check for any downgrade attack (TLS 1.2 or TLS 1.1).
///
/// Convenience function that checks both downgrade sentinels.
///
/// # Parameters
/// - `random`: The 32-byte random field from ServerHello
///
/// # Returns
/// - `true`: Any downgrade detected (client MUST abort)
/// - `false`: No downgrade detected
///
/// # Usage
/// ```zig
/// if (containsDowngradeSentinel(server_hello.random)) {
///     return error.DowngradeDetected; // Maps to illegal_parameter alert
/// }
/// ```
pub fn containsDowngradeSentinel(random: [32]u8) bool {
    return containsTls12DowngradeSentinel(random) or
        containsTls11DowngradeSentinel(random);
}

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

// ============================================================================
// Unit Tests
// ============================================================================

test "HelloRetryRequest detection" {
    const testing = std.testing;

    // Test HRR random detection
    var hrr_random: [32]u8 = HELLO_RETRY_REQUEST_RANDOM;
    try testing.expect(isHelloRetryRequest(hrr_random));

    // Test normal random is not HRR
    var normal_random: [32]u8 = undefined;
    std.crypto.random.bytes(&normal_random);
    try testing.expect(!isHelloRetryRequest(normal_random));

    // Test first byte different
    hrr_random[0] = 0x00;
    try testing.expect(!isHelloRetryRequest(hrr_random));

    // Test last byte different
    hrr_random = HELLO_RETRY_REQUEST_RANDOM;
    hrr_random[31] = 0x00;
    try testing.expect(!isHelloRetryRequest(hrr_random));
}

test "Downgrade protection - TLS 1.2 sentinel" {
    const testing = std.testing;

    // Random with TLS 1.2 downgrade sentinel in last 8 bytes
    var random_with_sentinel: [32]u8 = undefined;
    std.crypto.random.bytes(&random_with_sentinel);
    @memcpy(random_with_sentinel[24..32], &TLS12_DOWNGRADE_SENTINEL);

    try testing.expect(containsTls12DowngradeSentinel(random_with_sentinel));
    try testing.expect(!containsTls11DowngradeSentinel(random_with_sentinel));
    try testing.expect(containsDowngradeSentinel(random_with_sentinel));

    // Random without sentinel
    var normal_random: [32]u8 = undefined;
    std.crypto.random.bytes(&normal_random);
    try testing.expect(!containsTls12DowngradeSentinel(normal_random));
    try testing.expect(!containsDowngradeSentinel(normal_random));
}

test "Downgrade protection - TLS 1.1 sentinel" {
    const testing = std.testing;

    // Random with TLS 1.1 downgrade sentinel in last 8 bytes
    var random_with_sentinel: [32]u8 = undefined;
    std.crypto.random.bytes(&random_with_sentinel);
    @memcpy(random_with_sentinel[24..32], &TLS11_DOWNGRADE_SENTINEL);

    try testing.expect(!containsTls12DowngradeSentinel(random_with_sentinel));
    try testing.expect(containsTls11DowngradeSentinel(random_with_sentinel));
    try testing.expect(containsDowngradeSentinel(random_with_sentinel));
}

test "Downgrade protection - HRR is not a downgrade" {
    const testing = std.testing;

    // HelloRetryRequest random should not be detected as downgrade
    const hrr_random = HELLO_RETRY_REQUEST_RANDOM;
    try testing.expect(!containsDowngradeSentinel(hrr_random));
}

test "HRR random value correctness" {
    const testing = std.testing;

    // Verify the HRR random is exactly SHA-256("HelloRetryRequest")
    // Expected value from RFC 8446 §4.1.3
    const expected = [32]u8{
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    };

    try testing.expectEqualSlices(u8, &expected, &HELLO_RETRY_REQUEST_RANDOM);

    // Verify it's actually SHA-256 of "HelloRetryRequest"
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("HelloRetryRequest");
    var actual: [32]u8 = undefined;
    hasher.final(&actual);

    try testing.expectEqualSlices(u8, &actual, &HELLO_RETRY_REQUEST_RANDOM);
}

test "Downgrade sentinel values correctness" {
    const testing = std.testing;

    // Verify TLS 1.2 sentinel spells "DOWNGRD\x01"
    const tls12_expected = [8]u8{ 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01 };
    try testing.expectEqualSlices(u8, &tls12_expected, &TLS12_DOWNGRADE_SENTINEL);

    // Verify TLS 1.1 sentinel spells "DOWNGRD\x00"
    const tls11_expected = [8]u8{ 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00 };
    try testing.expectEqualSlices(u8, &tls11_expected, &TLS11_DOWNGRADE_SENTINEL);

    // Verify they only differ in the last byte
    try testing.expect(std.mem.eql(u8, TLS12_DOWNGRADE_SENTINEL[0..7], TLS11_DOWNGRADE_SENTINEL[0..7]));
    try testing.expect(TLS12_DOWNGRADE_SENTINEL[7] != TLS11_DOWNGRADE_SENTINEL[7]);
}
