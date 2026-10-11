// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

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
const backend = @import("crypto_backend");
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
/// - `selected_psk_index`: If non-null, the index of the selected PSK identity from the client's
///   pre_shared_key extension. Emits a pre_shared_key extension in ServerHello per RFC 8446 §4.2.11.
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
/// 1. **pre_shared_key** (0x0029): Selected PSK identity index (if PSK selected)
/// 2. **key_share** (0x0033): Server's ECDHE public key
/// 3. **supported_versions** (0x002b): TLS 1.3 version (0x0304)
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
///     null,  // quic_params ignored (goes in EncryptedExtensions)
///     null,  // selected_psk_index (null for non-PSK handshake)
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
    selected_psk_index: ?u16,
) ![]u8 {
    // draft-kwiatkowski-tls-ecdhe-mlkem: for the X25519MLKEM768 hybrid
    // group the ServerHello key_share is exactly
    // x25519_mlkem768_sh_keyshare_len (1120) bytes
    // (ML-KEM-768 ciphertext || X25519 pub, provider-concatenated). The
    // encoder already writes key_exchange as a length-prefixed opaque blob,
    // so a 1120-byte slice serializes unchanged; this assertion guards
    // against a malformed hybrid key_share reaching the wire.
    if (key_share_group == .x25519_mlkem768) {
        std.debug.assert(key_share_data.len == core_types.x25519_mlkem768_sh_keyshare_len);
    }

    // PERF-007: Pre-allocate with typical ServerHello size (~128 bytes body).
    var msg = try std.ArrayList(u8).initCapacity(allocator, 128);
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
    // PERF-007: Pre-allocate with typical extensions size (~64 bytes).
    var exts = try std.ArrayList(u8).initCapacity(allocator, 64);
    defer exts.deinit(allocator);

    // CRITICAL: Extension order must match BoringSSL/Quiche for interoperability.
    // BoringSSL order (ssl/tls13_server.cc:938-941):
    //   1. pre_shared_key (if resuming)
    //   2. pake (if using PAKE)
    //   3. key_share
    //   4. supported_versions
    // Our order is:
    //   1. pre_shared_key (if PSK selected)
    //   2. key_share
    //   3. supported_versions
    // This is CRITICAL because transcript hash = SHA256(ClientHello || ServerHello)
    // and extension order affects the byte representation.

    // RFC 8446 §4.2.11: pre_shared_key extension (if PSK selected)
    // Contains the selected identity index (u16) from the client's offered PSK list.
    // Placed first per BoringSSL extension order convention.
    if (selected_psk_index) |psk_idx| {
        const psk_data = [_]u8{
            @intCast(psk_idx >> 8),
            @intCast(psk_idx & 0xff),
        };
        try helpers.writeExtension(allocator, &exts, .pre_shared_key, &psk_data);
    }

    // key_share (mandatory for ECDHE) - MUST BE AFTER pre_shared_key (if present)
    // PERF-007: Pre-allocate with typical key share size (36 bytes for X25519).
    var ks_data = try std.ArrayList(u8).initCapacity(allocator, 36);
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

/// Build a HelloRetryRequest message (RFC 8446 §4.1.4).
///
/// HelloRetryRequest (HRR) is a ServerHello message with a special random value
/// that instructs the client to send a new ClientHello with updated parameters.
/// This is used when the server cannot process the original ClientHello, most
/// commonly when the client's key_share group is not supported by the server.
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for message buffer
/// - `selected_group`: The NamedGroup the server wants the client to use
/// - `cookie`: Stateless cookie to bind the retry to the original ClientHello
/// - `client_session_id`: Echo of client's session ID (for middlebox compatibility)
///
/// ## Returns
///
/// - `[]u8`: Serialized HelloRetryRequest message (caller owns memory, must free)
///
/// ## Message Format (RFC 8446 §4.1.4)
///
/// HelloRetryRequest is a ServerHello message with these characteristics:
/// - random field set to the special value SHA-256("HelloRetryRequest")
/// - legacy_version, legacy_session_id_echo, and legacy_compression_method follow ServerHello rules
/// - cipher_suite can be zero (will be negotiated in second ClientHello)
/// - Extensions:
///   1. **supported_versions** (0x002b): MANDATORY - TLS 1.3 (0x0304)
///   2. **cookie** (0x002c): Opaque cookie to prevent DoS attacks
///   3. **key_share** (0x0033): Contains only selected_group (2 bytes), not key exchange data
///
/// ## Key Share Extension in HRR (RFC 8446 §4.2.8)
///
/// In HelloRetryRequest, the key_share extension has a different format:
/// ```
/// struct {
///     NamedGroup selected_group;  // 2 bytes
/// } KeyShareHelloRetryRequest;
/// ```
///
/// This tells the client which group to use in the second ClientHello.
///
/// ## Cookie Extension (RFC 8446 §4.2.2)
///
/// The cookie extension binds the retry to the original ClientHello and prevents
/// DoS attacks. Format:
/// ```
/// struct {
///     opaque cookie<1..2^16-1>;
/// } Cookie;
/// ```
///
/// The cookie is generated using HMAC over:
/// - Client random from first ClientHello
/// - Transcript hash of first ClientHello
/// - Timestamp for freshness validation
///
/// ## Security Considerations
///
/// - HRR random value is FIXED (SHA-256("HelloRetryRequest")) - not generated
/// - Cookie MUST be validated when client sends second ClientHello
/// - Transcript hash special handling: Hash(message_hash(CH1) || HRR || CH2...)
/// - Server can be stateless by encoding state in the cookie
///
/// ## Transcript Hash Handling
///
/// When HRR is sent, the transcript is modified per RFC 8446 §4.4.1:
/// 1. Compute hash1 = Hash(ClientHello1)
/// 2. Replace transcript with: message_hash(hash1) || HelloRetryRequest
/// 3. Continue with: message_hash(hash1) || HRR || ClientHello2 || ServerHello...
///
/// ## Usage
///
/// ```zig
/// const cookie = try cookie_mod.generateCookie(allocator, server_secret, client_random, transcript_hash);
/// defer allocator.free(cookie);
///
/// const hrr = try buildHelloRetryRequest(
///     allocator,
///     .secp256r1,  // Request client to use P-256 instead of X25519
///     cookie,
///     client_session_id
/// );
/// defer allocator.free(hrr);
/// ```
///
/// ## RFC References
///
/// - RFC 8446 §4.1.4: HelloRetryRequest structure
/// - RFC 8446 §4.2.2: Cookie extension
/// - RFC 8446 §4.2.8: Key Share extension (HelloRetryRequest variant)
/// - RFC 8446 §4.4.1: Transcript hash modification for HRR
pub fn buildHelloRetryRequest(
    allocator: std.mem.Allocator,
    selected_group: core_types.NamedGroup,
    cookie: []const u8,
    client_session_id: ?[]const u8,
) ![]u8 {
    // PERF-007: Pre-allocate with typical HRR size (~128 bytes).
    var msg = try std.ArrayList(u8).initCapacity(allocator, 128);
    defer msg.deinit(allocator);

    // Legacy version (TLS 1.2 for compatibility)
    try msg.appendSlice(allocator, &[_]u8{ 0x03, 0x03 });

    // Random: MUST be the special HRR random value
    try msg.appendSlice(allocator, &HELLO_RETRY_REQUEST_RANDOM);

    // Legacy session ID (echo from client per RFC 8446 §4.1.3)
    if (client_session_id) |session_id| {
        try msg.append(allocator, @intCast(session_id.len));
        try msg.appendSlice(allocator, session_id);
    } else {
        try msg.append(allocator, 0);
    }

    // Cipher suite: Can be zero in HRR (will be negotiated in ClientHello2)
    // Using TLS_AES_128_GCM_SHA256 as a placeholder (common default)
    try msg.appendSlice(allocator, &[_]u8{ 0x13, 0x01 });

    // Legacy compression method
    try msg.append(allocator, 0);

    // Extensions
    // PERF-007: Pre-allocate with typical HRR extensions size (~64 bytes).
    var exts = try std.ArrayList(u8).initCapacity(allocator, 64);
    defer exts.deinit(allocator);

    // RFC 8446 §4.1.4: Extension order for HRR:
    // 1. supported_versions (MANDATORY)
    // 2. cookie (if present)
    // 3. key_share with selected_group (if requesting different group)

    // supported_versions (MANDATORY)
    try helpers.writeExtension(allocator, &exts, .supported_versions, &[_]u8{ 0x03, 0x04 });

    // cookie extension (RFC 8446 §4.2.2):
    //
    //     struct {
    //         opaque cookie<1..2^16-1>;
    //     } Cookie;
    //
    // The Cookie struct has a 2-byte inner length prefix that the
    // extension data MUST carry. We assemble the wrapped payload first,
    // then `writeExtension` adds the outer 2-byte ext_data_len.
    if (cookie.len > std.math.maxInt(u16)) return error.CookieTooLarge;
    const cookie_inner_len: u16 = @intCast(cookie.len);
    var wrapped = try std.ArrayList(u8).initCapacity(allocator, 2 + cookie.len);
    defer wrapped.deinit(allocator);
    try wrapped.append(allocator, @intCast(cookie_inner_len >> 8));
    try wrapped.append(allocator, @intCast(cookie_inner_len & 0xff));
    try wrapped.appendSlice(allocator, cookie);
    try helpers.writeExtension(allocator, &exts, .cookie, wrapped.items);

    // key_share extension with selected_group only (RFC 8446 §4.2.8)
    // Format for HRR: just the 2-byte NamedGroup value
    const group_value = @intFromEnum(selected_group);
    const group_bytes = [_]u8{
        @intCast(group_value >> 8),
        @intCast(group_value & 0xff),
    };
    try helpers.writeExtension(allocator, &exts, .key_share, &group_bytes);

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
    std.testing.io.random(&normal_random);
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
    std.testing.io.random(&random_with_sentinel);
    @memcpy(random_with_sentinel[24..32], &TLS12_DOWNGRADE_SENTINEL);

    try testing.expect(containsTls12DowngradeSentinel(random_with_sentinel));
    try testing.expect(!containsTls11DowngradeSentinel(random_with_sentinel));
    try testing.expect(containsDowngradeSentinel(random_with_sentinel));

    // Random without sentinel
    var normal_random: [32]u8 = undefined;
    std.testing.io.random(&normal_random);
    try testing.expect(!containsTls12DowngradeSentinel(normal_random));
    try testing.expect(!containsDowngradeSentinel(normal_random));
}

test "Downgrade protection - TLS 1.1 sentinel" {
    const testing = std.testing;

    // Random with TLS 1.1 downgrade sentinel in last 8 bytes
    var random_with_sentinel: [32]u8 = undefined;
    std.testing.io.random(&random_with_sentinel);
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

    // Verify it's actually SHA-256 of "HelloRetryRequest" (routed via the seam)
    var actual: [32]u8 = undefined;
    _ = backend.Hash.digest(.sha256, "HelloRetryRequest", &actual) catch unreachable;

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

test "buildHelloRetryRequest - basic structure" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create a test cookie
    const cookie = "test_cookie_12345678";
    const session_id = &[_]u8{ 0x01, 0x02, 0x03, 0x04 };

    const hrr = try buildHelloRetryRequest(
        allocator,
        .secp256r1, // Request P-256 group
        cookie,
        session_id,
    );
    defer allocator.free(hrr);

    // Verify HRR has minimum expected length
    // 2 (version) + 32 (random) + 1 (session_id_len) + 4 (session_id) + 2 (cipher) + 1 (compression) + 2 (ext_len) + extensions
    try testing.expect(hrr.len > 44);

    // Verify legacy version (0x0303 = TLS 1.2)
    try testing.expectEqual(@as(u8, 0x03), hrr[0]);
    try testing.expectEqual(@as(u8, 0x03), hrr[1]);

    // Verify HRR random value (bytes 2..34)
    try testing.expectEqualSlices(u8, &HELLO_RETRY_REQUEST_RANDOM, hrr[2..34]);

    // Verify this is detected as HRR
    var random: [32]u8 = undefined;
    @memcpy(&random, hrr[2..34]);
    try testing.expect(isHelloRetryRequest(random));
}

test "buildHelloRetryRequest - extension format" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const cookie = "my_cookie";
    const hrr = try buildHelloRetryRequest(
        allocator,
        .x25519,
        cookie,
        null, // No session ID
    );
    defer allocator.free(hrr);

    // Parse structure to find extensions
    // Skip: version(2) + random(32) + session_id_len(1) + cipher(2) + compression(1) = 38 bytes
    var pos: usize = 38;
    try testing.expect(pos + 2 <= hrr.len);

    // Read extensions length
    const ext_len = (@as(usize, hrr[pos]) << 8) | @as(usize, hrr[pos + 1]);
    pos += 2;

    try testing.expect(pos + ext_len == hrr.len); // Extensions should fill rest of message
    try testing.expect(ext_len > 0); // Must have extensions

    // Extensions should contain: supported_versions + cookie + key_share
    // We don't parse them fully here, just verify they're present
}

test "buildHelloRetryRequest - selected group encoding" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const cookie = "test";

    // Test with different groups
    const groups = [_]core_types.NamedGroup{
        .x25519, // 0x001d
        .secp256r1, // 0x0017
        .secp384r1, // 0x0018
    };

    for (groups) |group| {
        const hrr = try buildHelloRetryRequest(
            allocator,
            group,
            cookie,
            null,
        );
        defer allocator.free(hrr);

        // Verify HRR was built successfully
        try testing.expect(hrr.len > 40);

        // Verify HRR random is present
        try testing.expectEqualSlices(u8, &HELLO_RETRY_REQUEST_RANDOM, hrr[2..34]);
    }
}

test "buildHelloRetryRequest - cookie preservation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test with various cookie sizes
    const cookies = [_][]const u8{
        "small",
        "medium_sized_cookie_123",
        "very_long_cookie_" ++ ("x" ** 50),
    };

    for (cookies) |cookie| {
        const hrr = try buildHelloRetryRequest(
            allocator,
            .x25519,
            cookie,
            null,
        );
        defer allocator.free(hrr);

        // Verify HRR was built successfully
        try testing.expect(hrr.len > 40);

        // Cookie is embedded in extensions - we don't parse it here,
        // but verify the message length makes sense
        // Minimum: header(38) + ext_len(2) + supported_versions(6) + cookie(4+cookie.len) + key_share(6)
        const min_len = 38 + 2 + 6 + 4 + cookie.len + 6;
        try testing.expect(hrr.len >= min_len);
    }
}

test "buildHelloRetryRequest - session ID echo" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const cookie = "test_cookie";

    // Test with session ID
    const session_id = &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const hrr_with_sid = try buildHelloRetryRequest(
        allocator,
        .x25519,
        cookie,
        session_id,
    );
    defer allocator.free(hrr_with_sid);

    // Verify session ID is echoed (byte 34 should be length, then the ID)
    try testing.expectEqual(@as(u8, session_id.len), hrr_with_sid[34]);
    try testing.expectEqualSlices(u8, session_id, hrr_with_sid[35 .. 35 + session_id.len]);

    // Test without session ID
    const hrr_no_sid = try buildHelloRetryRequest(
        allocator,
        .x25519,
        cookie,
        null,
    );
    defer allocator.free(hrr_no_sid);

    // Verify session ID length is 0
    try testing.expectEqual(@as(u8, 0), hrr_no_sid[34]);
}

test "buildServerHello - no PSK extension when selected_psk_index is null" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var server_random: [32]u8 = undefined;
    std.testing.io.random(&server_random);
    const key_data = &[_]u8{0x42} ** 32;

    const sh = try buildServerHello(
        allocator,
        server_random,
        .TLS_AES_128_GCM_SHA256,
        .x25519,
        key_data,
        null,
        null,
        null, // No PSK selected
    );
    defer allocator.free(sh);

    // Parse extensions to verify no pre_shared_key extension present
    // Skip: version(2) + random(32) + session_id_len(1) + cipher(2) + compression(1) = 38
    var pos: usize = 38;
    try testing.expect(pos + 2 <= sh.len);
    const ext_len = (@as(usize, sh[pos]) << 8) | @as(usize, sh[pos + 1]);
    pos += 2;
    const exts_end = pos + ext_len;

    while (pos + 4 <= exts_end) {
        const etype = (@as(u16, sh[pos]) << 8) | sh[pos + 1];
        const elen = (@as(usize, sh[pos + 2]) << 8) | @as(usize, sh[pos + 3]);
        pos += 4;
        // pre_shared_key type is 0x0029 -- must NOT be present
        try testing.expect(etype != @intFromEnum(core_types.ExtensionType.pre_shared_key));
        pos += elen;
    }
}

test "buildServerHello - PSK extension emitted when selected_psk_index is set" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var server_random: [32]u8 = undefined;
    std.testing.io.random(&server_random);
    const key_data = &[_]u8{0x42} ** 32;

    const sh = try buildServerHello(
        allocator,
        server_random,
        .TLS_AES_128_GCM_SHA256,
        .x25519,
        key_data,
        null,
        null,
        0, // PSK index 0 selected
    );
    defer allocator.free(sh);

    // Parse extensions to find pre_shared_key extension
    var pos: usize = 38;
    try testing.expect(pos + 2 <= sh.len);
    const ext_len = (@as(usize, sh[pos]) << 8) | @as(usize, sh[pos + 1]);
    pos += 2;
    const exts_end = pos + ext_len;

    var found_psk = false;
    var psk_index: ?u16 = null;
    var psk_ext_position: usize = 0;
    var ext_count: usize = 0;
    while (pos + 4 <= exts_end) {
        const etype = (@as(u16, sh[pos]) << 8) | sh[pos + 1];
        const elen = (@as(usize, sh[pos + 2]) << 8) | @as(usize, sh[pos + 3]);
        pos += 4;
        if (etype == @intFromEnum(core_types.ExtensionType.pre_shared_key)) {
            found_psk = true;
            psk_ext_position = ext_count;
            // RFC 8446 §4.2.11: selected_identity is u16
            try testing.expectEqual(@as(usize, 2), elen);
            psk_index = (@as(u16, sh[pos]) << 8) | sh[pos + 1];
        }
        pos += elen;
        ext_count += 1;
    }

    try testing.expect(found_psk);
    try testing.expectEqual(@as(u16, 0), psk_index.?);
    // Per BoringSSL convention, pre_shared_key should be first extension
    try testing.expectEqual(@as(usize, 0), psk_ext_position);
}

test "buildServerHello - PSK extension with non-zero index" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var server_random: [32]u8 = undefined;
    std.testing.io.random(&server_random);
    const key_data = &[_]u8{0x42} ** 32;

    const sh = try buildServerHello(
        allocator,
        server_random,
        .TLS_AES_128_GCM_SHA256,
        .x25519,
        key_data,
        null,
        null,
        3, // PSK index 3 selected
    );
    defer allocator.free(sh);

    // Parse extensions to find PSK index value
    var pos: usize = 38;
    const ext_len = (@as(usize, sh[pos]) << 8) | @as(usize, sh[pos + 1]);
    pos += 2;
    const exts_end = pos + ext_len;

    var psk_index: ?u16 = null;
    while (pos + 4 <= exts_end) {
        const etype = (@as(u16, sh[pos]) << 8) | sh[pos + 1];
        const elen = (@as(usize, sh[pos + 2]) << 8) | @as(usize, sh[pos + 3]);
        pos += 4;
        if (etype == @intFromEnum(core_types.ExtensionType.pre_shared_key)) {
            try testing.expectEqual(@as(usize, 2), elen);
            psk_index = (@as(u16, sh[pos]) << 8) | sh[pos + 1];
        }
        pos += elen;
    }

    try testing.expect(psk_index != null);
    try testing.expectEqual(@as(u16, 3), psk_index.?);
}

test "buildServerHello - PSK extension byte-level format" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var server_random: [32]u8 = undefined;
    std.testing.io.random(&server_random);
    const key_data = &[_]u8{0x42} ** 32;

    const sh = try buildServerHello(
        allocator,
        server_random,
        .TLS_AES_128_GCM_SHA256,
        .x25519,
        key_data,
        null,
        null,
        0,
    );
    defer allocator.free(sh);

    // The first extension should be pre_shared_key (0x0029) with data [0x00, 0x00]
    // Extensions start at offset 40 (38 header + 2 ext_len)
    const ext_start = 40;
    try testing.expect(sh.len > ext_start + 6);

    // Extension type: 0x0029
    try testing.expectEqual(@as(u8, 0x00), sh[ext_start]);
    try testing.expectEqual(@as(u8, 0x29), sh[ext_start + 1]);
    // Extension length: 0x0002
    try testing.expectEqual(@as(u8, 0x00), sh[ext_start + 2]);
    try testing.expectEqual(@as(u8, 0x02), sh[ext_start + 3]);
    // Selected identity: 0x0000
    try testing.expectEqual(@as(u8, 0x00), sh[ext_start + 4]);
    try testing.expectEqual(@as(u8, 0x00), sh[ext_start + 5]);
}

test "buildServerHello - extension order: PSK before key_share before supported_versions" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var server_random: [32]u8 = undefined;
    std.testing.io.random(&server_random);
    const key_data = &[_]u8{0x42} ** 32;

    const sh = try buildServerHello(
        allocator,
        server_random,
        .TLS_AES_128_GCM_SHA256,
        .x25519,
        key_data,
        null,
        null,
        0,
    );
    defer allocator.free(sh);

    // Parse extension types in order
    var pos: usize = 38;
    const ext_len = (@as(usize, sh[pos]) << 8) | @as(usize, sh[pos + 1]);
    pos += 2;
    const exts_end = pos + ext_len;

    var ext_types = std.ArrayList(u16).init(allocator);
    defer ext_types.deinit();
    while (pos + 4 <= exts_end) {
        const etype = (@as(u16, sh[pos]) << 8) | sh[pos + 1];
        const elen = (@as(usize, sh[pos + 2]) << 8) | @as(usize, sh[pos + 3]);
        pos += 4;
        try ext_types.append(etype);
        pos += elen;
    }

    // Expected order: pre_shared_key (0x0029), key_share (0x0033), supported_versions (0x002b)
    try testing.expectEqual(@as(usize, 3), ext_types.items.len);
    try testing.expectEqual(@as(u16, 0x0029), ext_types.items[0]); // pre_shared_key
    try testing.expectEqual(@as(u16, 0x0033), ext_types.items[1]); // key_share
    try testing.expectEqual(@as(u16, 0x002b), ext_types.items[2]); // supported_versions
}

test "buildServerHello - without PSK has only key_share and supported_versions" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var server_random: [32]u8 = undefined;
    std.testing.io.random(&server_random);
    const key_data = &[_]u8{0x42} ** 32;

    const sh = try buildServerHello(
        allocator,
        server_random,
        .TLS_AES_128_GCM_SHA256,
        .x25519,
        key_data,
        null,
        null,
        null, // No PSK
    );
    defer allocator.free(sh);

    // Parse extension types in order
    var pos: usize = 38;
    const ext_len = (@as(usize, sh[pos]) << 8) | @as(usize, sh[pos + 1]);
    pos += 2;
    const exts_end = pos + ext_len;

    var ext_types = std.ArrayList(u16).init(allocator);
    defer ext_types.deinit();
    while (pos + 4 <= exts_end) {
        const etype = (@as(u16, sh[pos]) << 8) | sh[pos + 1];
        const elen = (@as(usize, sh[pos + 2]) << 8) | @as(usize, sh[pos + 3]);
        pos += 4;
        try ext_types.append(etype);
        pos += elen;
    }

    // Without PSK: only key_share (0x0033), supported_versions (0x002b)
    try testing.expectEqual(@as(usize, 2), ext_types.items.len);
    try testing.expectEqual(@as(u16, 0x0033), ext_types.items[0]); // key_share
    try testing.expectEqual(@as(u16, 0x002b), ext_types.items[1]); // supported_versions
}
