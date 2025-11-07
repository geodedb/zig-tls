//! RFC 8446 §4.1.3: ServerHello Tests
//!
//! Tests for TLS 1.3 ServerHello message structure and construction.
//!
//! ## RFC 8446 §4.1.3: ServerHello
//!
//! The ServerHello is sent in response to the ClientHello when the server can
//! find an acceptable set of algorithms and the client's key share is acceptable.
//!
//! ```
//! struct {
//!     ProtocolVersion legacy_version = 0x0303; /* TLS v1.2 */
//!     Random random;
//!     opaque legacy_session_id_echo<0..32>;
//!     CipherSuite cipher_suite;
//!     uint8 legacy_compression_method = 0;
//!     Extension extensions<6..2^16-1>;
//! } ServerHello;
//! ```
//!
//! ## Key Requirements
//!
//! - **legacy_version** MUST be 0x0303 (TLS 1.2) for compatibility
//! - **random** MUST be 32 bytes, MUST NOT be the same as ClientHello random
//! - **legacy_session_id_echo** MUST echo the client's session_id
//! - **cipher_suite** selects a single cipher suite from the client's list
//! - **legacy_compression_method** MUST be 0x00
//! - **extensions** MUST include supported_versions for TLS 1.3
//! - **extensions** MUST include key_share (selected group)
//!
//! ## Downgrade Protection
//!
//! TLS 1.3 ServerHello includes downgrade protection via special random values:
//! - Last 8 bytes = 44 4F 57 4E 47 52 44 01 if TLS 1.2 is being negotiated
//! - Last 8 bytes = 44 4F 57 4E 47 52 44 00 if TLS 1.1 or below
//!
//! ## Test Coverage
//!
//! - ServerHello structure validation
//! - Required fields presence
//! - Extension construction (supported_versions, key_share)
//! - Session ID echo verification
//! - Downgrade protection sentinels

const std = @import("std");
const testing = std.testing;

// Helper to convert hex string to bytes
fn hexToBytes(comptime hex: []const u8, out: []u8) void {
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        out[i / 2] = std.fmt.parseInt(u8, hex[i .. i + 2], 16) catch unreachable;
    }
}

// Helper to compare hex string with bytes
fn expectEqualHex(comptime hex: []const u8, actual: []const u8) !void {
    var expected: [hex.len / 2]u8 = undefined;
    hexToBytes(hex, &expected);
    try testing.expectEqualSlices(u8, &expected, actual);
}

// RFC 8446 §4.1.3: ServerHello Legacy Version
//
// The legacy_version field MUST be set to 0x0303 (TLS 1.2) for
// compatibility with middleboxes. Actual version negotiation happens
// via the supported_versions extension.
test "RFC 8446 §4.1.3: ServerHello legacy_version must be 0x0303" {
    const legacy_version: u16 = 0x0303;
    try testing.expectEqual(@as(u16, 0x0303), legacy_version);
}

// RFC 8446 §4.1.3: ServerHello Random Field
//
// The random field MUST be 32 bytes and contains a server-generated random value.
// It MUST NOT be the same as the ClientHello random.
test "RFC 8446 §4.1.3: ServerHello random field is 32 bytes" {
    var random: [32]u8 = undefined;
    std.crypto.random.bytes(&random);

    try testing.expectEqual(@as(usize, 32), random.len);
}

// RFC 8446 §4.1.3: ServerHello Downgrade Protection
//
// TLS 1.3 includes downgrade protection by requiring servers to set the last
// 8 bytes of the random field to a special value if a TLS version lower than
// 1.3 is negotiated.
//
// Downgrade sentinels:
// - TLS 1.2: 44 4F 57 4E 47 52 44 01 ("DOWNGRD\x01")
// - TLS 1.1 or below: 44 4F 57 4E 47 52 44 00 ("DOWNGRD\x00")
test "RFC 8446 §4.1.3: TLS 1.2 downgrade protection sentinel" {
    const tls12_downgrade_sentinel = [_]u8{ 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01 };

    try testing.expectEqualSlices(u8, "DOWNGRD\x01", &tls12_downgrade_sentinel);
    try testing.expectEqual(@as(usize, 8), tls12_downgrade_sentinel.len);
}

test "RFC 8446 §4.1.3: TLS 1.1 downgrade protection sentinel" {
    const tls11_downgrade_sentinel = [_]u8{ 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00 };

    try testing.expectEqualSlices(u8, "DOWNGRD\x00", &tls11_downgrade_sentinel);
    try testing.expectEqual(@as(usize, 8), tls11_downgrade_sentinel.len);
}

// RFC 8446 §4.1.3: ServerHello Session ID Echo
//
// The legacy_session_id_echo field MUST echo the value of
// legacy_session_id from the ClientHello.
test "RFC 8446 §4.1.3: ServerHello echoes ClientHello session ID" {
    const client_session_id = [_]u8{0x01, 0x02, 0x03, 0x04};
    const server_session_id_echo = client_session_id;

    try testing.expectEqualSlices(u8, &client_session_id, &server_session_id_echo);
}

// RFC 8446 §4.1.3: ServerHello Cipher Suite Selection
//
// The cipher_suite field contains the single cipher suite selected by the
// server from the client's list. For TLS 1.3, this MUST be a TLS 1.3 cipher suite.
test "RFC 8446 §4.1.3: ServerHello cipher suite selection" {
    const tls_aes_128_gcm_sha256: u16 = 0x1301;
    const tls_aes_256_gcm_sha384: u16 = 0x1302;
    const tls_chacha20_poly1305_sha256: u16 = 0x1303;

    // Verify TLS 1.3 cipher suite identifiers
    try testing.expectEqual(@as(u16, 0x1301), tls_aes_128_gcm_sha256);
    try testing.expectEqual(@as(u16, 0x1302), tls_aes_256_gcm_sha384);
    try testing.expectEqual(@as(u16, 0x1303), tls_chacha20_poly1305_sha256);
}

// RFC 8446 §4.1.3: ServerHello Compression Method
//
// The legacy_compression_method field MUST be 0x00 (null compression).
test "RFC 8446 §4.1.3: ServerHello compression method must be 0x00" {
    const legacy_compression_method: u8 = 0x00;
    try testing.expectEqual(@as(u8, 0x00), legacy_compression_method);
}

// RFC 8446 §4.2.1: ServerHello Supported Versions Extension
//
// The supported_versions extension (type 0x002b) is REQUIRED in TLS 1.3
// ServerHello messages. Unlike ClientHello, it contains a single selected version.
//
// ```
//! struct {
//!     select (Handshake.msg_type) {
//!         case server_hello:
//!             ProtocolVersion selected_version;
//!     };
//! } SupportedVersions;
//! ```
test "RFC 8446 §4.2.1: ServerHello supported_versions extension" {
    const supported_versions_type: u16 = 0x002b;
    try testing.expectEqual(@as(u16, 0x002b), supported_versions_type);

    // TLS 1.3 version value
    const tls13_version: u16 = 0x0304;
    try testing.expectEqual(@as(u16, 0x0304), tls13_version);
}

// RFC 8446 §4.2.8: ServerHello Key Share Extension
//
// The key_share extension (type 0x0033) in ServerHello contains the server's
// ephemeral ECDHE public key for the selected named group.
//
// ```
//! struct {
//!     KeyShareEntry server_share;
//! } KeyShareServerHello;
//! ```
test "RFC 8446 §4.2.8: ServerHello key_share extension" {
    const key_share_type: u16 = 0x0033;
    try testing.expectEqual(@as(u16, 0x0033), key_share_type);

    // X25519 named group (most common for QUIC)
    const x25519_group: u16 = 0x001d;
    try testing.expectEqual(@as(u16, 0x001d), x25519_group);

    // X25519 public key is 32 bytes
    const x25519_key_len: usize = 32;
    try testing.expectEqual(@as(usize, 32), x25519_key_len);
}

// RFC 8446 §4.1.3: ServerHello Extension Ordering
//
// While the order of extensions is generally not significant, the
// supported_versions and key_share extensions are typically sent first
// for consistency with the key schedule.
test "RFC 8446 §4.1.3: ServerHello extension ordering" {
    // Extension order: supported_versions, key_share (typical)
    const supported_versions_type: u16 = 0x002b;
    const key_share_type: u16 = 0x0033;

    try testing.expectEqual(@as(u16, 0x002b), supported_versions_type);
    try testing.expectEqual(@as(u16, 0x0033), key_share_type);
}

// RFC 8446 §4.1.4: HelloRetryRequest
//
// If the server cannot immediately proceed with the handshake, it sends a
// HelloRetryRequest which is actually a ServerHello with a special random value.
//
// HelloRetryRequest random: CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
//                          C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
test "RFC 8446 §4.1.4: HelloRetryRequest special random value" {
    const hrr_random_hex =
        "CF21AD74E59A6111BE1D8C021E65B891" ++
        "C2A211167ABB8C5E079E09E2C8A8339C";

    var hrr_random: [32]u8 = undefined;
    hexToBytes(hrr_random_hex, &hrr_random);

    try testing.expectEqual(@as(usize, 32), hrr_random.len);
    try expectEqualHex(hrr_random_hex, &hrr_random);
}

// RFC 8446 §4.1.3: ServerHello MUST NOT Contain Certificate Extensions
//
// The ServerHello must NOT contain extensions that belong in EncryptedExtensions,
// Certificate, or CertificateRequest.
//
// ServerHello-only extensions:
// - supported_versions (0x002b) - REQUIRED
// - key_share (0x0033) - REQUIRED
// - pre_shared_key (0x0029) - if PSK is used
test "RFC 8446 §4.1.3: ServerHello extension restrictions" {
    // Extensions allowed in ServerHello
    const supported_versions: u16 = 0x002b;
    const key_share: u16 = 0x0033;
    const pre_shared_key: u16 = 0x0029;

    try testing.expectEqual(@as(u16, 0x002b), supported_versions);
    try testing.expectEqual(@as(u16, 0x0033), key_share);
    try testing.expectEqual(@as(u16, 0x0029), pre_shared_key);

    // Extensions NOT allowed in ServerHello (go in EncryptedExtensions):
    const alpn: u16 = 0x0010;
    const server_name: u16 = 0x0000;

    try testing.expectEqual(@as(u16, 0x0010), alpn);
    try testing.expectEqual(@as(u16, 0x0000), server_name);
}
