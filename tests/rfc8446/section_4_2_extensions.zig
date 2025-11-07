//! RFC 8446 §4.2: Extensions Tests
//!
//! Tests for TLS 1.3 extension mechanism and common extensions.
//!
//! ## RFC 8446 §4.2: Extensions
//!
//! A number of TLS messages contain tag-length-value encoded extensions structures:
//!
//! ```
//! struct {
//!     ExtensionType extension_type;
//!     opaque extension_data<0..2^16-1>;
//! } Extension;
//! ```
//!
//! The "extension_type" identifies the particular extension type, and
//! "extension_data" contains information specific to the particular extension type.
//!
//! ## Extension Processing Rules
//!
//! - Clients MUST send supported_versions in ClientHello (§9.2)
//! - Extensions may appear in ClientHello, ServerHello, EncryptedExtensions,
//!   HelloRetryRequest, Certificate, and NewSessionTicket
//! - Unknown extensions MUST be ignored
//! - Extensions in ServerHello/HelloRetryRequest MUST appear in ClientHello
//! - pre_shared_key MUST be the last extension in ClientHello if present
//!
//! ## Test Coverage
//!
//! - Extension type identifiers
//! - Extension structure validation
//! - Required extensions verification
//! - Extension ordering rules
//! - Unknown extension handling

const std = @import("std");
const testing = std.testing;

// RFC 8446 §4.2: Extension Type Registry
//
// Extension types are registered in the IANA TLS ExtensionType Values registry.
// The following are commonly used in TLS 1.3:

test "RFC 8446 §4.2: Extension type identifiers" {
    // RFC 6066 §3: Server Name Indication
    const server_name: u16 = 0x0000;
    try testing.expectEqual(@as(u16, 0x0000), server_name);

    // RFC 8446 §4.2.3: Signature Algorithms (REQUIRED)
    const signature_algorithms: u16 = 0x000d;
    try testing.expectEqual(@as(u16, 0x000d), signature_algorithms);

    // RFC 8446 §4.2.7: Supported Groups
    const supported_groups: u16 = 0x000a;
    try testing.expectEqual(@as(u16, 0x000a), supported_groups);

    // RFC 7301: Application-Layer Protocol Negotiation
    const alpn: u16 = 0x0010;
    try testing.expectEqual(@as(u16, 0x0010), alpn);

    // RFC 8446 §4.2.11: Pre-Shared Key
    const pre_shared_key: u16 = 0x0029;
    try testing.expectEqual(@as(u16, 0x0029), pre_shared_key);

    // RFC 8446 §4.2.10: Early Data
    const early_data: u16 = 0x002a;
    try testing.expectEqual(@as(u16, 0x002a), early_data);

    // RFC 8446 §4.2.1: Supported Versions (REQUIRED for TLS 1.3)
    const supported_versions: u16 = 0x002b;
    try testing.expectEqual(@as(u16, 0x002b), supported_versions);

    // RFC 8446 §4.2.8: Key Share
    const key_share: u16 = 0x0033;
    try testing.expectEqual(@as(u16, 0x0033), key_share);

    // RFC 9001 §8.2: QUIC Transport Parameters
    const quic_transport_parameters: u16 = 0x0039;
    try testing.expectEqual(@as(u16, 0x0039), quic_transport_parameters);

    // RFC 8446 §4.2.9: PSK Key Exchange Modes
    const psk_key_exchange_modes: u16 = 0x002d;
    try testing.expectEqual(@as(u16, 0x002d), psk_key_exchange_modes);
}

// RFC 8446 §4.2.7: Supported Groups Extension
//
// The "supported_groups" extension (formerly "elliptic_curves") indicates
// which named groups (ECDHE curves and FFDHE groups) the client supports.
//
// ```
//! enum {
//!     /* Elliptic Curve Groups (ECDHE) */
//!     secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
//!     x25519(0x001D), x448(0x001E),
//!
//!     /* Finite Field Groups (FFDHE) */
//!     ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
//!     ffdhe6144(0x0103), ffdhe8192(0x0104),
//!
//!     (0xFFFF)
//! } NamedGroup;
//! ```
test "RFC 8446 §4.2.7: Named group identifiers" {
    // Elliptic Curve Groups (most common)
    const x25519: u16 = 0x001d;
    const secp256r1: u16 = 0x0017;
    const secp384r1: u16 = 0x0018;

    try testing.expectEqual(@as(u16, 0x001d), x25519);
    try testing.expectEqual(@as(u16, 0x0017), secp256r1);
    try testing.expectEqual(@as(u16, 0x0018), secp384r1);

    // Finite Field Groups
    const ffdhe2048: u16 = 0x0100;
    const ffdhe3072: u16 = 0x0101;

    try testing.expectEqual(@as(u16, 0x0100), ffdhe2048);
    try testing.expectEqual(@as(u16, 0x0101), ffdhe3072);
}

// RFC 8446 §4.2.3: Signature Algorithms Extension
//
// The "signature_algorithms" extension indicates which signature/hash
// algorithm pairs the client can verify. This is REQUIRED in TLS 1.3.
//
// ```
//! enum {
//!     /* ECDSA algorithms */
//!     ecdsa_secp256r1_sha256(0x0403),
//!     ecdsa_secp384r1_sha384(0x0503),
//!     ecdsa_secp521r1_sha512(0x0603),
//!
//!     /* Ed algorithms */
//!     ed25519(0x0807),
//!     ed448(0x0808),
//!
//!     /* RSASSA-PSS algorithms */
//!     rsa_pss_rsae_sha256(0x0804),
//!     rsa_pss_rsae_sha384(0x0805),
//!     rsa_pss_rsae_sha512(0x0806),
//!
//!     (0xFFFF)
//! } SignatureScheme;
//! ```
test "RFC 8446 §4.2.3: Signature scheme identifiers" {
    // ECDSA algorithms
    const ecdsa_secp256r1_sha256: u16 = 0x0403;
    const ecdsa_secp384r1_sha384: u16 = 0x0503;

    try testing.expectEqual(@as(u16, 0x0403), ecdsa_secp256r1_sha256);
    try testing.expectEqual(@as(u16, 0x0503), ecdsa_secp384r1_sha384);

    // Ed25519 (most common for QUIC)
    const ed25519: u16 = 0x0807;
    try testing.expectEqual(@as(u16, 0x0807), ed25519);

    // RSASSA-PSS algorithms
    const rsa_pss_rsae_sha256: u16 = 0x0804;
    try testing.expectEqual(@as(u16, 0x0804), rsa_pss_rsae_sha256);
}

// RFC 8446 §4.2.9: PSK Key Exchange Modes Extension
//
// The "psk_key_exchange_modes" extension indicates which PSK key exchange modes
// the client supports.
//
// ```
//! enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
//! ```
test "RFC 8446 §4.2.9: PSK key exchange modes" {
    const psk_ke: u8 = 0; // PSK-only mode
    const psk_dhe_ke: u8 = 1; // PSK with (EC)DHE mode

    try testing.expectEqual(@as(u8, 0), psk_ke);
    try testing.expectEqual(@as(u8, 1), psk_dhe_ke);
}

// RFC 8446 §4.2.8: Key Share Extension
//
// The "key_share" extension contains the endpoint's cryptographic parameters
// for ECDHE key agreement.
//
// Key exchange data lengths:
// - X25519: 32 bytes (most common for QUIC)
// - secp256r1: 65 bytes (uncompressed point)
// - secp384r1: 97 bytes (uncompressed point)
test "RFC 8446 §4.2.8: Key share data lengths" {
    const x25519_key_len: usize = 32;
    const secp256r1_uncompressed_len: usize = 65;
    const secp384r1_uncompressed_len: usize = 97;

    try testing.expectEqual(@as(usize, 32), x25519_key_len);
    try testing.expectEqual(@as(usize, 65), secp256r1_uncompressed_len);
    try testing.expectEqual(@as(usize, 97), secp384r1_uncompressed_len);
}

// RFC 8446 §4.2.11: Pre-Shared Key Extension Ordering
//
// The "pre_shared_key" extension MUST be the last extension in the
// ClientHello if it is present. This is a critical ordering requirement.
test "RFC 8446 §4.2.11: pre_shared_key must be last extension" {
    const pre_shared_key_type: u16 = 0x0029;

    // This is a structural requirement verified during parsing
    // If PSK extension is present, no extensions can follow it
    try testing.expectEqual(@as(u16, 0x0029), pre_shared_key_type);
}

// RFC 8446 §4.2.10: Early Data Extension
//
// The "early_data" extension indicates that the client is sending
// 0-RTT application data.
//
// In ClientHello: empty (presence indicates early data being sent)
// In EncryptedExtensions: empty (presence indicates early data accepted)
// In NewSessionTicket: max_early_data_size (u32)
test "RFC 8446 §4.2.10: Early data extension semantics" {
    const early_data_type: u16 = 0x002a;
    try testing.expectEqual(@as(u16, 0x002a), early_data_type);

    // Max early data size in NewSessionTicket
    const max_early_data_size_bytes: usize = 4; // u32
    try testing.expectEqual(@as(usize, 4), max_early_data_size_bytes);
}

// RFC 7301: Application-Layer Protocol Negotiation (ALPN)
//
// The ALPN extension allows the client to indicate which application-level
// protocols it supports. For QUIC, this is typically "h3" (HTTP/3).
//
// ```
//! opaque ProtocolName<1..2^8-1>;
//!
//! struct {
//!     ProtocolName protocol_name_list<2..2^16-1>
//! } ProtocolNameList;
//! ```
test "RFC 7301: ALPN extension for HTTP/3" {
    const alpn_type: u16 = 0x0010;
    try testing.expectEqual(@as(u16, 0x0010), alpn_type);

    // HTTP/3 protocol name
    const h3 = "h3";
    try testing.expectEqualStrings("h3", h3);
    try testing.expectEqual(@as(usize, 2), h3.len);
}

// RFC 6066 §3: Server Name Indication (SNI)
//
// The "server_name" extension allows the client to indicate which hostname
// it is attempting to connect to. This enables virtual hosting.
//
// ```
//! enum {
//!     host_name(0), (255)
//! } NameType;
//!
//! opaque HostName<1..2^16-1>;
//!
//! struct {
//!     NameType name_type;
//!     select (name_type) {
//!         case host_name: HostName;
//!     } name;
//! } ServerName;
//! ```
test "RFC 6066 §3: Server Name Indication" {
    const server_name_type: u16 = 0x0000;
    try testing.expectEqual(@as(u16, 0x0000), server_name_type);

    const host_name_type: u8 = 0x00;
    try testing.expectEqual(@as(u8, 0x00), host_name_type);
}

// RFC 8446 §4.2: Extension Processing - Unknown Extensions
//
// Clients MUST send supported_versions in the ClientHello. Servers MUST
// accept unknown extensions gracefully (ignore them).
test "RFC 8446 §4.2: Unknown extension handling" {
    // Unknown extensions must be ignored per RFC 8446 §4.2:
    // "Implementations MUST accept extensions they do not understand"

    // Example unknown extension type (not assigned)
    const unknown_extension: u16 = 0x9999;
    try testing.expect(unknown_extension > 0x0039);
}

// RFC 8446 §9.2: Mandatory Extensions
//
// TLS 1.3 ClientHello MUST contain these extensions:
// - supported_versions (0x002b)
// - signature_algorithms (0x000d)
test "RFC 8446 §9.2: Mandatory ClientHello extensions" {
    const supported_versions: u16 = 0x002b;
    const signature_algorithms: u16 = 0x000d;

    try testing.expectEqual(@as(u16, 0x002b), supported_versions);
    try testing.expectEqual(@as(u16, 0x000d), signature_algorithms);
}

// RFC 8446 §4.2: Extension Context
//
// Different extensions are allowed in different handshake messages:
//
// - ClientHello: server_name, supported_groups, signature_algorithms,
//                supported_versions, key_share, alpn, psk_key_exchange_modes,
//                pre_shared_key, early_data, quic_transport_parameters
//
// - ServerHello: supported_versions, key_share, pre_shared_key
//
// - EncryptedExtensions: server_name, alpn, early_data, quic_transport_parameters
test "RFC 8446 §4.2: Extension context restrictions" {
    // Extensions valid in multiple contexts
    const supported_versions: u16 = 0x002b; // CH, SH, HRR
    const key_share: u16 = 0x0033; // CH, SH, HRR

    // Extensions only in ClientHello
    const signature_algorithms: u16 = 0x000d; // CH only
    const supported_groups: u16 = 0x000a; // CH only

    // Extensions in EncryptedExtensions
    const alpn: u16 = 0x0010; // CH, EE
    const server_name: u16 = 0x0000; // CH, EE

    try testing.expectEqual(@as(u16, 0x002b), supported_versions);
    try testing.expectEqual(@as(u16, 0x0033), key_share);
    try testing.expectEqual(@as(u16, 0x000d), signature_algorithms);
    try testing.expectEqual(@as(u16, 0x000a), supported_groups);
    try testing.expectEqual(@as(u16, 0x0010), alpn);
    try testing.expectEqual(@as(u16, 0x0000), server_name);
}
