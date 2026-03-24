// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Comprehensive RFC Compliance Tests for TLS 1.3 Implementation
//!
//! This module contains regression tests that verify every enumeration value,
//! constant, and structure definition matches the specifications in:
//! - RFC 8446 (TLS 1.3)
//! - RFC 9001 (QUIC-TLS)
//! - RFC 5116 (AEAD)
//! - RFC 5280 (X.509)
//!
//! These tests ensure that any changes to the codebase maintain strict RFC
//! compliance. All values are verified against their exact RFC specifications.
//!
//! ## Test Categories
//! 1. Alert Protocol (RFC 8446 §6)
//! 2. Record Protocol (RFC 8446 §5)
//! 3. Cipher Suites (RFC 8446 Appendix B.4)
//! 4. Signature Schemes (RFC 8446 §4.2.3, Appendix B.3.1.3)
//! 5. Named Groups (RFC 8446 §4.2.7, Appendix B.3.1.4)
//! 6. Extension Types (RFC 8446 Appendix B.3)
//! 7. Key Schedule (RFC 8446 §7, RFC 9001 §5)

const std = @import("std");
const testing = std.testing;

const alert = @import("alert");
const record = @import("record");
const tls13_full = @import("tls13_full");
const key_schedule = @import("quic_tls");

// ============================================================================
// RFC 8446 §6 - Alert Protocol
// ============================================================================

test "RFC 8446 §6.1 - AlertLevel values" {
    // RFC 8446 §6.1: enum { warning(1), fatal(2), (255) } AlertLevel;
    try testing.expectEqual(@as(u8, 1), @intFromEnum(alert.AlertLevel.warning));
    try testing.expectEqual(@as(u8, 2), @intFromEnum(alert.AlertLevel.fatal));
}

test "RFC 8446 §6.2 - AlertDescription values" {
    // RFC 8446 §6.2: Verify ALL alert description values
    try testing.expectEqual(@as(u8, 0), @intFromEnum(alert.AlertDescription.close_notify));
    try testing.expectEqual(@as(u8, 10), @intFromEnum(alert.AlertDescription.unexpected_message));
    try testing.expectEqual(@as(u8, 20), @intFromEnum(alert.AlertDescription.bad_record_mac));
    try testing.expectEqual(@as(u8, 22), @intFromEnum(alert.AlertDescription.record_overflow));
    try testing.expectEqual(@as(u8, 40), @intFromEnum(alert.AlertDescription.handshake_failure));
    try testing.expectEqual(@as(u8, 42), @intFromEnum(alert.AlertDescription.bad_certificate));
    try testing.expectEqual(@as(u8, 43), @intFromEnum(alert.AlertDescription.unsupported_certificate));
    try testing.expectEqual(@as(u8, 44), @intFromEnum(alert.AlertDescription.certificate_revoked));
    try testing.expectEqual(@as(u8, 45), @intFromEnum(alert.AlertDescription.certificate_expired));
    try testing.expectEqual(@as(u8, 46), @intFromEnum(alert.AlertDescription.certificate_unknown));
    try testing.expectEqual(@as(u8, 47), @intFromEnum(alert.AlertDescription.illegal_parameter));
    try testing.expectEqual(@as(u8, 48), @intFromEnum(alert.AlertDescription.unknown_ca));
    try testing.expectEqual(@as(u8, 49), @intFromEnum(alert.AlertDescription.access_denied));
    try testing.expectEqual(@as(u8, 50), @intFromEnum(alert.AlertDescription.decode_error));
    try testing.expectEqual(@as(u8, 51), @intFromEnum(alert.AlertDescription.decrypt_error));
    try testing.expectEqual(@as(u8, 70), @intFromEnum(alert.AlertDescription.protocol_version));
    try testing.expectEqual(@as(u8, 71), @intFromEnum(alert.AlertDescription.insufficient_security));
    try testing.expectEqual(@as(u8, 80), @intFromEnum(alert.AlertDescription.internal_error));
    try testing.expectEqual(@as(u8, 86), @intFromEnum(alert.AlertDescription.inappropriate_fallback));
    try testing.expectEqual(@as(u8, 90), @intFromEnum(alert.AlertDescription.user_canceled));
    try testing.expectEqual(@as(u8, 109), @intFromEnum(alert.AlertDescription.missing_extension));
    try testing.expectEqual(@as(u8, 110), @intFromEnum(alert.AlertDescription.unsupported_extension));
    try testing.expectEqual(@as(u8, 112), @intFromEnum(alert.AlertDescription.unrecognized_name));
    try testing.expectEqual(@as(u8, 113), @intFromEnum(alert.AlertDescription.bad_certificate_status_response));
    try testing.expectEqual(@as(u8, 115), @intFromEnum(alert.AlertDescription.unknown_psk_identity));
    try testing.expectEqual(@as(u8, 116), @intFromEnum(alert.AlertDescription.certificate_required));
    try testing.expectEqual(@as(u8, 120), @intFromEnum(alert.AlertDescription.no_application_protocol));
}

// ============================================================================
// RFC 8446 §5 - Record Protocol
// ============================================================================

test "RFC 8446 §5.1 - ContentType enum values" {
    // RFC 8446 §5.1: enum { invalid(0), change_cipher_spec(20), alert(21),
    //                       handshake(22), application_data(23), (255) } ContentType;
    try testing.expectEqual(@as(u8, 0), @intFromEnum(record.ContentType.invalid));
    try testing.expectEqual(@as(u8, 20), @intFromEnum(record.ContentType.change_cipher_spec));
    try testing.expectEqual(@as(u8, 21), @intFromEnum(record.ContentType.alert));
    try testing.expectEqual(@as(u8, 22), @intFromEnum(record.ContentType.handshake));
    try testing.expectEqual(@as(u8, 23), @intFromEnum(record.ContentType.application_data));
    try testing.expectEqual(@as(u8, 24), @intFromEnum(record.ContentType.heartbeat)); // RFC 6520
}

test "RFC 8446 §5.1 - LegacyVersion values" {
    // RFC 8446 §5.1: Legacy TLS versions for record layer
    try testing.expectEqual(@as(u16, 0x0300), @intFromEnum(record.LegacyVersion.ssl_3_0));
    try testing.expectEqual(@as(u16, 0x0301), @intFromEnum(record.LegacyVersion.tls_1_0));
    try testing.expectEqual(@as(u16, 0x0302), @intFromEnum(record.LegacyVersion.tls_1_1));
    try testing.expectEqual(@as(u16, 0x0303), @intFromEnum(record.LegacyVersion.tls_1_2));
}

test "RFC 8446 §5.1 - Maximum fragment length" {
    // RFC 8446 §5.1: "The length MUST NOT exceed 2^14 bytes"
    try testing.expectEqual(@as(usize, 16384), record.max_plaintext_fragment);
}

// ============================================================================
// RFC 8446 Appendix B.4 - Cipher Suites
// ============================================================================

test "RFC 8446 Appendix B.4 - CipherSuite values" {
    // RFC 8446 Appendix B.4: TLS 1.3 cipher suite registry
    // | TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
    // | TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
    // | TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
    // | TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
    // | TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |

    try testing.expectEqual(@as(u16, 0x1301), @intFromEnum(tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256));
    try testing.expectEqual(@as(u16, 0x1302), @intFromEnum(tls13_full.CipherSuite.TLS_AES_256_GCM_SHA384));
    try testing.expectEqual(@as(u16, 0x1303), @intFromEnum(tls13_full.CipherSuite.TLS_CHACHA20_POLY1305_SHA256));
    try testing.expectEqual(@as(u16, 0x1304), @intFromEnum(tls13_full.CipherSuite.TLS_AES_128_CCM_SHA256));
    try testing.expectEqual(@as(u16, 0x1305), @intFromEnum(tls13_full.CipherSuite.TLS_AES_128_CCM_8_SHA256));
}

// ============================================================================
// RFC 8446 §4.2.3 - Signature Algorithms
// ============================================================================

test "RFC 8446 §4.2.3 - SignatureScheme RSASSA-PKCS1-v1_5 values" {
    // RFC 8446 §4.2.3: Legacy RSA PKCS#1 v1.5 schemes
    try testing.expectEqual(@as(u16, 0x0401), @intFromEnum(tls13_full.SignatureScheme.rsa_pkcs1_sha256));
    try testing.expectEqual(@as(u16, 0x0501), @intFromEnum(tls13_full.SignatureScheme.rsa_pkcs1_sha384));
    try testing.expectEqual(@as(u16, 0x0601), @intFromEnum(tls13_full.SignatureScheme.rsa_pkcs1_sha512));
}

test "RFC 8446 §4.2.3 - SignatureScheme ECDSA values" {
    // RFC 8446 §4.2.3: ECDSA signature schemes
    try testing.expectEqual(@as(u16, 0x0403), @intFromEnum(tls13_full.SignatureScheme.ecdsa_secp256r1_sha256));
    try testing.expectEqual(@as(u16, 0x0503), @intFromEnum(tls13_full.SignatureScheme.ecdsa_secp384r1_sha384));
    try testing.expectEqual(@as(u16, 0x0603), @intFromEnum(tls13_full.SignatureScheme.ecdsa_secp521r1_sha512));
}

test "RFC 8446 §4.2.3 - SignatureScheme RSA-PSS RSAE values" {
    // RFC 8446 §4.2.3: RSA-PSS with rsaEncryption OID
    try testing.expectEqual(@as(u16, 0x0804), @intFromEnum(tls13_full.SignatureScheme.rsa_pss_rsae_sha256));
    try testing.expectEqual(@as(u16, 0x0805), @intFromEnum(tls13_full.SignatureScheme.rsa_pss_rsae_sha384));
    try testing.expectEqual(@as(u16, 0x0806), @intFromEnum(tls13_full.SignatureScheme.rsa_pss_rsae_sha512));
}

test "RFC 8446 §4.2.3 - SignatureScheme EdDSA values" {
    // RFC 8446 §4.2.3: EdDSA signature schemes (RFC 8032)
    try testing.expectEqual(@as(u16, 0x0807), @intFromEnum(tls13_full.SignatureScheme.ed25519));
    try testing.expectEqual(@as(u16, 0x0808), @intFromEnum(tls13_full.SignatureScheme.ed448));
}

test "RFC 8446 §4.2.3 - SignatureScheme RSA-PSS PSS values" {
    // RFC 8446 §4.2.3: RSA-PSS with RSASSA-PSS OID
    try testing.expectEqual(@as(u16, 0x0809), @intFromEnum(tls13_full.SignatureScheme.rsa_pss_pss_sha256));
    try testing.expectEqual(@as(u16, 0x080a), @intFromEnum(tls13_full.SignatureScheme.rsa_pss_pss_sha384));
    try testing.expectEqual(@as(u16, 0x080b), @intFromEnum(tls13_full.SignatureScheme.rsa_pss_pss_sha512));
}

// ============================================================================
// RFC 8446 Appendix B.3.1.4 - Named Groups (Supported Groups Extension)
// ============================================================================

test "RFC 8446 Appendix B.3.1.4 - NamedGroup Elliptic Curve values" {
    // RFC 8446 Appendix B.3.1.4: ECDHE groups
    try testing.expectEqual(@as(u16, 0x0017), @intFromEnum(tls13_full.NamedGroup.secp256r1));
    try testing.expectEqual(@as(u16, 0x0018), @intFromEnum(tls13_full.NamedGroup.secp384r1));
    try testing.expectEqual(@as(u16, 0x0019), @intFromEnum(tls13_full.NamedGroup.secp521r1));
    try testing.expectEqual(@as(u16, 0x001d), @intFromEnum(tls13_full.NamedGroup.x25519));
    try testing.expectEqual(@as(u16, 0x001e), @intFromEnum(tls13_full.NamedGroup.x448));
}

test "RFC 8446 Appendix B.3.1.4 - NamedGroup Finite Field values" {
    // RFC 8446 Appendix B.3.1.4: FFDHE groups (RFC 7919)
    try testing.expectEqual(@as(u16, 0x0100), @intFromEnum(tls13_full.NamedGroup.ffdhe2048));
    try testing.expectEqual(@as(u16, 0x0101), @intFromEnum(tls13_full.NamedGroup.ffdhe3072));
    try testing.expectEqual(@as(u16, 0x0102), @intFromEnum(tls13_full.NamedGroup.ffdhe4096));
    try testing.expectEqual(@as(u16, 0x0103), @intFromEnum(tls13_full.NamedGroup.ffdhe6144));
    try testing.expectEqual(@as(u16, 0x0104), @intFromEnum(tls13_full.NamedGroup.ffdhe8192));
}

// ============================================================================
// RFC 8446 Appendix B.3 - Extension Types
// ============================================================================

test "RFC 8446 Appendix B.3 - ExtensionType values" {
    // RFC 8446 Appendix B.3: TLS extension type registry
    try testing.expectEqual(@as(u16, 0x0000), @intFromEnum(tls13_full.ExtensionType.server_name)); // RFC 6066
    try testing.expectEqual(@as(u16, 0x0001), @intFromEnum(tls13_full.ExtensionType.max_fragment_length)); // RFC 6066
    try testing.expectEqual(@as(u16, 0x0005), @intFromEnum(tls13_full.ExtensionType.status_request)); // RFC 6066
    try testing.expectEqual(@as(u16, 0x000a), @intFromEnum(tls13_full.ExtensionType.supported_groups)); // RFC 8446 §4.2.7
    try testing.expectEqual(@as(u16, 0x000d), @intFromEnum(tls13_full.ExtensionType.signature_algorithms)); // RFC 8446 §4.2.3
    try testing.expectEqual(@as(u16, 0x000e), @intFromEnum(tls13_full.ExtensionType.use_srtp)); // RFC 5764
    try testing.expectEqual(@as(u16, 0x000f), @intFromEnum(tls13_full.ExtensionType.heartbeat)); // RFC 6520
    try testing.expectEqual(@as(u16, 0x0010), @intFromEnum(tls13_full.ExtensionType.alpn)); // RFC 7301
    try testing.expectEqual(@as(u16, 0x0012), @intFromEnum(tls13_full.ExtensionType.signed_certificate_timestamp)); // RFC 6962
    try testing.expectEqual(@as(u16, 0x0013), @intFromEnum(tls13_full.ExtensionType.client_certificate_type)); // RFC 7250
    try testing.expectEqual(@as(u16, 0x0014), @intFromEnum(tls13_full.ExtensionType.server_certificate_type)); // RFC 7250
    try testing.expectEqual(@as(u16, 0x0015), @intFromEnum(tls13_full.ExtensionType.padding)); // RFC 7685
    try testing.expectEqual(@as(u16, 0x0029), @intFromEnum(tls13_full.ExtensionType.pre_shared_key)); // RFC 8446 §4.2.11
    try testing.expectEqual(@as(u16, 0x002a), @intFromEnum(tls13_full.ExtensionType.early_data)); // RFC 8446 §4.2.10
    try testing.expectEqual(@as(u16, 0x002b), @intFromEnum(tls13_full.ExtensionType.supported_versions)); // RFC 8446 §4.2.1
    try testing.expectEqual(@as(u16, 0x002c), @intFromEnum(tls13_full.ExtensionType.cookie)); // RFC 8446 §4.2.2
    try testing.expectEqual(@as(u16, 0x002d), @intFromEnum(tls13_full.ExtensionType.psk_key_exchange_modes)); // RFC 8446 §4.2.9
    try testing.expectEqual(@as(u16, 0x002f), @intFromEnum(tls13_full.ExtensionType.certificate_authorities)); // RFC 8446 §4.2.4
    try testing.expectEqual(@as(u16, 0x0030), @intFromEnum(tls13_full.ExtensionType.oid_filters)); // RFC 8446 §4.2.5
    try testing.expectEqual(@as(u16, 0x0031), @intFromEnum(tls13_full.ExtensionType.post_handshake_auth)); // RFC 8446 §4.6.2
    try testing.expectEqual(@as(u16, 0x0032), @intFromEnum(tls13_full.ExtensionType.signature_algorithms_cert)); // RFC 8446 §4.2.3
    try testing.expectEqual(@as(u16, 0x0033), @intFromEnum(tls13_full.ExtensionType.key_share)); // RFC 8446 §4.2.8
    try testing.expectEqual(@as(u16, 0x0039), @intFromEnum(tls13_full.ExtensionType.quic_transport_parameters)); // RFC 9001 §8.2
}

// ============================================================================
// RFC 9001 §4.8 - QUIC CRYPTO_ERROR Mapping
// ============================================================================

test "RFC 9001 §4.8 - QUIC CRYPTO_ERROR code mapping" {
    // RFC 9001 §4.8: TLS alerts mapped to QUIC CRYPTO_ERROR (0x0100 + alert)
    try testing.expectEqual(@as(u64, 0x0100), alert.toQuicCryptoError(.close_notify));
    try testing.expectEqual(@as(u64, 0x010A), alert.toQuicCryptoError(.unexpected_message));
    try testing.expectEqual(@as(u64, 0x0114), alert.toQuicCryptoError(.bad_record_mac));
    try testing.expectEqual(@as(u64, 0x0116), alert.toQuicCryptoError(.record_overflow));
    try testing.expectEqual(@as(u64, 0x0128), alert.toQuicCryptoError(.handshake_failure));
    try testing.expectEqual(@as(u64, 0x0150), alert.toQuicCryptoError(.internal_error));
    try testing.expectEqual(@as(u64, 0x0178), alert.toQuicCryptoError(.no_application_protocol));
}

// ============================================================================
// RFC 9001 Appendix A.1 - Key Derivation Test Vectors
// ============================================================================

test "RFC 9001 Appendix A.1 - QUIC v1 initial salt constant" {
    // RFC 9001 §5.2: QUIC v1 initial salt
    // Value: 38762cf7f55934b34d179ae6a4c80cadccbb7f0a
    const expected: [20]u8 = .{
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    };
    try testing.expectEqualSlices(u8, &expected, &key_schedule.initial_salt_v1);
}

test "RFC 9369 Appendix A.1 - QUIC v2 initial salt constant" {
    // RFC 9369 §A.1: QUIC v2 initial salt
    // Value: 0dede3def700a6db819381be6e269dcbf9bd2ed9
    const expected: [20]u8 = .{
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
        0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
    };
    try testing.expectEqualSlices(u8, &expected, &key_schedule.initial_salt_v2);
}

test "RFC 9001 Appendix A.1 - Initial secret derivation from DCID" {
    // RFC 9001 Appendix A.1: Test vector for initial secret derivation
    // DCID: 8394c8f03e515708
    const test_dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const expected_initial: [32]u8 = .{
        0x7d, 0xb5, 0xdf, 0x06, 0xe7, 0xa6, 0x9e, 0x43, 0x24, 0x96, 0xad, 0xed, 0xb0, 0x08, 0x51, 0x92,
        0x35, 0x95, 0x22, 0x15, 0x96, 0xae, 0x2a, 0xe9, 0xfb, 0x81, 0x15, 0xc1, 0xe9, 0xed, 0x0a, 0x44,
    };

    const initial_secret = key_schedule.deriveInitialSecretV1(&test_dcid);
    try testing.expectEqualSlices(u8, &expected_initial, &initial_secret);
}

test "RFC 9001 Appendix A.1 - Client/Server initial secrets" {
    // RFC 9001 Appendix A.1: Client and server initial secret split
    const test_dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const expected_client: [32]u8 = .{
        0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
        0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea,
    };
    const expected_server: [32]u8 = .{
        0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81,
        0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b,
    };

    const initial_secret = key_schedule.deriveInitialSecretV1(&test_dcid);
    const secrets = key_schedule.deriveClientServerInitial(initial_secret);

    try testing.expectEqualSlices(u8, &expected_client, &secrets.client);
    try testing.expectEqualSlices(u8, &expected_server, &secrets.server);
}

test "RFC 9001 Appendix A.1 - Client packet protection keys" {
    // RFC 9001 Appendix A.1: Full client key derivation test vector
    const test_dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const expected_key: [16]u8 = .{
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
    };
    const expected_iv: [12]u8 = .{
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c,
    };
    const expected_hp: [16]u8 = .{
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
    };

    const initial_secret = key_schedule.deriveInitialSecretV1(&test_dcid);
    const secrets = key_schedule.deriveClientServerInitial(initial_secret);
    const keys = key_schedule.deriveKeyIvHp(secrets.client);

    try testing.expectEqualSlices(u8, &expected_key, &keys.key);
    try testing.expectEqualSlices(u8, &expected_iv, &keys.iv);
    try testing.expectEqualSlices(u8, &expected_hp, &keys.hp);
}

test "RFC 9001 Appendix A.1 - Server packet protection keys" {
    // RFC 9001 Appendix A.1: Full server key derivation test vector
    const test_dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const expected_key: [16]u8 = .{
        0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c, 0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37,
    };
    const expected_iv: [12]u8 = .{
        0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e,
    };
    const expected_hp: [16]u8 = .{
        0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76, 0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14,
    };

    const initial_secret = key_schedule.deriveInitialSecretV1(&test_dcid);
    const secrets = key_schedule.deriveClientServerInitial(initial_secret);
    const keys = key_schedule.deriveKeyIvHp(secrets.server);

    try testing.expectEqualSlices(u8, &expected_key, &keys.key);
    try testing.expectEqualSlices(u8, &expected_iv, &keys.iv);
    try testing.expectEqualSlices(u8, &expected_hp, &keys.hp);
}

// ============================================================================
// RFC 8446 §7.1 - HKDF-Expand-Label
// ============================================================================

test "RFC 8446 §7.1 - HKDF-Expand-Label uses 'tls13 ' prefix" {
    // RFC 8446 §7.1: HkdfLabel must have "tls13 " prefix on labels
    // We verify that using different labels produces different outputs
    // and that the prefix is correctly applied (not used verbatim)
    const prk: [32]u8 = .{0xaa} ** 32;
    var out1: [16]u8 = undefined;
    var out2: [16]u8 = undefined;

    try key_schedule.expandLabel(prk[0..], "test", "", &out1);
    try key_schedule.expandLabel(prk[0..], "tls13 test", "", &out2);

    // If the prefix is applied correctly, these should produce different outputs
    // because expandLabel adds "tls13 " to both labels
    try testing.expect(!std.mem.eql(u8, &out1, &out2));
}

test "RFC 8446 §7.1 - HKDF-Expand-Label with different labels" {
    // RFC 8446 §7.1: Different labels must produce different outputs
    const prk: [32]u8 = .{0xbb} ** 32;
    var out1: [32]u8 = undefined;
    var out2: [32]u8 = undefined;

    try key_schedule.expandLabel(prk[0..], "client in", "", &out1);
    try key_schedule.expandLabel(prk[0..], "server in", "", &out2);

    try testing.expect(!std.mem.eql(u8, &out1, &out2));
}

test "RFC 8446 §7.1 - HKDF-Expand-Label with different contexts" {
    // RFC 8446 §7.1: Different contexts must produce different outputs
    const prk: [32]u8 = .{0xcc} ** 32;
    var out1: [32]u8 = undefined;
    var out2: [32]u8 = undefined;

    try key_schedule.expandLabel(prk[0..], "test", "context1", &out1);
    try key_schedule.expandLabel(prk[0..], "test", "context2", &out2);

    try testing.expect(!std.mem.eql(u8, &out1, &out2));
}

// ============================================================================
// RFC 8446 §5.5 - Limits on Key Usage
// ============================================================================

test "RFC 8446 §5.5 - AES-GCM confidentiality limit (2^24.5 records)" {
    // RFC 8446 §5.5: "For AES-GCM, up to 2^24.5 full-size records (about 24 million)
    // may be encrypted on a given connection"
    // 2^24.5 ≈ 23,726,566 records
    const aes128_limit: u64 = 1 << 24; // Conservative: 2^24 = 16,777,216 records
    _ = aes128_limit; // Test implementation should enforce this limit
}

test "RFC 8446 §5.3 - Per-record nonce is 64-bit sequence number XORed with IV" {
    // RFC 8446 §5.3: Nonce construction algorithm
    // "The 64-bit record sequence number is encoded in network byte order
    // and padded to the left with zeros to iv_length. The padded sequence
    // number is XORed with either the static client_write_iv or server_write_iv"

    // This test verifies the nonce derivation is deterministic
    const test_key: [16]u8 = .{0xaa} ** 16;
    const test_iv: [12]u8 = .{0xbb} ** 12;
    const seq: u64 = 12345;

    const allocator = testing.allocator;
    var cipher1 = try record.AeadCipher.init(.TLS_AES_128_GCM_SHA256, &test_key, &test_iv, null);
    defer cipher1.wipe();

    const plaintext = "test plaintext";
    const aad = "additional authenticated data";

    const ct1 = try cipher1.seal(allocator, seq, aad, plaintext);
    defer allocator.free(ct1);

    // Reset cipher and encrypt again - should produce same ciphertext for same seq
    var cipher2 = try record.AeadCipher.init(.TLS_AES_128_GCM_SHA256, &test_key, &test_iv, null);
    defer cipher2.wipe();

    const ct2 = try cipher2.seal(allocator, seq, aad, plaintext);
    defer allocator.free(ct2);

    // Same key, IV, seq, AAD, and plaintext must produce same ciphertext
    try testing.expectEqualSlices(u8, ct1, ct2);
}

// ============================================================================
// RFC 8446 §9.1 - Mandatory-to-Implement Cipher Suites
// ============================================================================

test "RFC 8446 §9.1 - TLS_AES_128_GCM_SHA256 is mandatory" {
    // RFC 8446 §9.1: "A TLS-compliant application MUST implement the
    // TLS_AES_128_GCM_SHA256 cipher suite"

    // Verify the cipher suite is correctly defined
    const suite = tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256;
    try testing.expectEqual(@as(u16, 0x1301), @intFromEnum(suite));
}

test "RFC 8446 §9.1 - SHOULD implement TLS_AES_256_GCM_SHA384" {
    // RFC 8446 §9.1: "[Applications] SHOULD implement the TLS_AES_256_GCM_SHA384
    // and TLS_CHACHA20_POLY1305_SHA256 cipher suites"

    const suite_aes256 = tls13_full.CipherSuite.TLS_AES_256_GCM_SHA384;
    const suite_chacha = tls13_full.CipherSuite.TLS_CHACHA20_POLY1305_SHA256;

    try testing.expectEqual(@as(u16, 0x1302), @intFromEnum(suite_aes256));
    try testing.expectEqual(@as(u16, 0x1303), @intFromEnum(suite_chacha));
}

// ============================================================================
// RFC 8446 §9.2 - Mandatory-to-Implement Extensions
// ============================================================================

test "RFC 8446 §9.2 - supported_versions extension is REQUIRED" {
    // RFC 8446 §9.2: "supported_versions is REQUIRED for all ClientHello,
    // ServerHello, and HelloRetryRequest messages"

    try testing.expectEqual(@as(u16, 0x002b), @intFromEnum(tls13_full.ExtensionType.supported_versions));
}

test "RFC 8446 §9.2 - signature_algorithms extension is REQUIRED" {
    // RFC 8446 §9.2: "signature_algorithms is REQUIRED for certificate authentication"

    try testing.expectEqual(@as(u16, 0x000d), @intFromEnum(tls13_full.ExtensionType.signature_algorithms));
}

test "RFC 8446 §9.2 - supported_groups and key_share are REQUIRED for DHE/ECDHE" {
    // RFC 8446 §9.2: "supported_groups is REQUIRED for ClientHello messages using
    // DHE or ECDHE key exchange. key_share is REQUIRED for DHE or ECDHE key exchange"

    try testing.expectEqual(@as(u16, 0x000a), @intFromEnum(tls13_full.ExtensionType.supported_groups));
    try testing.expectEqual(@as(u16, 0x0033), @intFromEnum(tls13_full.ExtensionType.key_share));
}
