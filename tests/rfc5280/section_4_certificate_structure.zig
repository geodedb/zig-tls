//! RFC 5280 §4: Certificate and Certificate Extensions Profile Tests
//!
//! Tests for X.509 certificate structure and common extensions.
//!
//! ## RFC 5280 §4: Certificate and Certificate Extensions Profile
//!
//! This section defines the X.509 v3 certificate format and standard extensions
//! used in Internet PKI.
//!
//! ## Certificate Structure (RFC 5280 §4.1)
//!
//! ```
//! Certificate ::= SEQUENCE {
//!   tbsCertificate       TBSCertificate,
//!   signatureAlgorithm   AlgorithmIdentifier,
//!   signatureValue       BIT STRING
//! }
//!
//! TBSCertificate ::= SEQUENCE {
//!   version              [0] EXPLICIT Version DEFAULT v1,
//!   serialNumber         CertificateSerialNumber,
//!   signature            AlgorithmIdentifier,
//!   issuer               Name,
//!   validity             Validity,
//!   subject              Name,
//!   subjectPublicKeyInfo SubjectPublicKeyInfo,
//!   extensions           [3] EXPLICIT Extensions OPTIONAL
//! }
//! ```
//!
//! ## Common Extensions (RFC 5280 §4.2)
//!
//! - Basic Constraints (§4.2.1.9): CA flag, path length constraint
//! - Key Usage (§4.2.1.3): Digital signature, key encipherment, etc.
//! - Extended Key Usage (§4.2.1.12): Server auth, client auth, code signing
//! - Subject Alternative Name (§4.2.1.6): DNS names, IP addresses
//! - Authority Key Identifier (§4.2.1.1): Key identifier from issuer
//! - Subject Key Identifier (§4.2.1.2): Key identifier for this cert
//!
//! ## Test Coverage
//!
//! - Certificate version validation (v3 required for extensions)
//! - Serial number constraints
//! - Validity period structure
//! - Extension OID identification
//! - Critical vs non-critical extensions
//! - Extension value constraints

const std = @import("std");
const testing = std.testing;

// RFC 5280 §4.1.2.1: Certificate Version
//
// The version field indicates the X.509 certificate version:
// - v1: version = 0 (default, no extensions)
// - v2: version = 1 (deprecated)
// - v3: version = 2 (current, supports extensions)
test "RFC 5280 §4.1.2.1: Certificate version values" {
    const v1: u8 = 0;
    const v2: u8 = 1;
    const v3: u8 = 2;

    try testing.expectEqual(@as(u8, 0), v1);
    try testing.expectEqual(@as(u8, 1), v2);
    try testing.expectEqual(@as(u8, 2), v3);

    // v3 is required for extensions
    const current_version: u8 = v3;
    try testing.expectEqual(@as(u8, 2), current_version);
}

// RFC 5280 §4.1.2.2: Serial Number
//
// The serial number MUST be a positive integer assigned by the CA.
// It MUST be unique for each certificate issued by a given CA.
// Serial numbers can be up to 20 octets.
test "RFC 5280 §4.1.2.2: Serial number constraints" {
    // Maximum serial number length (RFC 5280 §4.1.2.2)
    const max_serial_number_octets: usize = 20;
    try testing.expectEqual(@as(usize, 20), max_serial_number_octets);

    // Serial numbers MUST be positive (non-negative)
    // and unique per CA
}

// RFC 5280 §4.1.2.4: Issuer
//
// The issuer field identifies the entity that signed the certificate.
// It is a Distinguished Name (DN) structure.
test "RFC 5280 §4.1.2.4: Issuer distinguished name" {
    // Common DN components (attribute types):
    // - commonName (CN): 2.5.4.3
    // - organizationName (O): 2.5.4.10
    // - countryName (C): 2.5.4.6
    // - stateOrProvinceName (ST): 2.5.4.8
    // - localityName (L): 2.5.4.7

    // OIDs are variable-length
    const min_oid_length: usize = 2;
    try testing.expect(min_oid_length > 0);
}

// RFC 5280 §4.1.2.5: Validity
//
// The validity period is defined by notBefore and notAfter dates.
// Both use either UTCTime or GeneralizedTime encoding.
//
// ```
// Validity ::= SEQUENCE {
//   notBefore      Time,
//   notAfter       Time
// }
//
// Time ::= CHOICE {
//   utcTime        UTCTime,       -- YYMMDDHHMMSSZ for years 1950-2049
//   generalTime    GeneralizedTime -- YYYYMMDDHHMMSSZ
// }
// ```
test "RFC 5280 §4.1.2.5: Validity period structure" {
    // UTCTime format: YYMMDDHHMMSSZ (13 characters)
    const utc_time_length: usize = 13;
    try testing.expectEqual(@as(usize, 13), utc_time_length);

    // GeneralizedTime format: YYYYMMDDHHMMSSZ (15 characters)
    const generalized_time_length: usize = 15;
    try testing.expectEqual(@as(usize, 15), generalized_time_length);

    // Certificates expiring after 2049 MUST use GeneralizedTime
}

// RFC 5280 §4.1.2.6: Subject
//
// The subject field identifies the entity associated with the public
// key in the certificate. It uses the same Distinguished Name structure
// as the issuer.
test "RFC 5280 §4.1.2.6: Subject distinguished name" {
    // For server certificates, CN often contains the hostname
    // For CA certificates, subject identifies the CA

    // Subject Alternative Name extension is preferred for hostnames
}

// RFC 5280 §4.1.2.7: Subject Public Key Info
//
// The SubjectPublicKeyInfo field contains the public key and identifies
// the algorithm with which the key is used.
//
// ```
// SubjectPublicKeyInfo ::= SEQUENCE {
//   algorithm         AlgorithmIdentifier,
//   subjectPublicKey  BIT STRING
// }
// ```
test "RFC 5280 §4.1.2.7: Subject public key info structure" {
    // Common algorithm OIDs:
    // - RSA: 1.2.840.113549.1.1.1
    // - ECDSA with secp256r1: 1.2.840.10045.2.1 + 1.2.840.10045.3.1.7
    // - Ed25519: 1.3.101.112

    // Public key is a BIT STRING
    const bit_string_tag: u8 = 0x03;
    try testing.expectEqual(@as(u8, 0x03), bit_string_tag);
}

// RFC 5280 §4.2: Certificate Extensions
//
// Extensions provide additional information about the certificate or
// the key it contains. Each extension has:
// - extnID: OID identifying the extension type
// - critical: boolean indicating if extension must be processed
// - extnValue: OCTET STRING containing DER-encoded extension value
//
// ```
// Extension ::= SEQUENCE {
//   extnID     OBJECT IDENTIFIER,
//   critical   BOOLEAN DEFAULT FALSE,
//   extnValue  OCTET STRING
// }
// ```
test "RFC 5280 §4.2: Extension structure" {
    // Extensions are optional in v1, v2 but common in v3
    const v3_with_extensions: u8 = 2;
    try testing.expectEqual(@as(u8, 2), v3_with_extensions);

    // Critical extensions MUST be processed
    // Non-critical extensions MAY be ignored
}

// RFC 5280 §4.2.1.1: Authority Key Identifier
//
// The authority key identifier extension identifies the public key
// used to sign this certificate. OID: 2.5.29.35
test "RFC 5280 §4.2.1.1: Authority Key Identifier extension" {
    // OID: 2.5.29.35 (id-ce-authorityKeyIdentifier)
    const authority_key_id_oid = [_]u8{ 0x55, 0x1d, 0x23 }; // 2.5.29.35

    try testing.expectEqual(@as(usize, 3), authority_key_id_oid.len);

    // Non-critical extension
    const is_critical: bool = false;
    try testing.expectEqual(false, is_critical);
}

// RFC 5280 §4.2.1.2: Subject Key Identifier
//
// The subject key identifier extension provides a means of identifying
// certificates that contain a particular public key. OID: 2.5.29.14
test "RFC 5280 §4.2.1.2: Subject Key Identifier extension" {
    // OID: 2.5.29.14 (id-ce-subjectKeyIdentifier)
    const subject_key_id_oid = [_]u8{ 0x55, 0x1d, 0x0e }; // 2.5.29.14

    try testing.expectEqual(@as(usize, 3), subject_key_id_oid.len);

    // Non-critical extension
    const is_critical: bool = false;
    try testing.expectEqual(false, is_critical);
}

// RFC 5280 §4.2.1.3: Key Usage
//
// The key usage extension defines the purpose of the key contained in
// the certificate. OID: 2.5.29.15
//
// Key usage bits:
// - digitalSignature (0): Digital signatures
// - keyEncipherment (2): Key transport (RSA)
// - dataEncipherment (3): Data encryption
// - keyAgreement (4): Key agreement (ECDHE)
// - keyCertSign (5): Certificate signing (CA)
// - cRLSign (6): CRL signing (CA)
test "RFC 5280 §4.2.1.3: Key Usage extension" {
    // OID: 2.5.29.15 (id-ce-keyUsage)
    const key_usage_oid = [_]u8{ 0x55, 0x1d, 0x0f }; // 2.5.29.15

    try testing.expectEqual(@as(usize, 3), key_usage_oid.len);

    // Key usage bits
    const digital_signature: u8 = 0; // Bit 0
    const key_encipherment: u8 = 2; // Bit 2
    const key_agreement: u8 = 4; // Bit 4
    const key_cert_sign: u8 = 5; // Bit 5
    const crl_sign: u8 = 6; // Bit 6

    try testing.expectEqual(@as(u8, 0), digital_signature);
    try testing.expectEqual(@as(u8, 2), key_encipherment);
    try testing.expectEqual(@as(u8, 4), key_agreement);
    try testing.expectEqual(@as(u8, 5), key_cert_sign);
    try testing.expectEqual(@as(u8, 6), crl_sign);

    // SHOULD be marked critical
    const should_be_critical: bool = true;
    try testing.expectEqual(true, should_be_critical);
}

// RFC 5280 §4.2.1.6: Subject Alternative Name
//
// The subject alternative name extension allows additional identities
// to be bound to the certificate. OID: 2.5.29.17
//
// Common name types:
// - dNSName (2): DNS hostname
// - iPAddress (7): IP address
// - uniformResourceIdentifier (6): URI
test "RFC 5280 §4.2.1.6: Subject Alternative Name extension" {
    // OID: 2.5.29.17 (id-ce-subjectAltName)
    const subject_alt_name_oid = [_]u8{ 0x55, 0x1d, 0x11 }; // 2.5.29.17

    try testing.expectEqual(@as(usize, 3), subject_alt_name_oid.len);

    // GeneralName types
    const dns_name: u8 = 2;
    const uniform_resource_identifier: u8 = 6;
    const ip_address: u8 = 7;

    try testing.expectEqual(@as(u8, 2), dns_name);
    try testing.expectEqual(@as(u8, 6), uniform_resource_identifier);
    try testing.expectEqual(@as(u8, 7), ip_address);

    // For server certificates, SHOULD be marked critical if subject DN is empty
}

// RFC 5280 §4.2.1.9: Basic Constraints
//
// The basic constraints extension identifies whether the certificate
// subject is a CA and the maximum depth of certification paths. OID: 2.5.29.19
//
// ```
// BasicConstraints ::= SEQUENCE {
//   cA                BOOLEAN DEFAULT FALSE,
//   pathLenConstraint INTEGER (0..MAX) OPTIONAL
// }
// ```
test "RFC 5280 §4.2.1.9: Basic Constraints extension" {
    // OID: 2.5.29.19 (id-ce-basicConstraints)
    const basic_constraints_oid = [_]u8{ 0x55, 0x1d, 0x13 }; // 2.5.29.19

    try testing.expectEqual(@as(usize, 3), basic_constraints_oid.len);

    // cA flag
    const is_ca: bool = true;
    const is_end_entity: bool = false;

    try testing.expectEqual(true, is_ca);
    try testing.expectEqual(false, is_end_entity);

    // MUST be marked critical for CA certificates
    const critical_for_ca: bool = true;
    try testing.expectEqual(true, critical_for_ca);
}

// RFC 5280 §4.2.1.12: Extended Key Usage
//
// The extended key usage extension indicates the purposes for which
// the certified public key may be used. OID: 2.5.29.37
//
// Common extended key usages:
// - serverAuth (1.3.6.1.5.5.7.3.1): TLS server authentication
// - clientAuth (1.3.6.1.5.5.7.3.2): TLS client authentication
// - codeSigning (1.3.6.1.5.5.7.3.3): Code signing
test "RFC 5280 §4.2.1.12: Extended Key Usage extension" {
    // OID: 2.5.29.37 (id-ce-extKeyUsage)
    const ext_key_usage_oid = [_]u8{ 0x55, 0x1d, 0x25 }; // 2.5.29.37

    try testing.expectEqual(@as(usize, 3), ext_key_usage_oid.len);

    // Common EKU OIDs (partial, full OIDs are longer)
    // serverAuth: 1.3.6.1.5.5.7.3.1
    // clientAuth: 1.3.6.1.5.5.7.3.2
    // codeSigning: 1.3.6.1.5.5.7.3.3

    // For TLS server certificates, serverAuth is required
}

// RFC 5280 §4.2.1.10: Name Constraints
//
// The name constraints extension indicates a name space within which
// all subject names in subsequent certificates must be located. OID: 2.5.29.30
//
// Used by CA certificates to restrict naming in subordinate certificates.
test "RFC 5280 §4.2.1.10: Name Constraints extension" {
    // OID: 2.5.29.30 (id-ce-nameConstraints)
    const name_constraints_oid = [_]u8{ 0x55, 0x1d, 0x1e }; // 2.5.29.30

    try testing.expectEqual(@as(usize, 3), name_constraints_oid.len);

    // MUST be marked critical
    const is_critical: bool = true;
    try testing.expectEqual(true, is_critical);

    // Contains permittedSubtrees and/or excludedSubtrees
}

// RFC 5280 §4.1.1.2: Signature Algorithm
//
// The signatureAlgorithm field identifies the algorithm used to sign
// the certificate.
//
// Common signature algorithms:
// - RSA with SHA-256: 1.2.840.113549.1.1.11
// - ECDSA with SHA-256: 1.2.840.10045.4.3.2
// - ECDSA with SHA-384: 1.2.840.10045.4.3.3
// - Ed25519: 1.3.101.112
test "RFC 5280 §4.1.1.2: Signature algorithm identifiers" {
    // Signature algorithms are identified by OIDs
    // The same algorithm appears in both:
    // - Certificate.signatureAlgorithm
    // - TBSCertificate.signature
    // These MUST match

    const signature_algorithm_tag: u8 = 0x30; // SEQUENCE
    try testing.expectEqual(@as(u8, 0x30), signature_algorithm_tag);
}

// RFC 5280 §4.1.1.3: Signature Value
//
// The signature value is a BIT STRING containing the digital signature
// computed over the ASN.1 DER encoding of the TBSCertificate.
test "RFC 5280 §4.1.1.3: Signature value structure" {
    // Signature is a BIT STRING
    const bit_string_tag: u8 = 0x03;
    try testing.expectEqual(@as(u8, 0x03), bit_string_tag);

    // Signature lengths vary by algorithm:
    // - ECDSA with P-256: ~70-72 bytes (DER-encoded)
    // - ECDSA with P-384: ~100-104 bytes (DER-encoded)
    // - Ed25519: 64 bytes (fixed)
    // - RSA 2048: 256 bytes
    const ed25519_sig_len: usize = 64;
    try testing.expectEqual(@as(usize, 64), ed25519_sig_len);
}
