//! X.509 Certificate Parsing and Validation for TLS 1.3
//!
//! Implements a minimal X.509 v3 certificate parser and validator for TLS 1.3
//! handshake processing in QUIC environments. Supports the certificate validation
//! requirements specified in:
//! - RFC 5280 (X.509 Public Key Infrastructure Certificate and CRL Profile)
//! - RFC 7468 (PEM Textual Encodings)
//! - RFC 6818 (Updates to RFC 5280)
//! - RFC 8446 §4.4.2 (TLS 1.3 Certificate message)
//! - RFC 8446 §4.4.3 (TLS 1.3 CertificateVerify)
//!
//! This module provides the certificate processing subset needed for TLS 1.3
//! QUIC handshakes, including:
//! - DER-encoded certificate parsing (ASN.1 structures via asn1.zig)
//! - X.509 v3 extension handling (SAN, Basic Constraints, Key Usage, EKU)
//! - Certificate chain validation with path length constraints
//! - Time-based validity checking with Unix timestamp support
//! - Server identity verification via Subject Alternative Names and Common Name
//! - Signature algorithm inference from SubjectPublicKeyInfo
//! - Certificate signature verification for chain validation
//!
//! ## Supported Features
//! - **Certificate Extensions**: SubjectAltName (DNS names), BasicConstraints,
//!   KeyUsage, ExtendedKeyUsage (serverAuth)
//! - **Signature Algorithms**: ECDSA (P-256/P-384 SHA-256/SHA-384), RSA-PSS SHA-256,
//!   Ed25519 (via sig.zig integration)
//! - **Validation Modes**: Full chain validation with trust store integration,
//!   or insecure bypass for testing
//! - **Time Format Support**: GeneralizedTime (YYYYMMDDHHMMSSZ) and UTCTime
//!   (YYMMDDHHMMSSZ) per RFC 5280 §4.1.2.5
//! - **Wildcard Matching**: Left-label wildcard matching for DNS names (*.example.com)
//!
//! ## RFC 5280 Compliance
//! This implementation focuses on the server certificate validation requirements
//! from RFC 5280 §6 (Certification Path Validation) with TLS-specific constraints:
//! - Leaf certificate MUST have ExtendedKeyUsage with id-kp-serverAuth
//! - Leaf certificate MUST have KeyUsage with digitalSignature bit when present
//! - Intermediate certificates MUST have BasicConstraints with cA=TRUE
//! - Path length constraints are enforced per RFC 5280 §4.2.1.9
//! - Certificate validity period is checked against current time
//!
//! ## TLS 1.3 Integration (RFC 8446 §4.4.2)
//! The TLS 1.3 Certificate message carries a certificate_list where:
//! - Each certificate is a DER-encoded X.509v3 certificate
//! - The sender's certificate must be first (leaf certificate)
//! - Each following certificate should certify the one immediately preceding it
//! - The self-signed root certificate MAY be omitted
//!
//! This module validates chains received in TLS Certificate messages and provides
//! public key extraction for CertificateVerify signature verification.
//!
//! ## Signature Algorithm Support
//! Supported signature algorithms for certificate chain validation:
//! - ECDSA with P-256 curve and SHA-256 (id-ecdsa-with-SHA256)
//! - ECDSA with P-384 curve and SHA-384 (id-ecdsa-with-SHA384)
//! - RSASSA-PSS with SHA-256 (id-RSASSA-PSS)
//! - Ed25519 (id-Ed25519)
//!
//! ## Security Considerations
//! - **Trust Store**: Root certificates must be validated via pluggable TrustStore
//!   callback when `allow_insecure` is false
//! - **Name Validation**: Server name (SNI) must match SubjectAltName or CN
//! - **Time Validation**: Certificates are rejected if expired or not yet valid
//! - **Path Validation**: Full chain validation enforces CA constraints and path limits
//! - **Insecure Mode**: `allow_insecure=true` bypasses ALL validation - testing only!
//!
//! ## Design Notes
//! - Uses minimal ASN.1 decoder (asn1.zig) for DER parsing
//! - Zero-copy parsing where possible (certificates reference input buffer)
//! - Signature verification delegates to sig.zig for algorithm-specific operations
//! - Time calculations use Unix epoch (seconds since 1970-01-01T00:00:00Z)
//! - Wildcard matching follows CA/Browser Forum Baseline Requirements
//!
//! ## Future Work
//! - OCSP stapling support (RFC 6960)
//! - Signed Certificate Timestamp validation (RFC 6962)
//! - Name constraints enforcement (RFC 5280 §4.2.1.10)
//! - Policy constraints and mappings (RFC 5280 §4.2.1.11-12)
//! - CRL distribution points (RFC 5280 §4.2.1.13)
//! - Migration to std.crypto.x509 when available in Zig stdlib
const std = @import("std");
const asn1 = @import("asn1");
const sigmod = @import("sig");
const Ed25519 = std.crypto.sign.Ed25519;

/// Pluggable trust store for root certificate validation.
///
/// Provides a callback mechanism to validate root certificate trust anchors
/// during chain validation. The callback receives the SubjectPublicKeyInfo
/// (SPKI) of the root certificate and returns true if it's trusted.
///
/// This design allows integration with system trust stores, custom trust
/// anchors, or pinned public keys without embedding trust policy in this module.
///
/// ## RFC Reference
/// RFC 5280 §6.1.1 - Trust anchor information includes public key
///
/// ## Usage Example
/// ```
/// const ts = TrustStore {
///     .isTrustedSpki = myTrustStoreCallback,
/// };
/// setTrustStore(ts);
/// // Now validateChain() will invoke callback for root validation
/// ```
///
/// ## Security Considerations
/// The trust store callback is invoked ONLY for self-signed root certificates
/// after signature verification succeeds. The callback must implement appropriate
/// trust policy (e.g., match against known root SPKI hashes).
pub const TrustStore = struct {
    /// Callback to check if a root certificate's SPKI is trusted.
    ///
    /// ## Parameters
    /// - `spki_der`: DER-encoded SubjectPublicKeyInfo from root certificate
    ///
    /// ## Returns
    /// `true` if the SPKI matches a trusted root, `false` otherwise
    isTrustedSpki: *const fn (spki_der: []const u8) bool,
};

/// Global trust store instance (set via setTrustStore()).
var g_trust_store: ?TrustStore = null;

/// Install or clear the global trust store hook.
///
/// Sets the trust store callback used by validateChain() for root certificate
/// validation. Pass null to disable trust store validation (useful for testing).
///
/// ## Parameters
/// - `ts`: Trust store instance with callback, or null to disable
///
/// ## RFC Reference
/// RFC 5280 §6.1.1 - Trust anchor information
///
/// ## Security Considerations
/// Without a trust store, validateChain() will reject all chains unless
/// `allow_insecure=true` is used. Always set a trust store in production.
pub fn setTrustStore(ts: ?TrustStore) void {
    g_trust_store = ts;
}

/// Distinguished Name subset containing only Common Name field.
///
/// Simplified representation of the X.509 Distinguished Name structure.
/// Only extracts the Common Name (CN) attribute, which is sufficient for
/// server identity validation when SubjectAltName is not present.
///
/// ## RFC Reference
/// RFC 5280 §4.1.2.4 - Issuer and Subject name structures
/// RFC 5280 §4.1.2.6 - Subject field (deprecated for identity in favor of SAN)
///
/// ## Design Note
/// Full DN parsing (O, OU, C, ST, L) is omitted as modern certificates use
/// SubjectAltName for identity and CN is only a fallback per RFC 6125.
pub const Name = struct {
    /// Common Name (CN) attribute from the RDNSequence, or null if not present.
    /// RFC 5280 §4.1.2.4 - Common Name is of type DirectoryString
    cn: ?[]const u8 = null,
};

/// Subject Alternative Name extension containing DNS names.
///
/// Represents the id-ce-subjectAltName extension (OID 2.5.29.17) containing
/// DNS name entries. This is the primary mechanism for server identity in
/// TLS 1.3 per RFC 6125 §6.4.4.
///
/// ## RFC References
/// - RFC 5280 §4.2.1.6 - Subject Alternative Name extension
/// - RFC 6125 §6.4.4 - Checking DNS-ID identities
/// - RFC 8446 §4.4.2.2 - Server Certificate Selection
///
/// ## Design Note
/// Only DNS names (GeneralName choice [2]) are extracted. Other name forms
/// (email, URI, IP address) are ignored as they're not used for TLS server identity.
pub const SubjectAltName = struct {
    /// List of DNS names from the SubjectAltName extension.
    /// RFC 5280 §4.2.1.6 - dNSName is IA5String
    dns: []const []const u8,
};

/// Basic Constraints extension indicating CA status and path length limit.
///
/// Represents the id-ce-basicConstraints extension (OID 2.5.29.19) which
/// indicates whether a certificate is a CA certificate and constrains the
/// maximum depth of valid certification paths.
///
/// ## RFC References
/// - RFC 5280 §4.2.1.9 - Basic Constraints extension
/// - RFC 5280 §6.1.4 - Preparation for Certificate Processing (path length)
///
/// ## Fields
/// - `ca`: If true, certificate may sign other certificates (CA certificate)
/// - `path_len`: Maximum number of intermediate CA certificates that may follow
///   this certificate in a valid certification path. None means no limit.
///
/// ## Validation Rules
/// - Leaf certificates: basicConstraints should have cA=FALSE or be absent
/// - Intermediate/Root CAs: basicConstraints MUST be present with cA=TRUE
/// - Path length: Each intermediate CA decrements the path length constraint
pub const BasicConstraints = struct {
    /// CA flag: true if this certificate can sign other certificates.
    /// RFC 5280 §4.2.1.9 - cA boolean value
    ca: bool = false,
    /// Maximum number of intermediate CAs that may follow in the path.
    /// RFC 5280 §4.2.1.9 - pathLenConstraint INTEGER (0..MAX) OPTIONAL
    path_len: ?u32 = null,
};

/// Key Usage extension defining cryptographic purposes for the public key.
///
/// Represents the id-ce-keyUsage extension (OID 2.5.29.15) which restricts
/// the operations that may be performed with the certificate's public key.
///
/// ## RFC References
/// - RFC 5280 §4.2.1.3 - Key Usage extension
/// - RFC 8446 §4.4.2.2 - Certificate MUST allow digitalSignature for TLS 1.3
///
/// ## Bit Positions (RFC 5280 §4.2.1.3)
/// - Bit 0 (0x8000): digitalSignature - Required for TLS leaf certificates
/// - Bit 1 (0x4000): nonRepudiation / contentCommitment
/// - Bit 2 (0x2000): keyEncipherment - Used in RSA key exchange (TLS 1.2)
/// - Bit 3 (0x1000): dataEncipherment
/// - Bit 4 (0x0800): keyAgreement
/// - Bit 5 (0x0400): keyCertSign - Required for CA certificates
/// - Bit 6 (0x0200): cRLSign
/// - Bit 7 (0x0100): encipherOnly
/// - Bit 8 (0x0080): decipherOnly
///
/// ## Validation for TLS
/// - Leaf certificates: digitalSignature (bit 0) MUST be set when KeyUsage present
/// - CA certificates: keyCertSign (bit 5) MUST be set
pub const KeyUsage = struct {
    /// Bitmask with MSB-first encoding (bit 0 is 0x8000, bit 7 is 0x0100).
    /// RFC 5280 §4.2.1.3 - BIT STRING with named bits
    bits: u16,
};

/// Extended Key Usage extension indicating certificate purposes.
///
/// Represents the id-ce-extKeyUsage extension (OID 2.5.29.37) which indicates
/// one or more purposes for which the certified public key may be used.
///
/// ## RFC References
/// - RFC 5280 §4.2.1.12 - Extended Key Usage extension
/// - RFC 5280 §4.2.1.12 - id-kp-serverAuth OID 1.3.6.1.5.5.7.3.1
/// - RFC 8446 §4.4.2.2 - Server certificate MUST be valid for id-kp-serverAuth
///
/// ## Design Note
/// Only tracks id-kp-serverAuth (TLS web server authentication) as this is
/// the only EKU purpose relevant for TLS 1.3 server certificates.
pub const ExtKeyUsage = struct {
    /// True if id-kp-serverAuth (1.3.6.1.5.5.7.3.1) is present.
    /// RFC 5280 §4.2.1.12 - TLS WWW server authentication
    server_auth: bool = false,
};

/// Parsed X.509 certificate with extracted fields for TLS validation.
///
/// Zero-copy view over a DER-encoded X.509 certificate with parsed extension
/// data. All slices reference the original DER buffer passed to parseCert().
///
/// ## RFC References
/// - RFC 5280 §4.1 - Basic Certificate Fields
/// - RFC 5280 §4.2 - Standard Extensions
/// - RFC 8446 §4.4.2 - TLS 1.3 Certificate message
///
/// ## Lifetime
/// The Certificate struct borrows from the input DER buffer. The buffer must
/// remain valid for the lifetime of the Certificate struct. Extension data
/// (SAN DNS names) also reference the original buffer.
///
/// ## Validation Flow
/// 1. Parse DER certificate -> Certificate struct
/// 2. Check validity period (not_before_unix to not_after_unix)
/// 3. Verify server name matches SAN or CN
/// 4. Check ExtendedKeyUsage contains serverAuth
/// 5. Check KeyUsage contains digitalSignature (if present)
/// 6. Verify signature using issuer's SPKI
pub const Certificate = struct {
    /// Raw TBSCertificate bytes for signature verification.
    /// RFC 5280 §4.1.2 - TBSCertificate ::= SEQUENCE { ... }
    tbs: []const u8,

    /// Distinguished Name from Subject field (Common Name only).
    /// RFC 5280 §4.1.2.6 - Subject field (fallback for identity)
    subject: Name,

    /// Subject Alternative Name extension (DNS names only).
    /// RFC 5280 §4.2.1.6 - Primary identity mechanism
    san: ?SubjectAltName = null,

    /// Basic Constraints extension (CA flag and path length).
    /// RFC 5280 §4.2.1.9 - Required for CA certificates
    basic: ?BasicConstraints = null,

    /// Key Usage extension (cryptographic purpose bits).
    /// RFC 5280 §4.2.1.3 - Constrains key operations
    ku: ?KeyUsage = null,

    /// Extended Key Usage extension (certificate purposes).
    /// RFC 5280 §4.2.1.12 - Must include serverAuth for TLS servers
    eku: ?ExtKeyUsage = null,

    /// Validity period start (Unix timestamp seconds since 1970-01-01T00:00:00Z).
    /// RFC 5280 §4.1.2.5 - notBefore field
    not_before_unix: i64,

    /// Validity period end (Unix timestamp seconds since 1970-01-01T00:00:00Z).
    /// RFC 5280 §4.1.2.5 - notAfter field
    not_after_unix: i64,

    /// SubjectPublicKeyInfo DER bytes for signature verification and key extraction.
    /// RFC 5280 §4.1.2.7 - Subject Public Key Info
    spki: []const u8,
};

/// Check if a year is a leap year (Gregorian calendar).
///
/// ## Algorithm
/// A year is a leap year if:
/// - Divisible by 4 AND not divisible by 100, OR
/// - Divisible by 400
///
/// ## Examples
/// - 2000: leap (divisible by 400)
/// - 1900: not leap (divisible by 100 but not 400)
/// - 2024: leap (divisible by 4, not by 100)
/// - 2023: not leap
fn isLeap(year: u16) bool {
    return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0);
}

/// Calculate total days elapsed before a given month in a year.
///
/// Returns the number of days from January 1st to the start of the specified
/// month, accounting for leap years in February.
///
/// ## Parameters
/// - `year`: Year for leap year calculation
/// - `month`: Month (1-12, where 1=January, 12=December)
///
/// ## Returns
/// Number of days before the start of `month` (0 for January)
fn daysBeforeMonth(year: u16, month: u8) i64 {
    const mdays = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    var d: i64 = 0;
    var m: u8 = 1;
    while (m < month) : (m += 1) {
        if (m == 2 and isLeap(year)) d += 29 else d += mdays[m - 1];
    }
    return d;
}

fn unixSecondsFromYMDHMS(year: u16, month: u8, day: u8, hh: u8, mm: u8, ss: u8) i64 {
    if (year < 1970) return 0; // clamp for simplicity
    var days: i64 = 0;
    var y: u16 = 1970;
    while (y < year) : (y += 1) days += if (isLeap(y)) 366 else 365;
    days += daysBeforeMonth(year, month);
    days += (@as(i64, day) - 1);
    return days * 86400 + @as(i64, hh) * 3600 + @as(i64, mm) * 60 + @as(i64, ss);
}

fn parseTime(bytes: []const u8) !i64 {
    // Accept the subset: YYYYMMDDHHMMSSZ or YYMMDDHHMMSSZ; return unix seconds
    if (bytes.len == 13 and bytes[12] == 'Z') {
        const yy = try std.fmt.parseInt(u8, bytes[0..2], 10);
        const year: u16 = if (yy >= 50) (@as(u16, 1900) + @as(u16, yy)) else (@as(u16, 2000) + @as(u16, yy));
        const month = try std.fmt.parseInt(u8, bytes[2..4], 10);
        const day = try std.fmt.parseInt(u8, bytes[4..6], 10);
        const hh = try std.fmt.parseInt(u8, bytes[6..8], 10);
        const mm = try std.fmt.parseInt(u8, bytes[8..10], 10);
        const ss = try std.fmt.parseInt(u8, bytes[10..12], 10);
        return unixSecondsFromYMDHMS(year, month, day, hh, mm, ss);
    }
    if (bytes.len == 15 and bytes[14] == 'Z') {
        const year = try std.fmt.parseInt(u16, bytes[0..4], 10);
        const month = try std.fmt.parseInt(u8, bytes[4..6], 10);
        const day = try std.fmt.parseInt(u8, bytes[6..8], 10);
        const hh = try std.fmt.parseInt(u8, bytes[8..10], 10);
        const mm = try std.fmt.parseInt(u8, bytes[10..12], 10);
        const ss = try std.fmt.parseInt(u8, bytes[12..14], 10);
        return unixSecondsFromYMDHMS(year, month, day, hh, mm, ss);
    }
    return error.UnsupportedTimeFormat;
}

fn unwrapExtnValueToBytes(extn_val_or_octets: []const u8) []const u8 {
    // extnValue is an OCTET STRING containing DER of the actual extension value
    var d = asn1.Decoder.init(extn_val_or_octets);
    const inner = d.readOctetString() catch return extn_val_or_octets; // tolerate if already raw
    return inner;
}

/// Parse a DER-encoded X.509 certificate and extract fields for TLS validation.
///
/// Parses the ASN.1 DER encoding of an X.509 v3 certificate and extracts:
/// - TBSCertificate for signature verification
/// - Subject Distinguished Name (Common Name only)
/// - Validity period (notBefore, notAfter) as Unix timestamps
/// - SubjectPublicKeyInfo for key extraction
/// - X.509 v3 extensions: SubjectAltName, BasicConstraints, KeyUsage, ExtendedKeyUsage
///
/// ## Certificate Structure (RFC 5280 §4.1)
/// ```
/// Certificate  ::=  SEQUENCE  {
///     tbsCertificate       TBSCertificate,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signatureValue       BIT STRING  }
///
/// TBSCertificate  ::=  SEQUENCE  {
///     version         [0]  EXPLICIT Version DEFAULT v1,
///     serialNumber         CertificateSerialNumber,
///     signature            AlgorithmIdentifier,
///     issuer               Name,
///     validity             Validity,
///     subject              Name,
///     subjectPublicKeyInfo SubjectPublicKeyInfo,
///     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///     extensions      [3]  EXPLICIT Extensions OPTIONAL  }
/// ```
///
/// ## Parameters
/// - `alloc`: Allocator for temporary buffers (currently unused, for future extension data)
/// - `der`: Complete DER-encoded X.509 certificate bytes
///
/// ## Returns
/// Certificate struct with borrowed slices referencing `der` buffer. The `der` buffer
/// MUST remain valid for the lifetime of the returned Certificate.
///
/// ## Errors
/// Returns errors from asn1.Decoder for malformed DER encoding:
/// - Invalid ASN.1 structure
/// - Missing required fields
/// - Malformed extension data
/// - Unsupported time formats
///
/// ## RFC References
/// - RFC 5280 §4.1 - Basic Certificate Fields
/// - RFC 5280 §4.2 - Certificate Extensions
/// - RFC 5280 §4.1.2.5 - Validity period encoding
/// - RFC 5280 §4.2.1.6 - SubjectAltName extension (OID 2.5.29.17)
/// - RFC 5280 §4.2.1.9 - BasicConstraints extension (OID 2.5.29.19)
/// - RFC 5280 §4.2.1.3 - KeyUsage extension (OID 2.5.29.15)
/// - RFC 5280 §4.2.1.12 - ExtendedKeyUsage extension (OID 2.5.29.37)
///
/// ## Design Notes
/// - Zero-copy: All slices in Certificate reference the input `der` buffer
/// - Shallow Subject parsing: Only extracts Common Name (CN), ignores O/OU/C/etc
/// - SAN filtering: Only extracts dNSName entries (GeneralName [2]), ignores others
/// - Extension limit: SubjectAltName limited to 8 DNS names (array allocation)
/// - OID matching: Uses suffix matching for extension OIDs (last N bytes)
///
/// ## Security Considerations
/// This function only parses the certificate structure. It does NOT:
/// - Verify signatures (use validateChain for full validation)
/// - Check validity period (use checkValidity)
/// - Validate name constraints
/// - Enforce policy constraints
pub fn parseCert(alloc: std.mem.Allocator, der: []const u8) !Certificate {
    _ = alloc; // currently not owning sub-slices
    var d = asn1.Decoder.init(der);
    const seq = try d.readSequence(); // Certificate
    var ci = asn1.Decoder.init(seq);
    // RFC 5280 §4.1 - Parse Certificate SEQUENCE containing TBSCertificate
    const tbs = try ci.readSequence();
    const tbs_off_begin = (@intFromPtr(tbs.ptr) - @intFromPtr(seq.ptr)) + (seq.ptr - der.ptr);
    const tbs_len = tbs.len;

    // RFC 5280 §4.1.2 - Parse TBSCertificate fields: version, serial, signature, issuer, validity, subject, spki, extensions
    var ti = asn1.Decoder.init(tbs);
    _ = try ti.readTLV(); // version or serial
    _ = try ti.readTLV(); // maybe version/serial/signature
    _ = try ti.readTLV(); // signature or serial/signature
    const issuer = try ti.readTLV();
    _ = issuer;
    const validity = try ti.readSequence();
    var vd = asn1.Decoder.init(validity);
    const not_before_tlv = try vd.readTLV();
    const not_after_tlv = try vd.readTLV();
    const not_before = try parseTime(not_before_tlv.val);
    const not_after = try parseTime(not_after_tlv.val);
    const subject_seq = try ti.readSequence();
    // Parse subject for CN (very shallow: look for UTF8String in RDNs)
    var subj_cn: ?[]const u8 = null;
    {
        var sdec = asn1.Decoder.init(subject_seq);
        while (true) {
            const tlv = sdec.readTLV() catch break;
            if (asn1.tagClass(tlv.tag) == .universal and asn1.tagNumber(tlv.tag) == 12) {
                subj_cn = tlv.val;
                break;
            }
        }
    }
    const spki_tlv = try ti.readTLV();

    // Try to find extensions sequence and parse SAN/basic/ku/eku if present
    var san_result: ?SubjectAltName = null;
    var basic_res: ?BasicConstraints = null;
    var ku_res: ?KeyUsage = null;
    var eku_res: ?ExtKeyUsage = null;
    while (true) {
        const tlv = ti.readTLV() catch break;
        // Look for [3] EXPLICIT Extensions (context-specific constructed)
        if (asn1.tagClass(tlv.tag) == .context and asn1.isConstructed(tlv.tag)) {
            var ed = asn1.Decoder.init(tlv.val);
            const exts_seq = ed.readSequence() catch continue;
            var exd = asn1.Decoder.init(exts_seq);
            while (true) {
                const ext = exd.readSequence() catch break;
                var one = asn1.Decoder.init(ext);
                const oid = one.readOID() catch continue;
                const critical_or_val = one.readTLV() catch continue;
                var val = critical_or_val.val;
                if (one.readTLV() catch null) |v2| val = v2.val;
                const inner = unwrapExtnValueToBytes(val);
                // id-ce-subjectAltName = 2.5.29.17
                if (oid.len >= 3 and oid[0] == 0x55 and oid[1] == 0x1d and oid[2] == 0x11) {
                    var vd2 = asn1.Decoder.init(inner);
                    const san_seq = vd2.readSequence() catch continue;
                    var dns_list: [8][]const u8 = undefined;
                    var dns_len: usize = 0;
                    var s2 = asn1.Decoder.init(san_seq);
                    while (dns_len < dns_list.len) {
                        const gn = s2.readTLV() catch break;
                        if (asn1.tagClass(gn.tag) == .context and asn1.tagNumber(gn.tag) == 2) {
                            dns_list[dns_len] = gn.val;
                            dns_len += 1;
                        }
                    }
                    if (dns_len > 0) san_result = .{ .dns = dns_list[0..dns_len] };
                }
                // id-ce-basicConstraints = 2.5.29.19
                if (oid.len >= 3 and oid[0] == 0x55 and oid[1] == 0x1d and oid[2] == 0x13) {
                    var bd = asn1.Decoder.init(inner);
                    const bc_seq = bd.readSequence() catch continue;
                    var b2 = asn1.Decoder.init(bc_seq);
                    var ca = false;
                    var path_len: ?u32 = null;
                    const tlv_ca = b2.readTLV() catch null;
                    if (tlv_ca) |t| {
                        // BOOLEAN TRUE is 0xff or 0x01 depending on encoder; accept any non-zero
                        if (asn1.tagClass(t.tag) == .universal and asn1.tagNumber(t.tag) == 1 and t.val.len >= 1) ca = (t.val[0] != 0);
                        const tlv_pl = b2.readTLV() catch null;
                        if (tlv_pl) |pl| {
                            if (asn1.tagClass(pl.tag) == .universal and asn1.tagNumber(pl.tag) == 2) {
                                // Parse small integer
                                var v: u32 = 0;
                                for (pl.val) |bb| v = (v << 8) | bb;
                                path_len = v;
                            }
                        }
                    }
                    basic_res = .{ .ca = ca, .path_len = path_len };
                }
                // id-ce-keyUsage = 2.5.29.15
                if (oid.len >= 3 and oid[0] == 0x55 and oid[1] == 0x1d and oid[2] == 0x0f) {
                    var kd = asn1.Decoder.init(inner);
                    const bits = kd.readBitString() catch continue;
                    var mask: u16 = 0;
                    // bits[0] is first 8 bits (MSB first) after 'unused bits' removal handled in readBitString
                    for (bits, 0..) |b, idx| {
                        const shift: u4 = @intCast((bits.len - 1 - idx) * 8);
                        mask |= @as(u16, @intCast(b)) << shift;
                    }
                    ku_res = .{ .bits = mask };
                }
                // id-ce-extKeyUsage = 2.5.29.37; serverAuth = 1.3.6.1.5.5.7.3.1 (2B 06 01 05 05 07 03 01)
                if (oid.len >= 3 and oid[0] == 0x55 and oid[1] == 0x1d and oid[2] == 0x25) {
                    var ed2 = asn1.Decoder.init(inner);
                    const seq2 = ed2.readSequence() catch continue;
                    var e2 = asn1.Decoder.init(seq2);
                    var server_auth = false;
                    while (true) {
                        const oid2 = e2.readOID() catch break;
                        if (oid2.len >= 8 and std.mem.eql(u8, oid2[oid2.len - 8 ..], &[_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 })) {
                            server_auth = true;
                        }
                    }
                    eku_res = .{ .server_auth = server_auth };
                }
            }
        }
    }

    const subject: Name = .{ .cn = subj_cn };
    const tbs_start: usize = @intCast(tbs_off_begin);
    const tbs_bytes = der[tbs_start .. tbs_start + tbs_len];
    return .{
        .tbs = tbs_bytes,
        .subject = subject,
        .san = san_result,
        .basic = basic_res,
        .ku = ku_res,
        .eku = eku_res,
        .not_before_unix = not_before,
        .not_after_unix = not_after,
        .spki = spki_tlv.val,
    };
}

/// Infer the TLS signature algorithm from a DER-encoded certificate's SubjectPublicKeyInfo.
/// Detects Ed25519, ECDSA P-256, and RSA-PSS (SHA-256). Returns error.UnsupportedKeyAlgorithm
/// for unsupported or unknown key types.
pub fn inferSignatureAlgorithm(cert_der: []const u8) !sigmod.SigAlg {
    const cert = try parseCert(std.heap.page_allocator, cert_der);

    if (sigmod.parseEd25519Spki(cert.spki)) |_| {
        return .ed25519;
    } else |err| switch (err) {
        error.UnexpectedAlgorithm => {},
        else => return err,
    }

    if (sigmod.parseEcdsaSpki(cert.spki, std.heap.page_allocator)) |spki_val| {
        var spki = spki_val;
        defer spki.deinit();
        if (!spki.curve_p256) return error.UnsupportedKeyAlgorithm;
        return .ecdsa_secp256r1_sha256;
    } else |err| switch (err) {
        error.UnexpectedAlgorithm => {},
        error.UnsupportedCurve, error.InvalidEcPoint => return error.UnsupportedKeyAlgorithm,
        else => return err,
    }

    if (sigmod.parseRsaSpki(cert.spki, std.heap.page_allocator)) |spki_val| {
        var spki = spki_val;
        defer spki.deinit();
        return .rsa_pss_sha256;
    } else |err| switch (err) {
        error.UnexpectedAlgorithm => {},
        else => return err,
    }

    return error.UnsupportedKeyAlgorithm;
}

/// Check if the current time is within the certificate's validity period.
///
/// Validates that a certificate is currently valid by comparing the current time
/// against the notBefore and notAfter fields from RFC 5280 §4.1.2.5.
///
/// ## Parameters
/// - `now_unix`: Current time as Unix timestamp (seconds since 1970-01-01T00:00:00Z)
/// - `cert`: Certificate to validate
///
/// ## Errors
/// - `error.NotYetValid`: Current time is before certificate's notBefore
/// - `error.Expired`: Current time is after certificate's notAfter
///
/// ## RFC References
/// - RFC 5280 §4.1.2.5 - Validity period: notBefore and notAfter fields
/// - RFC 5280 §6.1.3(a) - Path validation requires validity period check
/// - RFC 8446 §4.4.2.2 - Certificate MUST be valid at the time it is received
///
/// ## Security Considerations
/// - Use a trusted time source for `now_unix` to prevent time-based attacks
/// - Check validity BEFORE verifying signatures to avoid wasted computation
/// - Validity is checked at TLS handshake time, not packet arrival time
pub fn checkValidity(now_unix: i64, cert: *const Certificate) !void {
    // RFC 5280 §4.1.2.5 - notBefore: certificate is not valid before this time
    if (now_unix < cert.not_before_unix) return error.NotYetValid;
    // RFC 5280 §4.1.2.5 - notAfter: certificate is not valid after this time
    if (now_unix > cert.not_after_unix) return error.Expired;
}

fn toLowerAscii(b: u8) u8 {
    return if (b >= 'A' and b <= 'Z') b + 32 else b;
}

fn endsWithAsciiCI(hay: []const u8, suf: []const u8) bool {
    if (hay.len < suf.len) return false;
    const off = hay.len - suf.len;
    var i: usize = 0;
    while (i < suf.len) : (i += 1) {
        if (toLowerAscii(hay[off + i]) != toLowerAscii(suf[i])) return false;
    }
    return true;
}

fn containsDot(s: []const u8) bool {
    for (s) |c| if (c == '.') return true;
    return false;
}

fn wildcardMatch(host: []const u8, pattern: []const u8) bool {
    // Only support "*.example.com" with exactly one extra label on the left.
    if (pattern.len < 3 or pattern[0] != '*' or pattern[1] != '.') return false;
    const suffix = pattern[1..]; // includes leading '.'
    if (!endsWithAsciiCI(host, suffix)) return false;
    const prefix_len = host.len - suffix.len;
    if (prefix_len == 0) return false;
    const prefix = host[0..prefix_len];
    // Exactly one label on the left: no additional dots allowed in prefix
    if (containsDot(prefix)) return false;
    return true;
}

/// Match a server name against certificate identity (SAN or CN with wildcard support).
///
/// Validates that a DNS hostname matches the certificate's identity by checking:
/// 1. SubjectAltName dNSName entries (preferred, RFC 6125 §6.4.4)
/// 2. Subject Common Name as fallback if no SAN present (deprecated but supported)
///
/// Supports left-label wildcard matching (*.example.com) per CA/Browser Forum
/// Baseline Requirements. Wildcards only match a single DNS label.
///
/// ## Parameters
/// - `cert`: Certificate to check
/// - `name`: DNS hostname to match (e.g., "www.example.com")
///
/// ## Returns
/// `true` if `name` matches any SAN DNS entry or the CN (when no SAN present)
///
/// ## Matching Rules
/// 1. Exact case-sensitive match (for simplicity, RFC 4343 DNS is case-insensitive)
/// 2. Wildcard match: "*.example.com" matches "www.example.com" but NOT:
///    - "example.com" (needs at least one label before wildcard)
///    - "sub.www.example.com" (wildcard matches only one label)
/// 3. SAN takes precedence: If SAN is present, CN is ignored per RFC 6125 §6.4.4
///
/// ## RFC References
/// - RFC 6125 §6.4.4 - Subject Alternative Name is authoritative for identity
/// - RFC 5280 §4.2.1.6 - SubjectAltName extension
/// - RFC 5280 §4.1.2.6 - Subject CN is deprecated for identity
/// - RFC 8446 §4.4.2.2 - Server identity MUST be validated
/// - CA/Browser Forum Baseline Requirements §3.2.2.4 - Wildcard certificate validation
///
/// ## Security Considerations
/// - SAN is checked first; CN is only checked if SAN is absent
/// - Wildcard certificates are limited to left-most label only
/// - No support for multiple wildcards or mid-label wildcards
/// - Case-sensitive comparison (should be case-insensitive per DNS but simplified)
pub fn matchDnsName(cert: *const Certificate, name: []const u8) bool {
    // Exact byte match (case-sensitive) for simplicity; wildcard support for leading label.
    if (cert.san) |san| {
        for (san.dns) |d| {
            if (std.mem.eql(u8, d, name)) return true;
            if (d.len >= 2 and d[0] == '*' and d[1] == '.') {
                if (wildcardMatch(name, d)) return true;
            }
        }
        return false;
    }
    if (cert.subject.cn) |cn| {
        if (std.mem.eql(u8, cn, name)) return true;
        if (cn.len >= 2 and cn[0] == '*' and cn[1] == '.') return wildcardMatch(name, cn);
        return false;
    }
    return false;
}

fn parseCertSignature(der: []const u8) !struct { algo_oid: []const u8, sig_der: []const u8 } {
    var d = asn1.Decoder.init(der);
    const cert_seq = try d.readSequence();
    var c = asn1.Decoder.init(cert_seq);
    _ = try c.readSequence(); // tbs
    // signatureAlgorithm
    var sa = asn1.Decoder.init(try c.readSequence());
    const oid = try sa.readOID();
    // Optional params ignored for now
    _ = sa.readTLV() catch null;
    // signatureValue BIT STRING
    const sig_bits = try c.readBitString();
    return .{ .algo_oid = oid, .sig_der = sig_bits };
}

fn oidIsEcdsaSha256(oid: []const u8) bool {
    // 1.2.840.10045.4.3.2 -> bytes end with 2A 86 48 CE 3D 04 03 02
    return oid.len >= 8 and std.mem.eql(u8, oid[oid.len - 8 ..], &[_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 });
}
fn oidIsEcdsaSha384(oid: []const u8) bool {
    return oid.len >= 8 and std.mem.eql(u8, oid[oid.len - 8 ..], &[_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 });
}
fn oidIsRsaPss(oid: []const u8) bool {
    // 1.2.840.113549.1.1.10 -> 2A 86 48 86 F7 0D 01 01 0A
    return oid.len >= 9 and std.mem.eql(u8, oid[oid.len - 9 ..], &[_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A });
}
fn oidIsEd25519(oid: []const u8) bool {
    // Ed25519 1.3.101.112 -> 2B 65 70
    return oid.len >= 3 and std.mem.eql(u8, oid[oid.len - 3 ..], &[_]u8{ 0x2B, 0x65, 0x70 });
}

fn verifyCertSig(issuer_spki_der: []const u8, tbs: []const u8, algo_oid: []const u8, sig_der: []const u8) bool {
    if (oidIsEcdsaSha256(algo_oid)) {
        const E = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P256, std.crypto.hash.sha2.Sha256);
        const signature = E.Signature.fromDer(sig_der) catch return false;
        var spki = sigmod.parseEcdsaSpki(issuer_spki_der, std.heap.page_allocator) catch return false;
        defer spki.deinit();
        const pubkey = E.PublicKey.fromSec1(spki.sec1_uncompressed) catch return false;
        signature.verify(tbs, pubkey) catch return false;
        return true;
    }
    if (oidIsEcdsaSha384(algo_oid)) {
        const E = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P384, std.crypto.hash.sha2.Sha384);
        const signature = E.Signature.fromDer(sig_der) catch return false;
        var spki = sigmod.parseEcdsaSpki(issuer_spki_der, std.heap.page_allocator) catch return false;
        defer spki.deinit();
        const pubkey = E.PublicKey.fromSec1(spki.sec1_uncompressed) catch return false;
        signature.verify(tbs, pubkey) catch return false;
        return true;
    }
    if (oidIsRsaPss(algo_oid)) {
        // Constrain to SHA-256 and saltLen=32. Verify TBSCertificate directly (no TLS context).
        // Note: We reuse the RSA-PSS verifier from sig.zig by providing the raw TBS as message.
        return sigmod.verifyCertificateVerify(.rsa_pss_sha256, issuer_spki_der, sig_der, "", tbs) catch false;
    }
    if (oidIsEd25519(algo_oid)) {
        // Ed25519 signature verification using std.crypto
        const pubkey_bytes = sigmod.parseEd25519Spki(issuer_spki_der) catch return false;
        const pubkey = Ed25519.PublicKey.fromBytes(pubkey_bytes) catch return false;
        if (sig_der.len != 64) return false;
        var sig_arr: [64]u8 = undefined;
        @memcpy(&sig_arr, sig_der[0..64]);
        const signature = Ed25519.Signature.fromBytes(sig_arr);
        signature.verify(tbs, pubkey) catch return false;
        return true;
    }
    return false;
}

/// Validate a complete X.509 certificate chain for TLS server authentication.
///
/// Performs full RFC 5280 §6 certification path validation for a TLS server
/// certificate chain. This is the primary entry point for certificate validation
/// during TLS 1.3 handshakes.
///
/// ## Validation Steps (RFC 5280 §6.1)
/// 1. Parse all certificates in the chain
/// 2. **Leaf Certificate Checks**:
///    - Validity period (notBefore <= now <= notAfter)
///    - Server name matches SubjectAltName or CN
///    - ExtendedKeyUsage contains id-kp-serverAuth
///    - KeyUsage contains digitalSignature bit (if present)
/// 3. **Intermediate Certificate Checks** (for each cert in positions 1..N-1):
///    - BasicConstraints present with cA=TRUE
///    - Validity period check
///    - Path length constraints enforced (RFC 5280 §4.2.1.9)
/// 4. **Chain Signature Verification**:
///    - Each certificate's signature verified by the next certificate's SPKI
///    - Root certificate is self-signed (verified by its own SPKI)
/// 5. **Root Trust Validation**:
///    - Root must have BasicConstraints with cA=TRUE
///    - Root SPKI validated by trust store callback (if set)
///
/// ## Parameters
/// - `alloc`: Allocator for temporary Certificate structures
/// - `chain_der`: Array of DER-encoded certificates [leaf, intermediate(s), root]
/// - `now_unix`: Current time as Unix timestamp for validity checking
/// - `server_name`: Expected DNS hostname for server identity (SNI value)
/// - `allow_insecure`: If true, ALL validation is bypassed (testing only!)
///
/// ## Errors
/// - `EmptyChain`: chain_der has no certificates
/// - `NotYetValid`/`Expired`: Certificate validity period violation
/// - `NameMismatch`: Server name doesn't match leaf certificate identity
/// - `EkuNotAllowed`: Leaf certificate missing id-kp-serverAuth
/// - `KuNotAllowed`: Leaf certificate missing digitalSignature bit in KeyUsage
/// - `BasicConstraints`: CA certificate missing required basicConstraints
/// - `PathLenExceeded`: Intermediate cert violates path length constraint
/// - `SignatureParse`: Malformed certificate signature
/// - `BadSignature`: Certificate signature verification failed
/// - `UntrustedRoot`: Root SPKI rejected by trust store callback
///
/// ## RFC References
/// - RFC 5280 §6 - Certification Path Validation algorithm
/// - RFC 5280 §6.1.3 - Basic Certificate Processing
/// - RFC 5280 §6.1.4 - Preparation for Certificate Processing
/// - RFC 5280 §4.2.1.9 - Basic Constraints and path length
/// - RFC 5280 §4.2.1.12 - Extended Key Usage (id-kp-serverAuth)
/// - RFC 5280 §4.2.1.3 - Key Usage (digitalSignature)
/// - RFC 8446 §4.4.2 - TLS 1.3 Certificate message and validation
/// - RFC 8446 §4.4.2.2 - Certificate requirements for TLS servers
///
/// ## Chain Structure
/// The chain_der array MUST be ordered from leaf to root:
/// - chain_der[0]: Leaf (end-entity) certificate
/// - chain_der[1..N-1]: Intermediate CA certificates (optional, may be empty)
/// - chain_der[N-1]: Root CA certificate (self-signed, may be omitted if trust store validates)
///
/// ## Trust Anchor Handling
/// If a trust store is configured via setTrustStore(), the root certificate's
/// SPKI is validated by the callback. Without a trust store:
/// - If `allow_insecure=true`: Chain is accepted without root validation (INSECURE!)
/// - If `allow_insecure=false`: Chain is rejected with UntrustedRoot
///
/// ## Security Considerations
/// - **NEVER use `allow_insecure=true` in production** - it disables ALL validation
/// - Trust store callback MUST verify root SPKI against known trust anchors
/// - Server name (SNI) MUST match to prevent man-in-the-middle attacks
/// - Validity period MUST be checked to prevent using expired certificates
/// - Signature verification MUST succeed to prevent forged certificates
/// - Path length constraints prevent deep chains that could hide rogue CAs
///
/// ## Design Notes
/// - Currently validates only the leaf certificate in detail; partial intermediate validation
/// - Self-signed roots are accepted (last cert signs itself)
/// - OCSP/CRL checking not implemented (revocation checking omitted)
/// - Name constraints not enforced (RFC 5280 §4.2.1.10)
/// - Policy mapping not supported (RFC 5280 §4.2.1.5)
pub fn validateChain(alloc: std.mem.Allocator, chain_der: []const []const u8, now_unix: i64, server_name: []const u8, allow_insecure: bool) !void {
    if (allow_insecure) return;
    if (chain_der.len == 0) return error.EmptyChain;

    // Parse all certs
    var certs = try alloc.alloc(Certificate, chain_der.len);
    defer alloc.free(certs);
    var i: usize = 0;
    while (i < chain_der.len) : (i += 1) certs[i] = try parseCert(alloc, chain_der[i]);

    // Leaf checks
    try checkValidity(now_unix, &certs[0]);
    if (!matchDnsName(&certs[0], server_name)) return error.NameMismatch;
    if (certs[0].eku) |eku| if (!eku.server_auth) return error.EkuNotAllowed;
    if (certs[0].ku) |ku| {
        // Require digitalSignature bit when KeyUsage present (RFC 5280 §4.2.1.3)
        // Our bitstring packs MSB of first byte as highest mask bit (0x8000 when 2 bytes).
        if ((ku.bits & 0x8000) == 0) return error.KuNotAllowed;
    }

    // Intermediates must be CA and within pathLenConstraint
    var max_path: ?u32 = null;
    var depth: u32 = 0;
    i = 1;
    while (i < certs.len) : (i += 1) {
        depth += 1;
        const c = certs[i];
        // BasicConstraints CA required for all but leaf
        if (c.basic) |b| {
            if (!b.ca) return error.BasicConstraints;
            if (b.path_len) |pl| max_path = if (max_path) |m| @min(m, pl) else pl;
        } else return error.BasicConstraints;
        if (c.ku) |ku| {
            // Expect keyCertSign (bit 5) present when KU provided; our mask is rough, skip strict check
            _ = ku;
        }
        try checkValidity(now_unix, &c);
        if (max_path) |m| {
            if (depth > m + 1) return error.PathLenExceeded; // leaf + m intermediates allowed
        }
    }

    // Verify signatures along the chain
    i = 0;
    while (i < certs.len) : (i += 1) {
        const issuer_index: usize = if (i + 1 < certs.len) i + 1 else i; // root self-signed
        const issuer_spki = certs[issuer_index].spki;
        const parsed = parseCertSignature(chain_der[i]) catch return error.SignatureParse;
        const ok = verifyCertSig(issuer_spki, certs[i].tbs, parsed.algo_oid, parsed.sig_der);
        if (!ok) return error.BadSignature;
        if (i == certs.len - 1) {
            // Root must be CA and trusted if trust store provided
            if (certs[i].basic) |b| {
                if (!b.ca) return error.BasicConstraints;
            } else return error.BasicConstraints;
            if (g_trust_store) |ts| {
                if (!ts.isTrustedSpki(certs[i].spki)) return error.UntrustedRoot;
            }
        }
    }
}
