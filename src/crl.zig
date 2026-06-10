// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! RFC 5280 §5.1 Certificate Revocation List (CRL) parsing + provided-CRL
//! revocation checking.
//!
//! This module parses a DER-encoded `CertificateList` (RFC 5280 §5.1), verifies
//! its signature against an issuing CA certificate, and answers whether a given
//! certificate serial number is revoked by that CRL.
//!
//! ## Scope (intentional non-goals)
//! - **No network fetching.** CRLs are *provided* to this module as bytes. The
//!   application / QUIC layer is responsible for discovering CRL Distribution
//!   Points (RFC 5280 §4.2.1.13) and fetching the bytes over the wire. This
//!   module only parses + verifies + checks the bytes it is handed.
//! - **No delta CRLs, no indirect CRLs, no reason-code filtering.** Only the
//!   base CRL revoked-serial set is consulted.
//!
//! ## Signature reuse (no duplication)
//! A `CertificateList` shares the SAME outer DER shape as a `Certificate`:
//! `SEQUENCE { tbs, signatureAlgorithm AlgorithmIdentifier, signatureValue BIT STRING }`.
//! Therefore `x509.parseCertSignature(crl_der)` extracts `{algo_oid, sig_der}`
//! unchanged, and `x509.verifyCertSig(issuer.spki, tbsCertList, ...)` verifies
//! the CRL signature. We deliberately reuse the x509 signature path (which
//! contains the CONF-01 P-384/SHA-256 independent curve/hash fix) rather than
//! re-implementing signature verification here.
//!
//! ## ASN.1 structure (RFC 5280 §5.1)
//! ```text
//! CertificateList ::= SEQUENCE {
//!     tbsCertList          TBSCertList,
//!     signatureAlgorithm   AlgorithmIdentifier,
//!     signatureValue       BIT STRING }
//!
//! TBSCertList ::= SEQUENCE {
//!     version              Version OPTIONAL,        -- if present, v2 (INTEGER)
//!     signature            AlgorithmIdentifier,
//!     issuer               Name,
//!     thisUpdate           Time,
//!     nextUpdate           Time OPTIONAL,
//!     revokedCertificates  SEQUENCE OF SEQUENCE {
//!         userCertificate      CertificateSerialNumber,
//!         revocationDate       Time,
//!         crlEntryExtensions   Extensions OPTIONAL } OPTIONAL,
//!     crlExtensions        [0] EXPLICIT Extensions OPTIONAL }
//! ```

const std = @import("std");
const asn1 = @import("asn1");
const x509 = @import("x509");

/// Errors produced by CRL DER parsing.
pub const CrlError = error{ Malformed, UnexpectedTag, Truncated };

/// A single `RevokedCertificate` entry (RFC 5280 §5.1.2.6).
pub const RevokedCert = struct {
    /// userCertificate serial number: raw INTEGER content bytes. Zero-copy slice
    /// into the input CRL DER (caller-owned buffer must outlive this struct).
    serial: []const u8,
    /// revocationDate as Unix seconds.
    revocation_date_unix: i64,
};

/// A parsed RFC 5280 §5.1 `CertificateList`.
///
/// All `[]const u8` fields are zero-copy slices into the `raw` input DER, which
/// the caller owns and MUST keep alive for the lifetime of this struct. Only the
/// `revoked` array itself is allocator-owned (free via `deinit`).
pub const CertificateList = struct {
    /// Full issuer `Name` TLV (tag+len+content). Zero-copy slice into input.
    issuer_der: []const u8,
    /// thisUpdate as Unix seconds (RFC 5280 §5.1.2.4).
    this_update_unix: i64,
    /// nextUpdate as Unix seconds, or null if absent (RFC 5280 §5.1.2.5).
    next_update_unix: ?i64,
    /// Revoked entries (allocator-owned array; serial slices into input).
    revoked: []RevokedCert,
    /// Full tbsCertList TLV (tag+len+content) — the EXACT bytes the issuer
    /// signed. Zero-copy slice into input.
    tbs: []const u8,
    /// signatureAlgorithm OID content bytes (from x509.parseCertSignature).
    algo_oid: []const u8,
    /// signatureValue bytes, unused-bits byte already stripped.
    sig_der: []const u8,
    /// The whole CRL DER (caller-owned; must outlive this struct).
    raw: []const u8,

    /// Parse a DER-encoded `CertificateList`.
    ///
    /// Returns a `CertificateList` whose slices reference `der` (which must
    /// outlive the returned struct). The `revoked` array is allocated from
    /// `alloc` and must be released via `deinit`.
    pub fn parse(alloc: std.mem.Allocator, der: []const u8) !CertificateList {
        var top = asn1.Decoder.init(der);
        const cl_content = try top.readSequence(); // CertificateList content

        var d = asn1.Decoder.init(cl_content);

        // --- tbsCertList SEQUENCE: capture full TLV span ---
        const tbs_start = d.off;
        const tbs_hdr = try d.nextHeader();
        if (asn1.tagNumber(tbs_hdr.tag) != 16 or !asn1.isConstructed(tbs_hdr.tag))
            return CrlError.UnexpectedTag;
        // APPSEC bound: reject a length that exceeds the remaining buffer before
        // computing the end offset (mirrors x509.parseCert / asn1.readTLV).
        if (tbs_hdr.len > cl_content.len - d.off) return CrlError.Truncated;
        const tbs_content_start = d.off;
        const tbs_end = d.off + tbs_hdr.len;
        const tbs = cl_content[tbs_start..tbs_end]; // full tbsCertList TLV

        // --- parse tbsCertList content ---
        var t = asn1.Decoder.init(cl_content[tbs_content_start..tbs_end]);

        // version (INTEGER) OPTIONAL — present == v2. Peek the first TLV: if it
        // is a universal INTEGER it is the version; otherwise it is already the
        // signature AlgorithmIdentifier SEQUENCE and must NOT be consumed twice.
        {
            const save = t.off;
            const first = try t.readTLV();
            const is_version = asn1.tagClass(first.tag) == .universal and asn1.tagNumber(first.tag) == 2;
            if (!is_version) {
                // Not a version field — rewind so the signature AlgId is read below.
                t.off = save;
            }
        }

        // signature AlgorithmIdentifier (SEQUENCE) — skip; the authoritative
        // algorithm comes from the outer signatureAlgorithm via parseCertSignature.
        {
            const sig_algid = try t.readTLV();
            if (asn1.tagNumber(sig_algid.tag) != 16) return CrlError.UnexpectedTag;
        }

        // issuer Name (SEQUENCE) — capture full TLV (header + content) so it can
        // be compared / displayed. readTLV would drop the header, so span it.
        const iss_start = t.off;
        const iss_hdr = try t.nextHeader();
        if (asn1.tagNumber(iss_hdr.tag) != 16) return CrlError.UnexpectedTag;
        if (iss_hdr.len > t.buf.len - t.off) return CrlError.Truncated;
        const iss_end = t.off + iss_hdr.len;
        const issuer_der = t.buf[iss_start..iss_end];
        t.off = iss_end;

        // thisUpdate Time (REQUIRED): UTCTime (0x17) or GeneralizedTime (0x18).
        const this_update_unix = blk: {
            const tlv = try t.readTLV();
            if (!isTimeTag(tlv.tag)) return CrlError.UnexpectedTag;
            break :blk x509.parseDerTime(tlv.val) catch return CrlError.Malformed;
        };

        // Remaining optional fields: nextUpdate Time, revokedCertificates
        // SEQUENCE, crlExtensions [0]. Branch on tag.
        var next_update_unix: ?i64 = null;
        var revoked = std.ArrayList(RevokedCert).empty;
        errdefer revoked.deinit(alloc);

        while (t.off < t.buf.len) {
            const save = t.off;
            const tlv = try t.readTLV();
            if (isTimeTag(tlv.tag)) {
                // nextUpdate (only valid before revokedCertificates).
                next_update_unix = x509.parseDerTime(tlv.val) catch return CrlError.Malformed;
            } else if (asn1.tagClass(tlv.tag) == .universal and asn1.tagNumber(tlv.tag) == 16 and asn1.isConstructed(tlv.tag)) {
                // revokedCertificates ::= SEQUENCE OF SEQUENCE { serial, date, ... }
                try parseRevoked(alloc, tlv.val, &revoked);
            } else if (asn1.tagClass(tlv.tag) == .context and asn1.tagNumber(tlv.tag) == 0) {
                // crlExtensions [0] EXPLICIT — ignored (delta/indirect not handled).
                break;
            } else {
                // Unknown field; restore offset and stop to be tolerant.
                t.off = save;
                break;
            }
        }

        const sig = try x509.parseCertSignature(der); // same outer shape as a cert

        return .{
            .issuer_der = issuer_der,
            .this_update_unix = this_update_unix,
            .next_update_unix = next_update_unix,
            .revoked = try revoked.toOwnedSlice(alloc),
            .tbs = tbs,
            .algo_oid = sig.algo_oid,
            .sig_der = sig.sig_der,
            .raw = der,
        };
    }

    /// Release the allocator-owned `revoked` array. Zero-copy slices into the
    /// input DER are not freed (the caller owns the DER buffer).
    pub fn deinit(self: *CertificateList, alloc: std.mem.Allocator) void {
        alloc.free(self.revoked);
    }

    /// Returns true if `serial` (raw INTEGER content bytes) is listed as revoked.
    /// Serials are compared after stripping ALL leading 0x00 DER sign/padding
    /// bytes so that the caller's `cert.serial_number` and the CRL entry's serial
    /// match regardless of non-minimal encodings (consistent with OCSP).
    pub fn isRevoked(self: CertificateList, serial: []const u8) bool {
        const want = normalizeSerial(serial);
        for (self.revoked) |r| {
            if (std.mem.eql(u8, normalizeSerial(r.serial), want)) return true;
        }
        return false;
    }
};

/// Parse a `revokedCertificates` SEQUENCE OF content (`seq_content`) into
/// `out`. Each entry is `SEQUENCE { userCertificate INTEGER, revocationDate
/// Time, crlEntryExtensions OPTIONAL }`.
fn parseRevoked(alloc: std.mem.Allocator, seq_content: []const u8, out: *std.ArrayList(RevokedCert)) !void {
    var dec = asn1.Decoder.init(seq_content);
    while (dec.off < dec.buf.len) {
        const entry_tlv = try dec.readTLV();
        if (asn1.tagNumber(entry_tlv.tag) != 16 or !asn1.isConstructed(entry_tlv.tag))
            return CrlError.UnexpectedTag;

        var e = asn1.Decoder.init(entry_tlv.val);

        // userCertificate INTEGER — capture content bytes (zero-copy serial).
        const serial_tlv = try e.readTLV();
        if (asn1.tagClass(serial_tlv.tag) != .universal or asn1.tagNumber(serial_tlv.tag) != 2)
            return CrlError.UnexpectedTag;

        // revocationDate Time.
        const date_tlv = try e.readTLV();
        if (!isTimeTag(date_tlv.tag)) return CrlError.UnexpectedTag;
        const rev_date = x509.parseDerTime(date_tlv.val) catch return CrlError.Malformed;

        // crlEntryExtensions OPTIONAL — ignored.
        try out.append(alloc, .{ .serial = serial_tlv.val, .revocation_date_unix = rev_date });
    }
}

/// Strip ALL leading 0x00 DER sign/padding bytes from an INTEGER content slice
/// (keeping at least one byte so serial 0 is preserved) so that two encodings of
/// the same serial compare equal. Mirrors `ocsp.normalizeInteger` exactly so the
/// CRL and OCSP revocation engines never disagree on a non-minimal serial
/// (CWE-1025); stripping only one zero would let a revoked serial be MISSED.
fn normalizeSerial(s: []const u8) []const u8 {
    var i: usize = 0;
    while (i + 1 < s.len and s[i] == 0x00) i += 1;
    return s[i..];
}

/// True if `tag` is a DER Time: UTCTime (0x17) or GeneralizedTime (0x18).
fn isTimeTag(tag: u8) bool {
    return asn1.tagClass(tag) == .universal and (asn1.tagNumber(tag) == 23 or asn1.tagNumber(tag) == 24);
}

/// Verify the CRL's signature over its tbsCertList using the issuer cert's SPKI.
///
/// Reuses `x509.verifyCertSig` (RSA-PKCS#1 / RSA-PSS / ECDSA incl. P-384 /
/// Ed25519 dispatch). `alloc` is required because RSA verification allocates.
pub fn verifySignedBy(alloc: std.mem.Allocator, cl: *const CertificateList, issuer: *const x509.Certificate) bool {
    return x509.verifyCertSig(issuer.spki, cl.tbs, cl.algo_oid, cl.sig_der, alloc);
}

/// Revocation status of a certificate against a CRL.
pub const RevocationStatus = enum { good, revoked };

/// Errors that block a revocation decision.
pub const CheckError = error{ CrlBadSignature, CrlExpired, CrlIssuerMismatch, CrlStale };

/// Maximum tolerated clock skew when judging a CRL's `thisUpdate` to be
/// implausibly future-dated (RFC 5280 §5.1.2.4). 5 minutes.
const max_clock_skew_secs: i64 = 300;

/// Check a cert against a PROVIDED CRL.
///
/// Decision order is strictly fail-closed:
///   1. Issuer-Name binding (RFC 5280 §6.3.3): the CRL's issuer `Name` MUST
///      equal the certificate's issuer `Name`; otherwise `CrlIssuerMismatch`.
///      This prevents a confused-deputy bypass where a validly-signed CRL from
///      one trusted CA is applied to a certificate issued by a different CA
///      (CWE-441 / CWE-863).
///   2. Signature: the CRL MUST be signed by `issuer` (else `CrlBadSignature`).
///   3. Freshness (RFC 5280 §5.1.2.4-5):
///        - reject a `thisUpdate` more than `max_clock_skew_secs` in the future
///          (`CrlStale`);
///        - if `nextUpdate` is present, reject `now_unix > nextUpdate`
///          (`CrlExpired`);
///        - if `nextUpdate` is ABSENT, the CRL's staleness cannot be bounded, so
///          it is rejected as `CrlStale` rather than trusted with unbounded age.
///   4. Status: return `.revoked` if the cert serial is listed, else `.good`.
///
/// Network fetching of CRLs (via the cert's CRLDistributionPoints) is
/// intentionally NOT performed here — that is the application / QUIC layer's
/// responsibility. `alloc` is required because RSA signature verification
/// allocates.
pub fn checkRevocation(
    alloc: std.mem.Allocator,
    cert: *const x509.Certificate,
    cl: *const CertificateList,
    issuer: *const x509.Certificate,
    now_unix: i64,
) CheckError!RevocationStatus {
    // RFC 5280 §6.3.3: the CRL applies only when its issuer Name matches the
    // certificate's issuer Name. Bind first, fail closed (CWE-441/CWE-863).
    if (!std.mem.eql(u8, cl.issuer_der, cert.issuer_der)) return CheckError.CrlIssuerMismatch;

    if (!verifySignedBy(alloc, cl, issuer)) return CheckError.CrlBadSignature;

    // Freshness. Reject implausibly future-dated CRLs (clock-skew tolerant).
    if (cl.this_update_unix > now_unix + max_clock_skew_secs) return CheckError.CrlStale;
    if (cl.next_update_unix) |nu| {
        if (now_unix > nu) return CheckError.CrlExpired;
    } else {
        // RFC 5280 §5.1.2.5 makes nextUpdate OPTIONAL; without it we cannot bound
        // staleness, so treat the CRL as stale (fail-closed) rather than trusting
        // an unbounded-age list.
        return CheckError.CrlStale;
    }

    return if (cl.isRevoked(cert.serial_number)) .revoked else .good;
}

// ============================================================================
// Unit Tests
// ============================================================================

const testing = std.testing;
const test_certs = @import("test_certs");

test "normalizeSerial strips ALL leading zero sign bytes (matches OCSP)" {
    try testing.expectEqualSlices(u8, &[_]u8{ 0x10, 0x00 }, normalizeSerial(&[_]u8{ 0x10, 0x00 }));
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0x01 }, normalizeSerial(&[_]u8{ 0x00, 0xFF, 0x01 }));
    // A lone 0x00 (serial == 0) is preserved.
    try testing.expectEqualSlices(u8, &[_]u8{0x00}, normalizeSerial(&[_]u8{0x00}));
    // F3: non-minimal encodings with >=2 leading zeros must be fully stripped,
    // matching ocsp.normalizeInteger so the two revocation engines agree.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x10, 0x00 }, normalizeSerial(&[_]u8{ 0x00, 0x00, 0x10, 0x00 }));
    try testing.expectEqualSlices(u8, &[_]u8{0x00}, normalizeSerial(&[_]u8{ 0x00, 0x00, 0x00 })); // serial 0 preserved
    try testing.expectEqualSlices(u8, &[_]u8{0xFF}, normalizeSerial(&[_]u8{ 0x00, 0xFF }));
}

test "isRevoked matches across non-minimal serial encodings (F3)" {
    const a = testing.allocator;
    var cl = try CertificateList.parse(a, test_certs.crl_with_revoked);
    defer cl.deinit(a);
    // The CRL lists serial 0x1000 minimally; a cert serial padded with extra
    // leading zeros must still be recognised as revoked.
    const padded = [_]u8{ 0x00, 0x00, 0x10, 0x00 };
    try testing.expect(cl.isRevoked(&padded));
}

test "crl parse: revoked CRL exposes issuer, thisUpdate, one revoked serial" {
    const a = testing.allocator;
    var cl = try CertificateList.parse(a, test_certs.crl_with_revoked);
    defer cl.deinit(a);

    try testing.expect(cl.issuer_der.len > 0);
    try testing.expect(cl.this_update_unix > 0);
    try testing.expect(cl.next_update_unix != null);
    try testing.expect(cl.next_update_unix.? > cl.this_update_unix);

    try testing.expectEqual(@as(usize, 1), cl.revoked.len);
    const want = [_]u8{ 0x10, 0x00 }; // serial 0x1000
    try testing.expect(cl.isRevoked(&want));

    const absent = [_]u8{ 0x99, 0x99 };
    try testing.expect(!cl.isRevoked(&absent));
}

test "crl parse: empty CRL has no revoked entries" {
    const a = testing.allocator;
    var cl = try CertificateList.parse(a, test_certs.crl_empty);
    defer cl.deinit(a);

    try testing.expectEqual(@as(usize, 0), cl.revoked.len);
    try testing.expect(cl.next_update_unix != null);
    const want = [_]u8{ 0x10, 0x00 };
    try testing.expect(!cl.isRevoked(&want));
}

test "crl verifySignedBy: revoked CRL verifies under issuing CA SPKI" {
    const a = testing.allocator;
    var cl = try CertificateList.parse(a, test_certs.crl_with_revoked);
    defer cl.deinit(a);
    var ca = try x509.parseCert(a, test_certs.crl_ca);
    defer ca.deinit(a);

    try testing.expect(verifySignedBy(a, &cl, &ca));
}

test "checkRevocation: missing nextUpdate is fail-closed (CrlStale) (F2)" {
    const a = testing.allocator;
    var cl = try CertificateList.parse(a, test_certs.crl_with_revoked);
    defer cl.deinit(a);
    var ca = try x509.parseCert(a, test_certs.crl_ca);
    defer ca.deinit(a);
    var leaf = try x509.parseCert(a, test_certs.crl_leaf);
    defer leaf.deinit(a);

    // The signature still verifies (we kept tbs/sig fields), but a CRL with no
    // nextUpdate cannot bound its staleness and must be rejected fail-closed.
    cl.next_update_unix = null;
    const now: i64 = 1812585600; // inside thisUpdate window
    try testing.expectError(CheckError.CrlStale, checkRevocation(a, &leaf, &cl, &ca, now));
}

test "checkRevocation: future-dated thisUpdate beyond skew is rejected (CrlStale) (F2)" {
    const a = testing.allocator;
    var cl = try CertificateList.parse(a, test_certs.crl_with_revoked);
    defer cl.deinit(a);
    var ca = try x509.parseCert(a, test_certs.crl_ca);
    defer ca.deinit(a);
    var leaf = try x509.parseCert(a, test_certs.crl_leaf);
    defer leaf.deinit(a);

    // now well before thisUpdate (more than 5 min skew) => implausibly future CRL.
    const now: i64 = cl.this_update_unix - 3600;
    try testing.expectError(CheckError.CrlStale, checkRevocation(a, &leaf, &cl, &ca, now));
}
