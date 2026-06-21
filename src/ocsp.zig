// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! OCSP Stapling Validation (RFC 6960)
//!
//! This module validates stapled Online Certificate Status Protocol (OCSP)
//! responses delivered inside TLS 1.3 Certificate messages. It implements the
//! subset of RFC 6960 required for TLS 1.3 server authentication:
//! - Parses OCSPResponse and BasicOCSPResponse structures (ASN.1 DER)
//! - Validates response status (successful) and SingleResponse certStatus
//! - Matches CertID against the leaf certificate (issuer name/key hash, serial)
//! - Enforces freshness via producedAt / thisUpdate / nextUpdate
//! - Verifies BasicOCSPResponse signature with issuer or delegated responder
//! - Validates delegated responder certificate EKU (id-kp-OCSPSigning)
//!
//! The implementation focuses on the common deployment scenario where the OCSP
//! response is stapled by the TLS server. OCSP request generation and fetching
//! (client-driven OCSP) are out of scope.
const std = @import("std");
const asn1 = @import("asn1");
const backend = @import("crypto_backend");
// fips-exempt: non-security — constant-time comparison primitive, not a crypto algorithm.
const timing_safe = std.crypto.timing_safe;

const ocsp_trace_enabled = false;

// SEC-049: Compile-time safety: prevent OCSP trace logging in release builds.
// OCSP traces can leak certificate status details, responder info, and other
// metadata that aids attackers in fingerprinting the TLS implementation.
comptime {
    if (ocsp_trace_enabled and @import("builtin").mode != .Debug) {
        @compileError("SECURITY: ocsp_trace_enabled must be false in release builds — OCSP metadata would be logged");
    }
}

const x509 = @import("x509");

/// Maximum allowed clock skew (seconds) when validating OCSP timestamps.
const max_clock_skew: i64 = 300; // 5 minutes

/// Maximum tolerated age past nextUpdate before considering response stale.
const max_stale: i64 = 900; // 15 minutes grace period beyond nextUpdate

/// Errors that can arise during OCSP validation.
pub const OcspError = error{
    MalformedResponse,
    UnsupportedResponseType,
    UnsupportedHashAlgorithm,
    MissingSingleResponse,
    CertStatusRevoked,
    CertStatusUnknown,
    IssuerHashMismatch,
    SerialMismatch,
    FutureProducedAt,
    FutureThisUpdate,
    StaleResponse,
    SignatureInvalid,
    MissingIssuer,
    ResponderCertParse,
    ResponderCertInvalid,
    ResponderMissingEku,
    ResponderSignatureInvalid,
};

pub const HashAlg = enum { sha1, sha256, sha384, sha512 };

/// Issuer certificate information for OCSP validation.
/// Contains both the parsed certificate and its DER encoding.
pub const IssuerInfo = struct {
    cert: *const x509.Certificate,
    der: []const u8,
};

pub fn hashAlgFromOid(oid: []const u8) OcspError!HashAlg {
    // SEC-076: canonical equality. Prior suffix-match accepted prefix-
    // attack encodings. Canonical DER OIDs are unique (RFC 5280 §4.1.1.2).
    const sha1 = [_]u8{ 0x2B, 0x0E, 0x03, 0x02, 0x1A };
    const sha256 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
    const sha384 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
    const sha512 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };

    if (asn1.oidEqual(oid, &sha1)) return .sha1;
    if (asn1.oidEqual(oid, &sha256)) return .sha256;
    if (asn1.oidEqual(oid, &sha384)) return .sha384;
    if (asn1.oidEqual(oid, &sha512)) return .sha512;
    return OcspError.UnsupportedHashAlgorithm;
}

/// Error returned when SHA-1 hash is requested but not supported.
/// SHA-1 is deprecated (CWE-328) and removed from std.crypto.
pub const ComputeDigestError = error{
    Sha1NotSupported,
};

pub fn computeDigest(alg: HashAlg, data: []const u8, out: *[64]u8) ComputeDigestError![]const u8 {
    switch (alg) {
        .sha1 => {
            // SHA-1 is deprecated (CWE-328) and not available in std.crypto.
            // RFC 6960 §4.3 recommends SHA-256 for OCSP responses.
            // Returning an error instead of an incorrect hash prevents silent
            // security failures when encountering legacy SHA-1 OCSP responses.
            // Servers should upgrade to SHA-256 per RFC 6960 recommendations.
            if (ocsp_trace_enabled) std.debug.print("[OCSP] SHA-1 hash algorithm encountered in OCSP response — rejected (CWE-328). Server should use SHA-256 per RFC 6960 §4.3.\n", .{});
            return ComputeDigestError.Sha1NotSupported;
        },
        // OCSP CertID digests routed through the crypto_backend seam. Byte-
        // identical to the prior std init/update/final under -Dfips=false;
        // validated provider under -Dfips=true. The seam's one-shot returns
        // the digest length, which equals the output-slice length we return.
        .sha256 => {
            const n = backend.Hash.digest(.sha256, data, out[0..]) catch unreachable;
            return out[0..n];
        },
        .sha384 => {
            const n = backend.Hash.digest(.sha384, data, out[0..]) catch unreachable;
            return out[0..n];
        },
        .sha512 => {
            const n = backend.Hash.digest(.sha512, data, out[0..]) catch unreachable;
            return out[0..n];
        },
    }
}

pub fn parseStatus(bytes: []const u8) OcspError!void {
    // OCSPResponseStatus ::= ENUMERATED { successful (0), ... }
    // SEC-070: ENUMERATED values in DER for the RFC 6960-defined statuses
    // (0..6) are always encoded as a single byte. Any other length
    // indicates a malformed (or BER-permissive) encoding we do not accept.
    // Strict single-byte equality also rules out leading-zero-padded
    // encodings that could otherwise hide a non-zero status behind a 0x00
    // prefix byte.
    if (bytes.len != 1) return OcspError.MalformedResponse;
    if (bytes[0] != 0) return OcspError.MalformedResponse;
}
pub fn normalizeInteger(bytes: []const u8) []const u8 {
    var idx: usize = 0;
    while (idx + 1 < bytes.len and bytes[idx] == 0) idx += 1;
    return bytes[idx..];
}

pub fn ensureResponseTypeBasic(oid: []const u8) OcspError!void {
    // SEC-076: canonical equality.
    const id_pkix_ocsp_basic = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01 };
    if (!asn1.oidEqual(oid, &id_pkix_ocsp_basic)) {
        return OcspError.UnsupportedResponseType;
    }
}

pub fn extractCertFromSequence(seq: []const u8) OcspError!?[]const u8 {
    var dec = asn1.Decoder.init(seq);
    const cert_tlv = dec.readTLV() catch return OcspError.MalformedResponse;
    if (asn1.tagClass(cert_tlv.tag) != .universal or asn1.tagNumber(cert_tlv.tag) != 16) return OcspError.MalformedResponse;
    return cert_tlv.val[0..cert_tlv.val.len]; // value already sequence content
}

/// SEC-026: Defense-in-depth constant-time comparison for OCSP data matching.
/// While serial/issuer data is not secret, using constant-time comparison
/// prevents any potential timing oracle from leaking structural information.
pub fn compareSlices(expected: []const u8, actual: []const u8) bool {
    // Length difference is safe to check early -- lengths are not secret
    // and timing_safe.compare requires same-length slices.
    if (expected.len != actual.len) return false;
    return timing_safe.compare(u8, expected, actual, .big) == .eq;
}

/// Validate a stapled OCSP response for the provided certificate chain.
///
/// * `response`: DER-encoded OCSPResponse from CertificateEntry extension
/// * `leaf`: Parsed leaf certificate (`parsed_certs[0]`)
/// * `leaf_der`: DER bytes of the leaf certificate
/// * `issuer_opt`: Parsed issuer certificate and DER bytes (optional)
/// * `now_unix`: Current Unix timestamp for freshness validation
pub fn validateStapledResponse(
    allocator: std.mem.Allocator,
    response: []const u8,
    leaf: *const x509.Certificate,
    leaf_der: []const u8,
    issuer_opt: ?IssuerInfo,
    now_unix: i64,
) OcspError!void {
    // QUAL-340: Thin orchestrator. The four validators preserve RFC 6960
    // processing order and, critically, the CWE-328 SHA-1 skip inside
    // `matchSingleResponse`. Leaf DER kept in signature for future
    // enhancements (e.g. CertID-leaf cross-check).
    _ = leaf_der;
    const issuer = issuer_opt orelse return OcspError.MissingIssuer;

    const decoded = try decodeResponseBytes(response);
    const parsed = try parseResponseData(decoded.response_data_der, now_unix);
    try matchSingleResponse(parsed.responses_seq, leaf, issuer, now_unix);
    try verifySignerChain(allocator, decoded, issuer, now_unix);
}

/// QUAL-340 helper: bundle of BasicOCSPResponse fields produced by
/// `decodeResponseBytes` and consumed by later validators.
const DecodedResponse = struct {
    /// Complete DER encoding of `tbsResponseData` (SEQUENCE TLV), used as
    /// the signature input by `verifySignerChain`.
    response_data_der: []const u8,
    /// OID of the signature algorithm over `response_data_der`.
    sig_algo_oid: []const u8,
    /// Raw signature bit string value.
    signature_bits: []const u8,
    /// Optional delegated responder certificate DER (first cert in [0] `certs`).
    responder_cert_der: ?[]const u8,
};

/// QUAL-340 helper: fields extracted from `tbsResponseData` needed downstream.
const ParsedResponseData = struct {
    /// Content of the `responses` SEQUENCE OF SingleResponse (value bytes of
    /// the SEQUENCE, ready for `asn1.Decoder.init`).
    responses_seq: []const u8,
};

/// QUAL-340 validator 1: decode the outer OCSPResponse/responseBytes wrapper
/// and inner BasicOCSPResponse. Returns the `tbsResponseData` bytes, the
/// signature algorithm OID, the signature bit string, and the optional
/// embedded responder certificate DER. Preserves RFC 6960 §4.2.1 parsing
/// order and the universal/context tag assertions from the pre-refactor body.
fn decodeResponseBytes(response: []const u8) OcspError!DecodedResponse {
    var ocsp_dec = asn1.Decoder.init(response);
    const ocsp_seq = ocsp_dec.readSequence() catch |err| {
        if (ocsp_trace_enabled) std.debug.print("OCSP: OCSPResponse outer SEQUENCE decode failed: {}\n", .{err});
        return OcspError.MalformedResponse;
    };
    var ocsp_inner = asn1.Decoder.init(ocsp_seq);

    const response_status_tlv = ocsp_inner.readTLV() catch |err| {
        if (ocsp_trace_enabled) std.debug.print("OCSP: responseStatus TLV decode failed: {}\n", .{err});
        return OcspError.MalformedResponse;
    };
    if (asn1.tagClass(response_status_tlv.tag) != .universal or asn1.tagNumber(response_status_tlv.tag) != 10) {
        return OcspError.MalformedResponse;
    }
    try parseStatus(response_status_tlv.val);

    const response_bytes_tlv = ocsp_inner.readTLV() catch |err| {
        if (ocsp_trace_enabled) std.debug.print("OCSP: responseBytes TLV decode failed: {}\n", .{err});
        return OcspError.MalformedResponse;
    };
    if (asn1.tagClass(response_bytes_tlv.tag) != .context or asn1.tagNumber(response_bytes_tlv.tag) != 0) {
        return OcspError.MalformedResponse;
    }

    var rb_dec = asn1.Decoder.init(response_bytes_tlv.val);
    const rb_seq = rb_dec.readSequence() catch return OcspError.MalformedResponse;
    var rb_inner = asn1.Decoder.init(rb_seq);
    const response_type_oid = rb_inner.readOID() catch return OcspError.MalformedResponse;
    try ensureResponseTypeBasic(response_type_oid);
    const basic_der = rb_inner.readOctetString() catch return OcspError.MalformedResponse;

    var basic_dec = asn1.Decoder.init(basic_der);
    const basic_seq = basic_dec.readSequence() catch |err| {
        if (ocsp_trace_enabled) std.debug.print("OCSP: BasicOCSPResponse SEQUENCE decode failed: {}\n", .{err});
        return OcspError.MalformedResponse;
    };
    var basic_inner = asn1.Decoder.init(basic_seq);

    const response_data_tlv = basic_inner.readTLV() catch |err| {
        if (ocsp_trace_enabled) std.debug.print("OCSP: tbsResponseData TLV decode failed: {}\n", .{err});
        return OcspError.MalformedResponse;
    };
    const val_ptr = @intFromPtr(response_data_tlv.val.ptr);
    const base_ptr = @intFromPtr(basic_seq.ptr);
    const header_len = val_ptr - base_ptr;
    const response_data_der = basic_seq[0 .. header_len + response_data_tlv.val.len];

    const sig_algo_seq = basic_inner.readSequence() catch return OcspError.MalformedResponse;
    var sig_algo_dec = asn1.Decoder.init(sig_algo_seq);
    const sig_algo_oid = sig_algo_dec.readOID() catch return OcspError.MalformedResponse;
    // Ignore parameters for now, RSA-PSS parameters handled in signature verifier
    _ = sig_algo_dec.readTLV() catch null;

    const signature_bits = basic_inner.readBitString() catch return OcspError.MalformedResponse;

    var responder_cert_der_opt: ?[]const u8 = null;
    if (basic_inner.readTLV() catch null) |certs_tlv| {
        if (asn1.tagClass(certs_tlv.tag) != .context or asn1.tagNumber(certs_tlv.tag) != 0) return OcspError.MalformedResponse;
        var certs_seq_dec = asn1.Decoder.init(certs_tlv.val);
        const certs_seq = certs_seq_dec.readSequence() catch return OcspError.MalformedResponse;
        responder_cert_der_opt = try extractCertFromSequence(certs_seq);
    }

    return .{
        .response_data_der = response_data_der,
        .sig_algo_oid = sig_algo_oid,
        .signature_bits = signature_bits,
        .responder_cert_der = responder_cert_der_opt,
    };
}

/// QUAL-340 validator 2: parse `tbsResponseData` up through `producedAt`,
/// skip the optional [0] version tag and the responderID byName/byKey, and
/// return the value bytes of the `responses` SEQUENCE. The `producedAt`
/// freshness check (within `max_clock_skew` of `now_unix`) is kept here
/// because it belongs to the ResponseData scope (RFC 6960 §4.2.2.1).
///
/// Takes the full `tbsResponseData` TLV and re-enters it so the caller can
/// pass `decoded.response_data_der` directly without knowing the header
/// offset computed in `decodeResponseBytes`.
fn parseResponseData(response_data_der: []const u8, now_unix: i64) OcspError!ParsedResponseData {
    var tbs_decoder = asn1.Decoder.init(response_data_der);
    const tbs_content = tbs_decoder.readSequence() catch return OcspError.MalformedResponse;
    var rd_dec = asn1.Decoder.init(tbs_content);

    var responder_id_tlv = rd_dec.readTLV() catch |err| {
        if (ocsp_trace_enabled) std.debug.print("OCSP: responderID TLV decode failed: {}\n", .{err});
        return OcspError.MalformedResponse;
    };
    if (asn1.tagClass(responder_id_tlv.tag) == .context and asn1.tagNumber(responder_id_tlv.tag) == 0) {
        // Version - skip value
        responder_id_tlv = rd_dec.readTLV() catch return OcspError.MalformedResponse;
    }

    // responderID (byName/byKey) - skip
    const produced_at_tlv = rd_dec.readTLV() catch return OcspError.MalformedResponse;
    if (asn1.tagClass(produced_at_tlv.tag) != .universal or asn1.tagNumber(produced_at_tlv.tag) != 24) {
        return OcspError.MalformedResponse;
    }
    const produced_at = x509.parseDerTime(produced_at_tlv.val) catch return OcspError.MalformedResponse;
    if (produced_at > now_unix + max_clock_skew) return OcspError.FutureProducedAt;

    const responses_seq = rd_dec.readSequence() catch |err| {
        if (ocsp_trace_enabled) std.debug.print("OCSP: tbsResponseData responses SEQUENCE decode failed: {}\n", .{err});
        return OcspError.MalformedResponse;
    };

    return .{ .responses_seq = responses_seq };
}

/// QUAL-340 validator 3: iterate the `responses` SEQUENCE OF SingleResponse,
/// match one to the leaf certificate via CertID (issuerNameHash,
/// issuerKeyHash, serialNumber), and enforce status / thisUpdate / nextUpdate.
///
/// CRITICAL (CWE-328): `computeDigest` returns
/// `error.UnsupportedHashAlgorithm` when the CertID hashAlgorithm is SHA-1
/// (or any other rejected hash). We intentionally *skip* that SingleResponse
/// with `continue` rather than aborting; other CertIDs in the responses
/// SEQUENCE may still match with an approved hash (SHA-256/384/512). This
/// behaviour is preserved verbatim from the pre-refactor body (formerly at
/// L301-303 / L307-309 of the inlined function).
fn matchSingleResponse(
    responses_seq: []const u8,
    leaf: *const x509.Certificate,
    issuer: IssuerInfo,
    now_unix: i64,
) OcspError!void {
    var responses_iter = asn1.Decoder.init(responses_seq);

    const issuer_spk = x509.subjectPublicKeyBytes(issuer.cert.spki) catch return OcspError.ResponderCertInvalid;

    var found = false;
    var status_is_good = false;
    var single_next_update: ?i64 = null;

    while (true) {
        const single_seq = responses_iter.readSequence() catch break;
        var single_dec = asn1.Decoder.init(single_seq);

        const cert_id_seq = single_dec.readSequence() catch |err| {
            if (ocsp_trace_enabled) std.debug.print("OCSP: SingleResponse certID SEQUENCE decode failed: {}\n", .{err});
            return OcspError.MalformedResponse;
        };
        var cert_id_dec = asn1.Decoder.init(cert_id_seq);
        const hash_algo_seq2 = cert_id_dec.readSequence() catch |err| {
            if (ocsp_trace_enabled) std.debug.print("OCSP: certID hashAlgorithm SEQUENCE decode failed: {}\n", .{err});
            return OcspError.MalformedResponse;
        };
        var hash_algo_dec = asn1.Decoder.init(hash_algo_seq2);
        const hash_algo_oid = hash_algo_dec.readOID() catch return OcspError.MalformedResponse;
        _ = hash_algo_dec.readTLV() catch null;
        const hash_alg = try hashAlgFromOid(hash_algo_oid);

        const issuer_name_hash = cert_id_dec.readOctetString() catch return OcspError.MalformedResponse;
        const issuer_key_hash = cert_id_dec.readOctetString() catch return OcspError.MalformedResponse;
        const serial_tlv = cert_id_dec.readTLV() catch return OcspError.MalformedResponse;
        if (asn1.tagClass(serial_tlv.tag) != .universal or asn1.tagNumber(serial_tlv.tag) != 2) return OcspError.MalformedResponse;

        var name_digest_buf: [64]u8 = undefined;
        const expected_name_hash = computeDigest(hash_alg, leaf.issuer_der, &name_digest_buf) catch {
            // SHA-1 not supported (CWE-328) - skip this SingleResponse and try next
            continue;
        };
        if (!compareSlices(expected_name_hash, issuer_name_hash)) continue;

        var key_digest_buf: [64]u8 = undefined;
        const expected_key_hash = computeDigest(hash_alg, issuer_spk, &key_digest_buf) catch {
            // SHA-1 not supported (CWE-328) - skip this SingleResponse and try next
            continue;
        };
        if (!compareSlices(expected_key_hash, issuer_key_hash)) continue;

        if (!compareSlices(normalizeInteger(leaf.serial_number), normalizeInteger(serial_tlv.val))) return OcspError.SerialMismatch;

        const times = try parseSingleResponseTimes(&single_dec, now_unix);
        status_is_good = true;
        single_next_update = times.next_update;
        found = true;
        break;
    }

    if (!found or !status_is_good) return OcspError.MissingSingleResponse;

    if (single_next_update) |nu| {
        if (now_unix > nu + max_stale) return OcspError.StaleResponse;
    }
}

/// QUAL-340 helper: parse the status / thisUpdate / optional nextUpdate tail
/// of a SingleResponse after the CertID has been matched and verified.
/// `single_dec` is positioned immediately after the CertID SEQUENCE.
///
/// Returns the nextUpdate value (if present); returns `OcspError` for
/// malformed encoding, bad status (revoked/unknown), or a future thisUpdate.
/// Caller owns the "good status" bookkeeping; reaching this helper without
/// an error implies `status == good`.
fn parseSingleResponseTimes(
    single_dec: *asn1.Decoder,
    now_unix: i64,
) OcspError!struct { next_update: ?i64 } {
    const single_status_tlv = single_dec.readTLV() catch return OcspError.MalformedResponse;
    if (asn1.tagClass(single_status_tlv.tag) != .context) return OcspError.MalformedResponse;
    switch (asn1.tagNumber(single_status_tlv.tag)) {
        0 => {}, // good
        1 => return OcspError.CertStatusRevoked,
        2 => return OcspError.CertStatusUnknown,
        else => return OcspError.MalformedResponse,
    }

    const this_update_tlv = single_dec.readTLV() catch return OcspError.MalformedResponse;
    if (asn1.tagClass(this_update_tlv.tag) != .universal or (asn1.tagNumber(this_update_tlv.tag) != 24 and asn1.tagNumber(this_update_tlv.tag) != 23)) {
        return OcspError.MalformedResponse;
    }
    const single_this_update = x509.parseDerTime(this_update_tlv.val) catch return OcspError.MalformedResponse;
    if (single_this_update > now_unix + max_clock_skew) return OcspError.FutureThisUpdate;

    var next_update: ?i64 = null;
    if (single_dec.readTLV() catch null) |next_update_tlv| {
        if (asn1.tagClass(next_update_tlv.tag) == .context and asn1.tagNumber(next_update_tlv.tag) == 0) {
            var inner_next = asn1.Decoder.init(next_update_tlv.val);
            const inner_time = inner_next.readTLV() catch return OcspError.MalformedResponse;
            if (asn1.tagClass(inner_time.tag) != .universal or (asn1.tagNumber(inner_time.tag) != 24 and asn1.tagNumber(inner_time.tag) != 23)) return OcspError.MalformedResponse;
            next_update = x509.parseDerTime(inner_time.val) catch return OcspError.MalformedResponse;
        }
    }

    return .{ .next_update = next_update };
}

/// QUAL-340 validator 4: resolve the signing SPKI (issuer's or a delegated
/// responder cert's) and verify the BasicOCSPResponse signature over
/// `tbsResponseData`. For delegated responders, enforce validity window and
/// EKU id-kp-OCSPSigning per RFC 6960 §4.2.2.2.
fn verifySignerChain(
    allocator: std.mem.Allocator,
    decoded: DecodedResponse,
    issuer: IssuerInfo,
    now_unix: i64,
) OcspError!void {
    var signer_spki = issuer.cert.spki;
    if (decoded.responder_cert_der) |resp_der| {
        const responder_cert = x509.parseCert(allocator, resp_der) catch return OcspError.ResponderCertParse;
        defer responder_cert.deinit(allocator);
        x509.checkValidity(now_unix, &responder_cert) catch return OcspError.ResponderCertInvalid;
        if (responder_cert.eku) |eku| {
            if (!eku.ocsp_signing) return OcspError.ResponderMissingEku;
        } else return OcspError.ResponderMissingEku;
        if (!x509.verifyCertificateSignedBy(&responder_cert, resp_der, issuer.cert, allocator)) return OcspError.ResponderSignatureInvalid;
        signer_spki = responder_cert.spki;
    }

    if (!x509.verifySignatureWithSpki(signer_spki, decoded.response_data_der, decoded.sig_algo_oid, decoded.signature_bits, allocator)) {
        return OcspError.SignatureInvalid;
    }
}
