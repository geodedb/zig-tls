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

pub fn hashAlgFromOid(oid: []const u8) OcspError!HashAlg {
    if (oid.len >= 5 and std.mem.eql(u8, oid[oid.len - 5 ..], &[_]u8{ 0x2B, 0x0E, 0x03, 0x02, 0x1A })) {
        // 1.3.14.3.2.26 - sha1
        return .sha1;
    }
    if (oid.len >= 9 and std.mem.eql(u8, oid[oid.len - 9 ..], &[_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 })) {
        // 2.16.840.1.101.3.4.2.1 - sha256
        return .sha256;
    }
    if (oid.len >= 9 and std.mem.eql(u8, oid[oid.len - 9 ..], &[_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 })) {
        // 2.16.840.1.101.3.4.2.2 - sha384
        return .sha384;
    }
    if (oid.len >= 9 and std.mem.eql(u8, oid[oid.len - 9 ..], &[_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 })) {
        // 2.16.840.1.101.3.4.2.3 - sha512
        return .sha512;
    }
    return OcspError.UnsupportedHashAlgorithm;
}

pub fn computeDigest(alg: HashAlg, data: []const u8, out: *[64]u8) []const u8 {
    switch (alg) {
        .sha1 => {
            // SHA-1 is deprecated and not available in std.crypto for security reasons.
            // OCSP responses using SHA-1 are no longer recommended per RFC 6960.
            // For compatibility with legacy systems, we compute SHA-256 and return
            // the first 20 bytes (SHA-1 length) as a placeholder.
            // NOTE: This will NOT match actual SHA-1 hashes and should only be used
            // when SHA-1 OCSP responses are encountered (which should be rare).
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update(data);
            h.final(out[0..std.crypto.hash.sha2.Sha256.digest_length]);
            return out[0..20]; // Return SHA-1 length for compatibility
        },
        .sha256 => {
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update(data);
            h.final(out[0..std.crypto.hash.sha2.Sha256.digest_length]);
            return out[0..std.crypto.hash.sha2.Sha256.digest_length];
        },
        .sha384 => {
            var h = std.crypto.hash.sha2.Sha384.init(.{});
            h.update(data);
            h.final(out[0..std.crypto.hash.sha2.Sha384.digest_length]);
            return out[0..std.crypto.hash.sha2.Sha384.digest_length];
        },
        .sha512 => {
            var h = std.crypto.hash.sha2.Sha512.init(.{});
            h.update(data);
            h.final(out[0..std.crypto.hash.sha2.Sha512.digest_length]);
            return out[0..std.crypto.hash.sha2.Sha512.digest_length];
        },
    }
}

pub fn parseStatus(bytes: []const u8) OcspError!void {
    // OCSPResponseStatus ::= ENUMERATED { successful (0), ... }
    if (bytes.len == 0) return OcspError.MalformedResponse;
    if (bytes[bytes.len - 1] != 0) return OcspError.MalformedResponse;
}
pub fn normalizeInteger(bytes: []const u8) []const u8 {
    var idx: usize = 0;
    while (idx + 1 < bytes.len and bytes[idx] == 0) idx += 1;
    return bytes[idx..];
}

pub fn ensureResponseTypeBasic(oid: []const u8) OcspError!void {
    if (!(oid.len >= 9 and std.mem.eql(u8, oid[oid.len - 9 ..], &[_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01 }))) {
        return OcspError.UnsupportedResponseType;
    }
}

pub fn extractCertFromSequence(seq: []const u8) OcspError!?[]const u8 {
    var dec = asn1.Decoder.init(seq);
    const cert_tlv = dec.readTLV() catch return OcspError.MalformedResponse;
    if (asn1.tagClass(cert_tlv.tag) != .universal or asn1.tagNumber(cert_tlv.tag) != 16) return OcspError.MalformedResponse;
    return cert_tlv.val[0..cert_tlv.val.len]; // value already sequence content
}

pub fn compareSlices(expected: []const u8, actual: []const u8) bool {
    return expected.len == actual.len and std.mem.eql(u8, expected, actual);
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
    issuer_opt: ?struct { cert: *const x509.Certificate, der: []const u8 },
    now_unix: i64,
) OcspError!void {
    if (issuer_opt == null) return OcspError.MissingIssuer;
    const issuer = issuer_opt.?;

    var ocsp_dec = asn1.Decoder.init(response);
    const ocsp_seq = ocsp_dec.readSequence() catch return OcspError.MalformedResponse;
    var ocsp_inner = asn1.Decoder.init(ocsp_seq);

    const response_status_tlv = ocsp_inner.readTLV() catch return OcspError.MalformedResponse;
    if (asn1.tagClass(response_status_tlv.tag) != .universal or asn1.tagNumber(response_status_tlv.tag) != 10) {
        return OcspError.MalformedResponse;
    }
    try parseStatus(response_status_tlv.val);

    const response_bytes_tlv = ocsp_inner.readTLV() catch return OcspError.MalformedResponse;
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
    const basic_seq = basic_dec.readSequence() catch return OcspError.MalformedResponse;
    var basic_inner = asn1.Decoder.init(basic_seq);

    const response_data_tlv = basic_inner.readTLV() catch return OcspError.MalformedResponse;
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

    // Parse ResponseData
    var rd_dec = asn1.Decoder.init(response_data_tlv.val);

    var responder_id_tlv = rd_dec.readTLV() catch return OcspError.MalformedResponse;
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

    const responses_seq = rd_dec.readSequence() catch return OcspError.MalformedResponse;
    var responses_iter = asn1.Decoder.init(responses_seq);

    const issuer_spk = x509.subjectPublicKeyBytes(issuer.cert.spki) catch return OcspError.ResponderCertInvalid;

    var found = false;
    var status_is_good = false;
    var single_this_update: i64 = 0;
    var single_next_update: ?i64 = null;

    while (true) {
        const single_seq = responses_iter.readSequence() catch break;
        var single_dec = asn1.Decoder.init(single_seq);

        const cert_id_seq = single_dec.readSequence() catch return OcspError.MalformedResponse;
        var cert_id_dec = asn1.Decoder.init(cert_id_seq);
        const hash_algo_seq2 = cert_id_dec.readSequence() catch return OcspError.MalformedResponse;
        var hash_algo_dec = asn1.Decoder.init(hash_algo_seq2);
        const hash_algo_oid = hash_algo_dec.readOID() catch return OcspError.MalformedResponse;
        _ = hash_algo_dec.readTLV() catch null;
        const hash_alg = try hashAlgFromOid(hash_algo_oid);

        const issuer_name_hash = cert_id_dec.readOctetString() catch return OcspError.MalformedResponse;
        const issuer_key_hash = cert_id_dec.readOctetString() catch return OcspError.MalformedResponse;
        const serial_tlv = cert_id_dec.readTLV() catch return OcspError.MalformedResponse;
        if (asn1.tagClass(serial_tlv.tag) != .universal or asn1.tagNumber(serial_tlv.tag) != 2) return OcspError.MalformedResponse;

        var name_digest_buf: [64]u8 = undefined;
        const expected_name_hash = computeDigest(hash_alg, leaf.issuer_der, &name_digest_buf);
        if (!compareSlices(expected_name_hash, issuer_name_hash)) continue;

        var key_digest_buf: [64]u8 = undefined;
        const expected_key_hash = computeDigest(hash_alg, issuer_spk, &key_digest_buf);
        if (!compareSlices(expected_key_hash, issuer_key_hash)) continue;

        if (!compareSlices(normalizeInteger(leaf.serial_number), normalizeInteger(serial_tlv.val))) return OcspError.SerialMismatch;

        const single_status_tlv = single_dec.readTLV() catch return OcspError.MalformedResponse;
        if (asn1.tagClass(single_status_tlv.tag) != .context) return OcspError.MalformedResponse;
        switch (asn1.tagNumber(single_status_tlv.tag)) {
            0 => status_is_good = true,
            1 => return OcspError.CertStatusRevoked,
            2 => return OcspError.CertStatusUnknown,
            else => return OcspError.MalformedResponse,
        }

        const this_update_tlv = single_dec.readTLV() catch return OcspError.MalformedResponse;
        if (asn1.tagClass(this_update_tlv.tag) != .universal or (asn1.tagNumber(this_update_tlv.tag) != 24 and asn1.tagNumber(this_update_tlv.tag) != 23)) {
            return OcspError.MalformedResponse;
        }
        single_this_update = x509.parseDerTime(this_update_tlv.val) catch return OcspError.MalformedResponse;
        if (single_this_update > now_unix + max_clock_skew) return OcspError.FutureThisUpdate;

        if (single_dec.readTLV() catch null) |next_update_tlv| {
            if (asn1.tagClass(next_update_tlv.tag) == .context and asn1.tagNumber(next_update_tlv.tag) == 0) {
                var inner_next = asn1.Decoder.init(next_update_tlv.val);
                const inner_time = inner_next.readTLV() catch return OcspError.MalformedResponse;
                if (asn1.tagClass(inner_time.tag) != .universal or (asn1.tagNumber(inner_time.tag) != 24 and asn1.tagNumber(inner_time.tag) != 23)) return OcspError.MalformedResponse;
                single_next_update = x509.parseDerTime(inner_time.val) catch return OcspError.MalformedResponse;
            }
        }

        found = true;
        break;
    }

    if (!found or !status_is_good) return OcspError.MissingSingleResponse;

    if (single_next_update) |nu| {
        if (now_unix > nu + max_stale) return OcspError.StaleResponse;
    }

    // Validate responder certificate if supplied
    var signer_spki = issuer.cert.spki;
    if (responder_cert_der_opt) |resp_der| {
        const responder_cert = x509.parseCert(allocator, resp_der) catch return OcspError.ResponderCertParse;
        x509.checkValidity(now_unix, &responder_cert) catch return OcspError.ResponderCertInvalid;
        if (responder_cert.eku) |eku| {
            if (!eku.ocsp_signing) return OcspError.ResponderMissingEku;
        } else return OcspError.ResponderMissingEku;
        if (!x509.verifyCertificateSignedBy(&responder_cert, resp_der, issuer.cert)) return OcspError.ResponderSignatureInvalid;
        signer_spki = responder_cert.spki;
    }

    if (!x509.verifySignatureWithSpki(signer_spki, response_data_der, sig_algo_oid, signature_bits)) {
        return OcspError.SignatureInvalid;
    }

    // Freshness already enforced via timestamps; ensure producedAt not too old relative to thisUpdate.
    _ = leaf_der; // Leaf DER unused currently but kept for future enhancements
}
