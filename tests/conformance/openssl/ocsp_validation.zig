// OCSP (Online Certificate Status Protocol) Validation Conformance Tests
// Phase 5, Task 1: OCSP stapling and response validation
//
// These tests drive the real library entry point
// `ocsp.validateStapledResponse` against OpenSSL-generated OCSP fixtures so the
// conformance suite exercises end-to-end DER parsing, CertID matching,
// freshness checks, and signature verification — not hand-rolled enums.
//
// Fixtures (tests/test_certs/gen_ocsp.sh):
//   ocsp_ca.der               - issuing CA cert (also the OCSP response signer)
//   ocsp_leaf.der             - leaf cert under test (serial 0x1010)
//   ocsp_response_good.der    - BasicOCSPResponse, Cert Status: good
//   ocsp_response_revoked.der - BasicOCSPResponse, Cert Status: revoked
//
// CRITICAL: the CertID hashAlgorithm in these fixtures is SHA-256, generated
// with `openssl ocsp -sha256`. The library deliberately rejects SHA-1 CertIDs
// (CWE-328): src/ocsp.zig matchSingleResponse SKIPS any SingleResponse whose
// CertID hash is SHA-1, which would otherwise yield MissingSingleResponse. The
// responses carry no embedded responder cert (-resp_no_certs), so the library
// verifies the signature directly against the issuer (CA) SPKI.
//
// RFC References:
// - RFC 6066 §8: Certificate Status Request (status_request extension)
// - RFC 6960: X.509 PKI Online Certificate Status Protocol - OCSP
// - RFC 5280 §4.2.1.13: CRL Distribution Points (alternative to OCSP)
//
// OpenSSL equivalents:
// - openssl ocsp -issuer ca.pem -sha256 -cert leaf.pem -reqout req.der
// - openssl ocsp -index db -CA ca.pem -rsigner ca.pem -rkey ca.key \
//       -reqin req.der -respout resp.der -resp_no_certs

const std = @import("std");
const testing = std.testing;
const x509 = @import("x509");
const ocsp = @import("ocsp");
const test_certs = @import("test_certs");

// 2027-06-10 00:00:00 UTC. Strictly inside the fixtures' validity window:
// thisUpdate = 2026-06-10, nextUpdate = 2036-06-07.
const NOW: i64 = 1812585600;

test "OCSP conformance: GOOD stapled response is accepted" {
    const a = testing.allocator;
    var ca = try x509.parseCert(a, test_certs.ocsp_ca);
    defer ca.deinit(a);
    var leaf = try x509.parseCert(a, test_certs.ocsp_leaf);
    defer leaf.deinit(a);

    const issuer = ocsp.IssuerInfo{ .cert = &ca, .der = test_certs.ocsp_ca };
    try ocsp.validateStapledResponse(
        a,
        test_certs.ocsp_response_good,
        &leaf,
        test_certs.ocsp_leaf,
        issuer,
        NOW,
    );
}

test "OCSP conformance: REVOKED stapled response is rejected (CertStatusRevoked)" {
    const a = testing.allocator;
    var ca = try x509.parseCert(a, test_certs.ocsp_ca);
    defer ca.deinit(a);
    var leaf = try x509.parseCert(a, test_certs.ocsp_leaf);
    defer leaf.deinit(a);

    const issuer = ocsp.IssuerInfo{ .cert = &ca, .der = test_certs.ocsp_ca };
    try testing.expectError(
        ocsp.OcspError.CertStatusRevoked,
        ocsp.validateStapledResponse(
            a,
            test_certs.ocsp_response_revoked,
            &leaf,
            test_certs.ocsp_leaf,
            issuer,
            NOW,
        ),
    );
}

test "OCSP conformance: tampered signature is rejected" {
    const a = testing.allocator;
    var ca = try x509.parseCert(a, test_certs.ocsp_ca);
    defer ca.deinit(a);
    var leaf = try x509.parseCert(a, test_certs.ocsp_leaf);
    defer leaf.deinit(a);

    const issuer = ocsp.IssuerInfo{ .cert = &ca, .der = test_certs.ocsp_ca };

    // Corrupt a byte inside the trailing signature BIT STRING of the GOOD
    // response. The CertID still matches (so we get past matchSingleResponse),
    // but the signature no longer verifies against the CA SPKI.
    var bad = try a.dupe(u8, test_certs.ocsp_response_good);
    defer a.free(bad);
    bad[bad.len - 5] ^= 0xFF;

    try testing.expectError(
        ocsp.OcspError.SignatureInvalid,
        ocsp.validateStapledResponse(
            a,
            bad,
            &leaf,
            test_certs.ocsp_leaf,
            issuer,
            NOW,
        ),
    );
}

test "OCSP conformance: missing issuer is rejected (MissingIssuer)" {
    const a = testing.allocator;
    var leaf = try x509.parseCert(a, test_certs.ocsp_leaf);
    defer leaf.deinit(a);

    // No issuer supplied: the response signature cannot be anchored, so the
    // library refuses to validate.
    try testing.expectError(
        ocsp.OcspError.MissingIssuer,
        ocsp.validateStapledResponse(
            a,
            test_certs.ocsp_response_good,
            &leaf,
            test_certs.ocsp_leaf,
            null,
            NOW,
        ),
    );
}
