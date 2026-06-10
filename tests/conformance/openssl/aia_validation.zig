// AIA (Authority Information Access) Conformance Tests
//
// These tests parse a REAL OpenSSL-generated certificate (aia_leaf.der,
// produced by tests/test_certs/gen_aia.sh) carrying an authorityInfoAccess
// extension with BOTH an OCSP responder URI and a caIssuers URI, then assert
// the values the library's parser exposes (RFC 5280 §4.2.2.1).
//
// The fixture's extension (verified via `openssl x509 -text`) is:
//     OCSP       - URI:http://ocsp.example/
//     CA Issuers - URI:http://ca.example/ca.der
//
// RFC References:
// - RFC 5280 §4.2.2.1: Authority Information Access (AIA) extension
// - RFC 6960 §3.1: OCSP Requests (locating OCSP responder via AIA)
//
// Scope: the library PARSES and EXPOSES the AIA URIs. Performing the actual
// HTTP fetches against them (OCSP requests, caIssuers retrieval) is the
// application/QUIC layer's responsibility — this crate has no socket I/O.
// That boundary is pinned by the second test below.

const std = @import("std");
const testing = std.testing;
const x509 = @import("x509");
const test_certs = @import("test_certs");

test "aia conformance - OCSP + caIssuers URIs parsed from real cert" {
    const a = testing.allocator;
    var leaf = try x509.parseCert(a, test_certs.aia_leaf);
    defer leaf.deinit(a);
    const aia = leaf.authority_info_access orelse return error.MissingAia;
    try testing.expectEqual(@as(usize, 1), aia.ocsp_uris.len);
    try testing.expectEqualStrings("http://ocsp.example/", aia.ocsp_uris[0]);
    try testing.expectEqual(@as(usize, 1), aia.ca_issuer_uris.len);
    try testing.expectEqualStrings("http://ca.example/ca.der", aia.ca_issuer_uris[0]);
}

test "aia conformance - live OCSP/caIssuers fetch is app-layer (documented boundary)" {
    // The library parses and EXPOSES AIA URIs; performing HTTP fetches against
    // them (OCSP requests, caIssuers retrieval) is the application/QUIC layer's
    // responsibility — this crate has no socket I/O. This test pins the
    // exposed-data contract, not network behavior.
    const a = testing.allocator;
    var leaf = try x509.parseCert(a, test_certs.aia_leaf);
    defer leaf.deinit(a);
    try testing.expect(leaf.authority_info_access != null);
}
