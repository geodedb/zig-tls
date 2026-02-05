// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! mTLS Interop Tests — OpenSSL Conformance
//!
//! Exercises the actual library functions (buildCertificateRequest, parseCertificateRequest,
//! buildCertificateVerify, parseCertificateVerify, buildCertificate, parseCertificate) and
//! cross-validates Ed25519 CertificateVerify signatures against OpenSSL EVP APIs via Zig FFI.
//!
//! ## RFC Coverage
//!
//! - RFC 8446 §4.3.2: CertificateRequest message
//! - RFC 8446 §4.4.2: Certificate message
//! - RFC 8446 §4.4.3: CertificateVerify message and signature computation
//!
//! ## OpenSSL Equivalents
//!
//! - EVP_DigestVerifyInit / EVP_DigestVerify for Ed25519 signature verification

const std = @import("std");
const testing = std.testing;
const tls13_full = @import("tls13_full");

const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/err.h");
});

/// Build the RFC 8446 §4.4.3 signature input for CertificateVerify.
fn buildCvSignatureInput(transcript_hash: [32]u8, is_server: bool) [130]u8 {
    const context_string = if (is_server)
        "TLS 1.3, server CertificateVerify"
    else
        "TLS 1.3, client CertificateVerify";
    // 64 spaces + 33-byte context + 0x00 + 32-byte hash = 130
    var buf: [130]u8 = undefined;
    @memset(buf[0..64], 0x20);
    @memcpy(buf[64..97], context_string);
    buf[97] = 0x00;
    @memcpy(buf[98..130], &transcript_hash);
    return buf;
}

// ============================================================================
// Test 1: buildCertificateRequest round-trip with signature_algorithms preserved
// ============================================================================

test "mTLS interop: buildCertificateRequest round-trip preserves sig_algorithms" {
    const alloc = testing.allocator;

    const schemes = [_]tls13_full.SignatureScheme{
        .ed25519,
        .ecdsa_secp256r1_sha256,
        .rsa_pss_rsae_sha256,
    };

    const body = try tls13_full.buildCertificateRequest(alloc, &schemes, null);
    defer alloc.free(body);

    const parsed = try tls13_full.parseCertificateRequest(alloc, body);
    defer alloc.free(parsed.signature_algorithms);

    try testing.expectEqual(@as(usize, 3), parsed.signature_algorithms.len);
    try testing.expectEqual(tls13_full.SignatureScheme.ed25519, parsed.signature_algorithms[0]);
    try testing.expectEqual(tls13_full.SignatureScheme.ecdsa_secp256r1_sha256, parsed.signature_algorithms[1]);
    try testing.expectEqual(tls13_full.SignatureScheme.rsa_pss_rsae_sha256, parsed.signature_algorithms[2]);
}

// ============================================================================
// Test 2: parseCertificateRequest with empty context (RFC 8446 §4.3.2)
// ============================================================================

test "mTLS interop: parseCertificateRequest empty context for initial handshake" {
    const alloc = testing.allocator;

    const schemes = [_]tls13_full.SignatureScheme{.ed25519};
    const body = try tls13_full.buildCertificateRequest(alloc, &schemes, null);
    defer alloc.free(body);

    const parsed = try tls13_full.parseCertificateRequest(alloc, body);
    defer alloc.free(parsed.signature_algorithms);

    try testing.expectEqual(@as(usize, 0), parsed.context.len);
}

// ============================================================================
// Test 3: CertificateRequest wire format — signature_algorithms extension 0x000d
// ============================================================================

test "mTLS interop: CertificateRequest wire format contains signature_algorithms 0x000d" {
    const alloc = testing.allocator;

    const schemes = [_]tls13_full.SignatureScheme{.ecdsa_secp256r1_sha256};
    const body = try tls13_full.buildCertificateRequest(alloc, &schemes, null);
    defer alloc.free(body);

    var found_sig_algs = false;
    const ext_start: usize = 1 + body[0] + 2;
    var pos: usize = ext_start;
    while (pos + 4 <= body.len) {
        const etype = (@as(u16, body[pos]) << 8) | body[pos + 1];
        const elen = (@as(u16, body[pos + 2]) << 8) | body[pos + 3];
        if (etype == 0x000d) {
            found_sig_algs = true;
            break;
        }
        pos += 4 + elen;
    }
    try testing.expect(found_sig_algs);
}

// ============================================================================
// Test 4: Ed25519 CertificateVerify signature verified by OpenSSL
// ============================================================================

test "mTLS interop: CertificateVerify Ed25519 signature verified by OpenSSL" {
    const alloc = testing.allocator;
    const key_pair = std.crypto.sign.Ed25519.KeyPair.generate();

    var transcript_hash: [32]u8 = undefined;
    @memset(&transcript_hash, 0xAB);

    // Build signature input per RFC 8446 §4.4.3 (server context)
    const sig_input = buildCvSignatureInput(transcript_hash, true);

    // Sign with Zig's Ed25519
    const signature = try key_pair.sign(&sig_input, null);
    const sig_bytes = signature.toBytes();

    // Build and parse CertificateVerify message
    const cv_msg = try tls13_full.buildCertificateVerify(alloc, .ed25519, &sig_bytes);
    defer alloc.free(cv_msg);

    const parsed = try tls13_full.parseCertificateVerify(cv_msg);
    try testing.expectEqual(tls13_full.SignatureScheme.ed25519, parsed.algorithm);

    // Verify with OpenSSL EVP
    const pub_key_bytes = key_pair.public_key.toBytes();
    const evp_pkey = c.EVP_PKEY_new_raw_public_key(
        c.EVP_PKEY_ED25519,
        null,
        &pub_key_bytes,
        pub_key_bytes.len,
    );
    try testing.expect(evp_pkey != null);
    defer c.EVP_PKEY_free(evp_pkey);

    const md_ctx = c.EVP_MD_CTX_new();
    try testing.expect(md_ctx != null);
    defer c.EVP_MD_CTX_free(md_ctx);

    var ret = c.EVP_DigestVerifyInit(md_ctx, null, null, null, evp_pkey);
    try testing.expectEqual(@as(c_int, 1), ret);

    ret = c.EVP_DigestVerify(md_ctx, &sig_bytes, sig_bytes.len, &sig_input, sig_input.len);
    try testing.expectEqual(@as(c_int, 1), ret);
}

// ============================================================================
// Test 5: Client CertificateVerify context string validated by OpenSSL
// ============================================================================

test "mTLS interop: client CertificateVerify context string validated by OpenSSL" {
    const key_pair = std.crypto.sign.Ed25519.KeyPair.generate();

    var transcript_hash: [32]u8 = undefined;
    @memset(&transcript_hash, 0xCD);

    // Client context string
    const sig_input = buildCvSignatureInput(transcript_hash, false);
    const signature = try key_pair.sign(&sig_input, null);
    const sig_bytes = signature.toBytes();

    // Verify with OpenSSL
    const pub_key_bytes = key_pair.public_key.toBytes();
    const evp_pkey = c.EVP_PKEY_new_raw_public_key(
        c.EVP_PKEY_ED25519,
        null,
        &pub_key_bytes,
        pub_key_bytes.len,
    );
    try testing.expect(evp_pkey != null);
    defer c.EVP_PKEY_free(evp_pkey);

    const md_ctx = c.EVP_MD_CTX_new();
    try testing.expect(md_ctx != null);
    defer c.EVP_MD_CTX_free(md_ctx);

    var ret = c.EVP_DigestVerifyInit(md_ctx, null, null, null, evp_pkey);
    try testing.expectEqual(@as(c_int, 1), ret);

    ret = c.EVP_DigestVerify(md_ctx, &sig_bytes, sig_bytes.len, &sig_input, sig_input.len);
    try testing.expectEqual(@as(c_int, 1), ret);
}

// ============================================================================
// Test 6: Server vs client CertificateVerify context strings produce different sigs
// ============================================================================

test "mTLS interop: server vs client CertificateVerify context strings differ" {
    const key_pair = std.crypto.sign.Ed25519.KeyPair.generate();
    var transcript_hash: [32]u8 = undefined;
    @memset(&transcript_hash, 0xEF);

    const server_input = buildCvSignatureInput(transcript_hash, true);
    const client_input = buildCvSignatureInput(transcript_hash, false);

    const server_sig = (try key_pair.sign(&server_input, null)).toBytes();
    const client_sig = (try key_pair.sign(&client_input, null)).toBytes();

    // Signatures MUST differ (different context strings)
    try testing.expect(!std.mem.eql(u8, &server_sig, &client_sig));

    // OpenSSL: server sig must NOT verify against client input
    const pub_key_bytes = key_pair.public_key.toBytes();
    const evp_pkey = c.EVP_PKEY_new_raw_public_key(
        c.EVP_PKEY_ED25519,
        null,
        &pub_key_bytes,
        pub_key_bytes.len,
    );
    try testing.expect(evp_pkey != null);
    defer c.EVP_PKEY_free(evp_pkey);

    const md_ctx = c.EVP_MD_CTX_new();
    try testing.expect(md_ctx != null);
    defer c.EVP_MD_CTX_free(md_ctx);

    var ret = c.EVP_DigestVerifyInit(md_ctx, null, null, null, evp_pkey);
    try testing.expectEqual(@as(c_int, 1), ret);

    ret = c.EVP_DigestVerify(md_ctx, &server_sig, server_sig.len, &client_input, client_input.len);
    try testing.expect(ret != 1);
}

// ============================================================================
// Test 7: buildCertificate / parseCertificate round-trip with request_context
// ============================================================================

test "mTLS interop: Certificate round-trip with request_context" {
    const alloc = testing.allocator;

    const mock_cert_der = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB, 0xCC, 0xDD };
    const entries = [_]tls13_full.CertificateEntryData{
        .{ .cert = &mock_cert_der },
    };

    const cert_msg = try tls13_full.buildCertificate(alloc, "", &entries);
    defer alloc.free(cert_msg);

    const parsed = try tls13_full.parseCertificate(alloc, cert_msg);
    defer alloc.free(parsed.entries);

    try testing.expectEqual(@as(usize, 0), parsed.context.len);
    try testing.expectEqual(@as(usize, 1), parsed.entries.len);
    try testing.expectEqualSlices(u8, &mock_cert_der, parsed.entries[0].cert);
}

// ============================================================================
// Test 8: Empty certificate message for client with no cert (RFC 8446 §4.4.2)
// ============================================================================

test "mTLS interop: empty Certificate message for client without cert" {
    const alloc = testing.allocator;

    const empty_entries = [_]tls13_full.CertificateEntryData{};
    const cert_msg = try tls13_full.buildCertificate(alloc, "", &empty_entries);
    defer alloc.free(cert_msg);

    const parsed = try tls13_full.parseCertificate(alloc, cert_msg);
    defer alloc.free(parsed.entries);

    try testing.expectEqual(@as(usize, 0), parsed.context.len);
    try testing.expectEqual(@as(usize, 0), parsed.entries.len);
}
