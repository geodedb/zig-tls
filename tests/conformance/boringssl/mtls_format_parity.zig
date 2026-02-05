// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! mTLS Format Parity Tests — BoringSSL Conformance
//!
//! Pure format validation tests ensuring CertificateRequest wire encoding matches
//! what BoringSSL and other TLS 1.3 stacks expect.  No OpenSSL linking required.
//!
//! ## RFC Coverage
//!
//! - RFC 8446 §4.3.2: CertificateRequest message wire format
//! - RFC 8446 §4.2.3: signature_algorithms extension (type 0x000d)
//!
//! ## Test Methodology
//!
//! Byte-level inspection of serialized messages to confirm:
//! - Context length encoding
//! - Extension type identifiers
//! - Length prefix sizes
//! - Round-trip fidelity

const std = @import("std");
const testing = std.testing;
const tls13_full = @import("tls13_full");

// ============================================================================
// Test 1: CertificateRequest context length byte is 0 for initial handshake
// ============================================================================

test "mTLS format parity: CertificateRequest context length byte is 0" {
    const alloc = testing.allocator;

    const schemes = [_]tls13_full.SignatureScheme{.ed25519};
    const body = try tls13_full.buildCertificateRequest(alloc, &schemes, null);
    defer alloc.free(body);

    // First byte is certificate_request_context length — MUST be 0 for initial handshake
    try testing.expectEqual(@as(u8, 0), body[0]);
}

// ============================================================================
// Test 2: signature_algorithms extension type is 0x000d in wire format
// ============================================================================

test "mTLS format parity: signature_algorithms extension type 0x000d" {
    const alloc = testing.allocator;

    const schemes = [_]tls13_full.SignatureScheme{.ecdsa_secp256r1_sha256};
    const body = try tls13_full.buildCertificateRequest(alloc, &schemes, null);
    defer alloc.free(body);

    // Wire layout: [ctx_len:1][extensions_len:2][ext_type:2][ext_len:2]...
    // With ctx_len=0: byte 0 = 0x00, bytes 1-2 = ext_total_len, bytes 3-4 = ext_type
    try testing.expect(body.len >= 5);

    const ext_type_hi = body[3];
    const ext_type_lo = body[4];
    try testing.expectEqual(@as(u8, 0x00), ext_type_hi);
    try testing.expectEqual(@as(u8, 0x0d), ext_type_lo);
}

// ============================================================================
// Test 3: Extension length encoding matches TLS 1.3 2-byte length prefix
// ============================================================================

test "mTLS format parity: extension length uses 2-byte prefix" {
    const alloc = testing.allocator;

    const schemes = [_]tls13_full.SignatureScheme{ .ed25519, .ecdsa_secp256r1_sha256 };
    const body = try tls13_full.buildCertificateRequest(alloc, &schemes, null);
    defer alloc.free(body);

    // After ctx_len(1) + extensions_total_len(2) + ext_type(2), we get ext_data_len(2)
    try testing.expect(body.len >= 7);

    const ext_data_len = (@as(u16, body[5]) << 8) | body[6];

    // The extension data for signature_algorithms contains:
    //   [list_len:2][scheme1:2][scheme2:2] = 2 + 2*2 = 6 bytes
    try testing.expectEqual(@as(u16, 6), ext_data_len);
}

// ============================================================================
// Test 4: CertificateRequest total message length validation
// ============================================================================

test "mTLS format parity: CertificateRequest total length is consistent" {
    const alloc = testing.allocator;

    const schemes = [_]tls13_full.SignatureScheme{.ed25519};
    const body = try tls13_full.buildCertificateRequest(alloc, &schemes, null);
    defer alloc.free(body);

    // Expected layout for 1 scheme, no CA certs:
    //   ctx_len(1) = 0
    //   extensions_total_len(2)
    //   signature_algorithms extension:
    //     ext_type(2) + ext_data_len(2) + list_len(2) + scheme(2) = 8
    // Total = 1 + 2 + 8 = 11
    const expected_len: usize = 1 + 2 + (2 + 2 + 2 + 2);
    try testing.expectEqual(expected_len, body.len);

    // Verify extensions_total_len matches remaining bytes
    const ext_total_len = (@as(u16, body[1]) << 8) | body[2];
    try testing.expectEqual(@as(u16, @intCast(body.len - 3)), ext_total_len);
}

// ============================================================================
// Test 5: Round-trip — build → serialize → parse produces identical structures
// ============================================================================

test "mTLS format parity: build-parse round-trip identity" {
    const alloc = testing.allocator;

    const schemes = [_]tls13_full.SignatureScheme{
        .ed25519,
        .ecdsa_secp256r1_sha256,
        .rsa_pss_rsae_sha256,
    };

    // Build first message
    const body1 = try tls13_full.buildCertificateRequest(alloc, &schemes, null);
    defer alloc.free(body1);

    // Parse it
    const parsed = try tls13_full.parseCertificateRequest(alloc, body1);
    defer alloc.free(parsed.signature_algorithms);

    // Re-build from parsed data
    const body2 = try tls13_full.buildCertificateRequest(alloc, parsed.signature_algorithms, null);
    defer alloc.free(body2);

    // Wire bytes must be identical
    try testing.expectEqualSlices(u8, body1, body2);
}
