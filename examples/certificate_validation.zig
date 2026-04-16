// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
//
//! Certificate Validation Example
//!
//! Demonstrates X.509 certificate parsing and validation for TLS 1.3.
//! Covers:
//! - Certificate parsing (DER format)
//! - Subject Alternative Name (SAN) matching
//! - Certificate chain validation
//! - Trust store integration
//!
//! ## RFC References
//! - RFC 5280: X.509 Certificate Profile
//! - RFC 8446 Section 4.4.2: Certificate message
//! - RFC 6125: Server Identity Verification

const std = @import("std");
const ztls = @import("ztls");

/// Example trust store callback.
/// In production, this would check against system or application trust anchors.
fn isTrustedSpki(spki_der: []const u8) bool {
    // In real implementation: compare SPKI hash against known trusted roots
    _ = spki_der;
    std.debug.print("     Trust store callback invoked\n", .{});
    return true; // Accept for demonstration
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== X.509 Certificate Validation Examples ===\n\n", .{});

    // =========================================================================
    // Example 1: Certificate Structure Overview
    // =========================================================================
    std.debug.print("1. X.509 Certificate Structure (RFC 5280)\n\n", .{});

    std.debug.print("   Certificate ::= SEQUENCE {{\n", .{});
    std.debug.print("       tbsCertificate       TBSCertificate,\n", .{});
    std.debug.print("       signatureAlgorithm   AlgorithmIdentifier,\n", .{});
    std.debug.print("       signatureValue       BIT STRING\n", .{});
    std.debug.print("   }}\n\n", .{});

    std.debug.print("   TBSCertificate includes:\n", .{});
    std.debug.print("     - version (v3 for TLS 1.3)\n", .{});
    std.debug.print("     - serialNumber\n", .{});
    std.debug.print("     - issuer (DN)\n", .{});
    std.debug.print("     - validity (notBefore, notAfter)\n", .{});
    std.debug.print("     - subject (DN)\n", .{});
    std.debug.print("     - subjectPublicKeyInfo (SPKI)\n", .{});
    std.debug.print("     - extensions (SAN, BasicConstraints, etc.)\n\n", .{});

    // =========================================================================
    // Example 2: Server Name Matching
    // =========================================================================
    std.debug.print("2. DNS Name Matching (RFC 6125)\n\n", .{});

    // Demonstrate matching logic
    std.debug.print("   Exact match:\n", .{});
    std.debug.print("     'example.com' matches 'example.com': true\n", .{});
    std.debug.print("     'example.com' matches 'Example.COM': true (case-insensitive)\n\n", .{});

    std.debug.print("   Wildcard match (*.example.com):\n", .{});
    std.debug.print("     'www.example.com' matches '*.example.com': true\n", .{});
    std.debug.print("     'example.com' matches '*.example.com': false (no left label)\n", .{});
    std.debug.print("     'sub.www.example.com' matches '*.example.com': false (multiple labels)\n\n", .{});

    // =========================================================================
    // Example 3: Name Constraints (RFC 5280 Section 4.2.1.10)
    // =========================================================================
    std.debug.print("3. Name Constraints Validation\n\n", .{});

    // Demonstrate name constraint checking
    const permitted = [_][]const u8{".example.com"};
    const excluded = [_][]const u8{".forbidden.example.com"};

    const constraints = ztls.x509.NameConstraints{
        .permitted_dns = &permitted,
        .excluded_dns = &excluded,
    };

    const test_names = [_][]const u8{
        "www.example.com",
        "api.example.com",
        "test.forbidden.example.com",
        "other.net",
    };

    for (test_names) |name| {
        const ok = ztls.x509.checkNameConstraints(name, constraints);
        std.debug.print("   '{s}': {s}\n", .{
            name,
            if (ok) "ALLOWED" else "DENIED",
        });
    }
    std.debug.print("\n", .{});

    // =========================================================================
    // Example 4: Trust Store Setup
    // =========================================================================
    std.debug.print("4. Trust Store Integration\n\n", .{});

    std.debug.print("   Setting up trust store with callback...\n", .{});
    ztls.x509.setTrustStore(.{ .isTrustedSpki = isTrustedSpki });
    std.debug.print("   Trust store registered\n\n", .{});

    std.debug.print("   Trust store is used by validateChain() to verify root CA.\n", .{});
    std.debug.print("   Callback receives SPKI (SubjectPublicKeyInfo) of root certificate.\n", .{});
    std.debug.print("   Return true to accept, false to reject.\n\n", .{});

    // Clear trust store
    ztls.x509.setTrustStore(null);

    // =========================================================================
    // Example 5: Validation Flow
    // =========================================================================
    std.debug.print("5. Certificate Chain Validation Flow\n\n", .{});

    std.debug.print("   validateChain(chain_der, now_unix, server_name, allow_insecure)\n\n", .{});

    std.debug.print("   Validation steps:\n", .{});
    std.debug.print("     1. Parse all certificates in chain\n", .{});
    std.debug.print("     2. Check leaf certificate validity period\n", .{});
    std.debug.print("     3. Verify server_name matches leaf SAN/CN\n", .{});
    std.debug.print("     4. Check ExtendedKeyUsage includes serverAuth\n", .{});
    std.debug.print("     5. Check KeyUsage includes digitalSignature\n", .{});
    std.debug.print("     6. Verify intermediate CAs have BasicConstraints CA=true\n", .{});
    std.debug.print("     7. Enforce path length constraints\n", .{});
    std.debug.print("     8. Verify signatures along the chain\n", .{});
    std.debug.print("     9. Validate root against trust store\n\n", .{});

    // =========================================================================
    // Example 6: Time Parsing (RFC 5280 Section 4.1.2.5)
    // =========================================================================
    std.debug.print("6. Certificate Time Formats\n\n", .{});

    // UTCTime format (YYMMDDHHMMSSZ)
    const utc_time = "231225120000Z"; // Dec 25, 2023 12:00:00 UTC
    const utc_unix = ztls.x509.parseDerTime(utc_time) catch 0;
    std.debug.print("   UTCTime '{s}': {} unix seconds\n", .{ utc_time, utc_unix });

    // GeneralizedTime format (YYYYMMDDHHMMSSZ)
    const gen_time = "20231225120000Z";
    const gen_unix = ztls.x509.parseDerTime(gen_time) catch 0;
    std.debug.print("   GeneralizedTime '{s}': {} unix seconds\n", .{ gen_time, gen_unix });

    std.debug.print("\n   RFC 5280: UTCTime for years 1950-2049, GeneralizedTime otherwise\n\n", .{});

    // =========================================================================
    // Example 7: Signature Algorithms
    // =========================================================================
    std.debug.print("7. Supported Signature Algorithms\n\n", .{});

    std.debug.print("   Certificate signature verification supports:\n", .{});
    std.debug.print("     - ecdsa_secp256r1_sha256 (ECDSA P-256)\n", .{});
    std.debug.print("     - ecdsa_secp384r1_sha384 (ECDSA P-384)\n", .{});
    std.debug.print("     - rsa_pss_rsae_sha256 (RSA-PSS)\n", .{});
    std.debug.print("     - ed25519 (EdDSA)\n\n", .{});

    // =========================================================================
    // Example 8: Error Handling
    // =========================================================================
    std.debug.print("8. Common Validation Errors\n\n", .{});

    std.debug.print("   error.EmptyChain         - No certificates provided\n", .{});
    std.debug.print("   error.NotYetValid        - Certificate notBefore is in future\n", .{});
    std.debug.print("   error.Expired            - Certificate notAfter is in past\n", .{});
    std.debug.print("   error.NameMismatch       - Server name doesn't match SAN/CN\n", .{});
    std.debug.print("   error.EkuNotAllowed      - Missing serverAuth EKU\n", .{});
    std.debug.print("   error.KuNotAllowed       - Missing digitalSignature KeyUsage\n", .{});
    std.debug.print("   error.BasicConstraints   - CA cert missing or invalid BC\n", .{});
    std.debug.print("   error.PathLenExceeded    - Path length constraint violated\n", .{});
    std.debug.print("   error.BadSignature       - Signature verification failed\n", .{});
    std.debug.print("   error.UntrustedRoot      - Root not in trust store\n\n", .{});

    // =========================================================================
    // Example 9: Practical Usage
    // =========================================================================
    std.debug.print("9. Practical Validation Example (Pseudocode)\n\n", .{});

    std.debug.print("   // In TLS handshake after receiving Certificate message:\n", .{});
    std.debug.print("   const chain_der = [_][]const u8{{ leaf_der, intermediate_der, root_der }};\n", .{});
    std.debug.print("   const now = @as(i64, @intCast(@divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s)));\n", .{});
    std.debug.print("   \n", .{});
    std.debug.print("   x509.validateChain(\n", .{});
    std.debug.print("       allocator,\n", .{});
    std.debug.print("       &chain_der,\n", .{});
    std.debug.print("       now,\n", .{});
    std.debug.print("       \"example.com\",  // from SNI\n", .{});
    std.debug.print("       false,            // allow_insecure = false in production!\n", .{});
    std.debug.print("   ) catch |err| {{\n", .{});
    std.debug.print("       // Send appropriate TLS alert\n", .{});
    std.debug.print("       return sendAlert(.certificate_unknown);\n", .{});
    std.debug.print("   }};\n\n", .{});

    _ = allocator;
    std.debug.print("=== Certificate Validation Examples Complete ===\n", .{});
}
