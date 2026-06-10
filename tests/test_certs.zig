// SPDX-License-Identifier: Apache-2.0
//! Shared embedded X.509 test-certificate fixtures.
//!
//! Conformance tests under tests/conformance/**/ live in nested module roots
//! and cannot `@embedFile` the tests/test_certs/ directory directly (Zig's
//! module path sandbox). This module sits at tests/ root, embeds the DER
//! fixtures once, and re-exports them so any test target can `@import("test_certs")`.

// Real OpenSSL-generated chain: leaf -> intermediate -> root.
// `openssl verify -CAfile root -untrusted intermediate leaf` => OK.
pub const leaf = @embedFile("test_certs/leaf_cert.der");
pub const intermediate = @embedFile("test_certs/intermediate_cert.der");
pub const root = @embedFile("test_certs/root_cert.der");

// Self-signed single-cert fixtures.
pub const ed25519 = @embedFile("test_certs/ed25519_cert.der");
pub const p256 = @embedFile("test_certs/p256_cert.der");
pub const p384 = @embedFile("test_certs/p384_cert.der");
pub const rsa2048 = @embedFile("test_certs/rsa2048_cert.der");
pub const expired = @embedFile("test_certs/expired_cert.der");

// Name-constraint fixtures (gen_name_constraints.sh).
pub const nc_constrained_ca = @embedFile("test_certs/nc_constrained_ca.der");
pub const nc_permitted_leaf = @embedFile("test_certs/nc_permitted_leaf.der");
pub const nc_excluded_leaf = @embedFile("test_certs/nc_excluded_leaf.der");

// OCSP fixtures (gen_ocsp.sh).
pub const ocsp_response_good = @embedFile("test_certs/ocsp_response_good.der");
pub const ocsp_response_revoked = @embedFile("test_certs/ocsp_response_revoked.der");
pub const ocsp_ca = @embedFile("test_certs/ocsp_ca.der");
pub const ocsp_leaf = @embedFile("test_certs/ocsp_leaf.der");

// CRL fixtures (gen_crl.sh).
pub const crl_empty = @embedFile("test_certs/crl_empty.der");
pub const crl_with_revoked = @embedFile("test_certs/crl_with_revoked.der");
pub const crl_ca = @embedFile("test_certs/crl_ca.der");
pub const crl_leaf = @embedFile("test_certs/crl_leaf.der");
