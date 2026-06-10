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
