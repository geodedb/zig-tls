//! Conformance Test Suite
//!
//! This module contains conformance tests against reference implementations
//! (BoringSSL, OpenSSL) to ensure compatibility and correctness.
//!
//! ## Test Organization
//!
//! Conformance tests validate that ztls produces identical outputs to:
//! - **BoringSSL**: Google's TLS implementation (used in Chromium, Android)
//! - **OpenSSL**: Industry-standard cryptographic library
//!
//! Test categories:
//! - HKDF key derivation
//! - AEAD operations (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)
//! - Alert code mapping (TLS alerts to QUIC error codes)
//! - X.509 certificate parsing
//! - OCSP response handling
//! - SCT (Signed Certificate Timestamp) parsing
//! - Signature verification
//!
//! ## Usage
//!
//! Run all conformance tests:
//! ```bash
//! make test-conformance
//! # or
//! zig build test-conformance
//! ```
//!
//! Run specific conformance suite:
//! ```bash
//! zig test tests/conformance/boringssl.zig
//! zig test tests/conformance/openssl.zig
//! ```
//!
//! ## Dependencies
//!
//! Conformance tests require OpenSSL development libraries:
//! ```bash
//! # Ubuntu/Debian
//! sudo apt-get install libssl-dev pkg-config
//!
//! # Fedora/RHEL
//! sudo dnf install openssl-devel pkg-config
//!
//! # Arch Linux
//! sudo pacman -S openssl pkg-config
//!
//! # macOS
//! brew install openssl pkg-config
//! ```

const std = @import("std");

// Re-export conformance test modules
// TODO: Move existing conformance tests here:
// pub const boringssl = @import("boringssl.zig");
// pub const openssl = @import("openssl.zig");
// pub const openssl_hkdf = @import("openssl_hkdf.zig");
// pub const x509_openssl = @import("x509_openssl.zig");
// pub const ocsp_openssl = @import("ocsp_openssl.zig");
// pub const sct_openssl = @import("sct_openssl.zig");
// pub const handshake = @import("handshake.zig");

test {
    std.testing.refAllDecls(@This());
}
