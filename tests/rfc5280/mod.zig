//! RFC 5280: X.509 Certificate and CRL Profile Test Suite
//!
//! This module organizes tests for X.509 certificate parsing and validation
//! per RFC 5280 (Internet X.509 Public Key Infrastructure Certificate and
//! Certificate Revocation List Profile).
//!
//! ## Test Organization
//!
//! Tests are organized by RFC 5280 section:
//! - §4.1: Basic Certificate Fields (version, serial, signature, issuer, validity, subject)
//! - §4.2: Certificate Extensions (standard and critical extensions)
//! - §4.2.1.3: Key Usage extension
//! - §4.2.1.4: Certificate Policies extension
//! - §4.2.1.6: Subject Alternative Name extension
//! - §4.2.1.9: Basic Constraints extension
//! - §4.2.1.10: Name Constraints extension
//! - §4.2.1.12: Extended Key Usage extension
//! - §6: Certification Path Validation
//! - §6.1: Basic Path Validation
//! - §6.2: Using the Path Validation Algorithm
//!
//! ## Usage
//!
//! Run all RFC 5280 tests:
//! ```bash
//! zig build test-rfc5280
//! ```
//!
//! Run specific section tests:
//! ```bash
//! zig test tests/rfc5280/section_4_1_basic_fields.zig
//! zig test tests/rfc5280/section_6_path_validation.zig
//! ```
//!
//! ## TLS Integration
//!
//! X.509 certificates in TLS 1.3 (RFC 8446 §4.4.2):
//! - Certificate message contains a certificate_list
//! - Each entry can have extensions (OCSP, SCT)
//! - Certificate must be valid for the negotiated signature scheme
//! - Server certificates must include serverAuth extended key usage
//! - Subject Alternative Name must match the server name (SNI)

const std = @import("std");

// Re-export test modules for discovery
pub const section_4_certificate_structure = @import("section_4_certificate_structure.zig");
pub const section_6_path_validation = @import("section_6_path_validation.zig");

test {
    std.testing.refAllDecls(@This());
}
