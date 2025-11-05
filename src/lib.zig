//! ztls: TLS 1.3 implementation for QUIC
//!
//! This library provides a TLS 1.3 implementation strictly adhering to RFC 8446
//! and RFC 9001 (QUIC-TLS). It is designed to be integrated into QUIC stacks
//! and uses only Zig standard library primitives with no external dependencies.
//!
//! ## Usage
//!
//! ```zig
//! const tls = @import("ztls");
//!
//! // Create a TLS context for a QUIC connection
//! var ctx = try tls.Context.init(config, callbacks);
//! defer ctx.deinit();
//!
//! // Process incoming CRYPTO frames
//! try ctx.processCrypto(crypto_data);
//!
//! // Get outgoing CRYPTO data
//! const outgoing = ctx.getOutgoingCrypto();
//! ```
//!
//! ## Architecture
//!
//! The library is organized into several modules:
//! - `tls13`: Main TLS 1.3 context and handshake state machine
//! - `key_schedule`: HKDF-based key derivation (RFC 8446 §7, RFC 9001 §5.1)
//! - `record`: TLS 1.3 record layer primitives and AEAD protection
//! - `x509`: X.509 certificate parsing and validation
//! - `sig`: Signature scheme handling and verification
//! - `alert`: TLS alert protocol and QUIC error mapping
//! - `zero_rtt`: 0-RTT ticket tracking and anti-replay
//!
//! See CLAUDE.md for detailed architecture documentation.

const std = @import("std");

// Core TLS 1.3 modules
pub const tls13 = @import("tls13");
pub const key_schedule = @import("quic_tls");
pub const record = @import("record");

// Certificate and signature handling
pub const x509 = @import("x509");
pub const sig = @import("sig");
pub const asn1 = @import("asn1");

// Protocol support modules
pub const alert = @import("alert");
pub const zero_rtt = @import("zero_rtt");
pub const tls13_full = @import("tls13_full");

// Re-export commonly used types from tls13 module
pub const Context = tls13.Context;
pub const Config = tls13.Config;
pub const Callbacks = tls13.Callbacks;
pub const Role = tls13.Role;
pub const EncryptionLevel = tls13.EncryptionLevel;
pub const HandshakeMetadata = tls13.HandshakeMetadata;
pub const SignatureScheme = tls13.SignatureScheme;

// Re-export cipher suites and extensions
pub const CipherSuite = tls13_full.CipherSuite;
pub const NamedGroup = tls13_full.NamedGroup;
pub const ExtensionType = tls13_full.ExtensionType;

// Re-export key schedule types
pub const H = key_schedule.H;
pub const initial_salt_v1 = key_schedule.initial_salt_v1;
pub const initial_salt_v2 = key_schedule.initial_salt_v2;

// Re-export alert types
pub const AlertDescription = alert.AlertDescription;
pub const AlertLevel = alert.AlertLevel;
pub const Alert = alert.Alert;

// Version information
pub const version = std.SemanticVersion{
    .major = 0,
    .minor = 1,
    .patch = 0,
};

test {
    // Run tests for all modules
    std.testing.refAllDecls(@This());
}
