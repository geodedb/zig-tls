//! Full TLS 1.3 message parsing for QUIC-TLS interoperability.
//!
//! This module implements complete parsing and serialization of TLS 1.3 handshake
//! messages per RFC 8446 §4 (Handshake Protocol) and RFC 8446 §4.2 (Extensions).
//! It provides the real-world TLS format support needed for interoperability with
//! production QUIC stacks (quic-go, quinn, msquic, etc.).
//!
//! ## Design Philosophy: INTEROP FIRST
//!
//! This implementation prioritizes compatibility with standard TLS 1.3 formats:
//! - Parses all standard extension types and values from RFC 8446
//! - Supports real-world cipher suites, named groups, and signature schemes
//! - Auto-detects and handles formats used by major QUIC implementations
//! - Gracefully ignores unknown extensions per RFC 8446 §4.2 requirements
//!
//! ## RFC Coverage
//!
//! ### Core Protocol (RFC 8446)
//! - §4.1.2: ClientHello message structure
//! - §4.1.3: ServerHello message structure
//! - §4.2: Extension definitions and processing rules
//! - §4.2.3: Signature Algorithms extension (signature_algorithms)
//! - §4.2.7: Key Share extension (key_share)
//! - §4.2.8: Supported Groups extension (supported_groups)
//! - §4.2.9: Supported Versions extension (supported_versions)
//! - §4.2.10: Pre-Shared Key extension (pre_shared_key)
//! - §4.2.11: Pre-Shared Key Exchange Modes (psk_key_exchange_modes)
//! - §4.3.1: EncryptedExtensions message
//! - §4.4.2: Certificate message structure
//! - §4.4.3: CertificateVerify message
//! - §4.4: Finished message and verify_data computation
//! - Appendix B.3: Extension type values
//! - Appendix B.3.1: Named Group registry
//! - Appendix B.3.1.3: Signature Scheme registry
//! - Appendix B.4: Cipher suite values
//!
//! ### QUIC Integration (RFC 9001)
//! - §8.2: QUIC Transport Parameters extension (0x0039)
//! - §4.1: Extension placement rules (ServerHello vs EncryptedExtensions)
//!
//! ### ALPN (RFC 7301)
//! - Application-Layer Protocol Negotiation extension
//!
//! ### Additional RFCs
//! - RFC 7919: Finite Field Diffie-Hellman groups (ffdhe2048, ffdhe3072, etc.)
//! - RFC 8032: Ed25519 and Ed448 signature schemes
//! - RFC 8017: RSA-PSS signature schemes
//! - RFC 5280: X.509 certificate format (parsed but not validated here)
//!
//! ## Message Flow
//!
//! ```
//! Client                                           Server
//!
//! ClientHello
//!   + supported_versions (0x002b)
//!   + supported_groups (0x000a)
//!   + key_share (0x0033)
//!   + signature_algorithms (0x000d)
//!   + alpn (0x0010)
//!   + quic_transport_parameters (0x0039)
//!   [+ pre_shared_key (0x0029)]              -------->
//!                                            <--------  ServerHello
//!                                                         + key_share
//!                                                         + supported_versions
//!                                            <--------  EncryptedExtensions
//!                                                         + alpn
//!                                                         + quic_transport_parameters
//!                                            <--------  Certificate
//!                                            <--------  CertificateVerify
//!                                            <--------  Finished
//!                                            -------->  Finished
//! ```
//!
//! ## Security Considerations
//!
//! - Extension order in ServerHello is CRITICAL for transcript hash consistency
//! - Unknown extensions MUST be ignored per RFC 8446 §4.2 (avoid handshake failures)
//! - Pre-shared key binder validation required before accepting PSK (RFC 8446 §4.2.11)
//! - Session ID echo required in ServerHello for middlebox compatibility (RFC 8446 §4.1.3)
//! - Downgrade protection via random sentinel (not implemented in this module)
//!
//! ## Implementation Notes
//!
//! - Uses Zig standard library primitives (no external dependencies)
//! - Allocator-aware: all heap allocations explicit and caller-controlled
//! - Zero-copy parsing where possible (slices reference input buffer)
//! - Supports only TLS 1.3 cipher suites (0x1301-0x1305)
//! - QUIC transport parameters placed in EncryptedExtensions per RFC 9001 §8.2
//! - Extension parsing is additive: unsupported extensions are silently skipped

const std = @import("std");
const ks = @import("quic_tls");
const x509 = @import("x509");
const sig = @import("sig");
const logger = @import("quic_logger");
const H = ks.H; // SHA-256

// Import modular TLS 1.3 message parsing and building functions
const core_types = @import("tls13/messages/core_types.zig");
const helpers_mod = @import("tls13/messages/helpers.zig");
const client_hello_mod = @import("tls13/messages/client_hello.zig");
const server_hello_mod = @import("tls13/messages/server_hello.zig");
const encrypted_extensions_mod = @import("tls13/messages/encrypted_extensions.zig");
const certificate_mod = @import("tls13/messages/certificate.zig");
const certificate_verify_mod = @import("tls13/messages/certificate_verify.zig");
const finished_mod = @import("tls13/messages/finished.zig");

// Re-export core types for backward compatibility (RFC 8446 Appendix B)
pub const ExtensionType = core_types.ExtensionType;
pub const NamedGroup = core_types.NamedGroup;
pub const SignatureScheme = core_types.SignatureScheme;
pub const CipherSuite = core_types.CipherSuite;

// Re-export helper functions for backward compatibility
pub const readU16 = helpers_mod.readU16;
pub const readU24 = helpers_mod.readU24;
pub const readU32 = helpers_mod.readU32;
pub const writeExtension = helpers_mod.writeExtension;

// Re-export ClientHello types and functions for backward compatibility
pub const ClientHello = client_hello_mod.ClientHello;
pub const KeyShareEntry = client_hello_mod.KeyShareEntry;
pub const PskIdentity = client_hello_mod.PskIdentity;
pub const PreSharedKey = client_hello_mod.PreSharedKey;
pub const parseClientHello = client_hello_mod.parseClientHello;

// Re-export ServerHello functions for backward compatibility
pub const buildServerHello = server_hello_mod.buildServerHello;

// Re-export EncryptedExtensions functions for backward compatibility
pub const buildEncryptedExtensions = encrypted_extensions_mod.buildEncryptedExtensions;

// Re-export Certificate types and functions for backward compatibility
pub const ParsedCertificateMessage = certificate_mod.ParsedCertificateMessage;
pub const CertificateEntryData = certificate_mod.CertificateEntryData;
pub const parseCertificate = certificate_mod.parseCertificate;
pub const buildCertificate = certificate_mod.buildCertificate;

// Re-export CertificateVerify functions for backward compatibility
pub const buildCertificateVerify = certificate_verify_mod.buildCertificateVerify;
pub const computeCertificateVerifySignature = certificate_verify_mod.computeCertificateVerifySignature;

// Re-export Finished functions for backward compatibility
pub const buildFinished = finished_mod.buildFinished;
pub const deriveFinishedVerifyData = finished_mod.deriveFinishedVerifyData;

// NOTE: TLS 1.3 message parsing and building functions have been extracted to:
// - src/tls13/messages/core_types.zig (ExtensionType, NamedGroup, SignatureScheme, CipherSuite)
// - src/tls13/messages/helpers.zig (readU16, readU24, readU32, writeExtension)
// - src/tls13/messages/client_hello.zig (ClientHello struct and parsing)
// - src/tls13/messages/server_hello.zig (ServerHello building)
// - src/tls13/messages/encrypted_extensions.zig (EncryptedExtensions building)
// - src/tls13/messages/certificate.zig (Certificate parsing and building)
// - src/tls13/messages/certificate_verify.zig (CertificateVerify building)
// - src/tls13/messages/finished.zig (Finished building)
// All types and functions are re-exported above for backward compatibility.
// See PHASE2_COMPLETE.md for details.

