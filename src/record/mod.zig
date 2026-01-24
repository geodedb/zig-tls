// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! TLS 1.3 Record Layer - Public API
//!
//! This module provides the public interface for TLS 1.3 record layer operations,
//! including plaintext framing and AEAD protection.
//!
//! ## Module Organization
//!
//! - **plaintext**: TLSPlaintext and TLSInnerPlaintext structures (RFC 8446 §5.1, §5.4)
//! - **aead**: AEAD cipher operations and nonce derivation (RFC 8446 §5.2, §5.3, §5.5)
//!
//! ## RFC Coverage
//!
//! - RFC 8446 §5: Record Protocol
//! - RFC 8446 §5.1: TLSPlaintext framing
//! - RFC 8446 §5.2: Record Payload Protection with AEAD
//! - RFC 8446 §5.3: Per-Record Nonce derivation
//! - RFC 8446 §5.4: TLSInnerPlaintext structure
//! - RFC 8446 §5.5: Limits on Key Usage
//! - RFC 5116: AEAD Interface
//! - RFC 9001 §5.3: QUIC Packet Protection
//!
//! ## Usage
//!
//! ```zig
//! const record = @import("record/mod.zig");
//!
//! // Plaintext operations
//! const encoded = try record.encodePlaintext(allocator, .handshake, fragment);
//! const view = try record.decodePlaintext(buffer);
//!
//! // AEAD operations
//! var cipher = try record.AeadCipher.init(.TLS_AES_128_GCM_SHA256, key, iv, null);
//! defer cipher.wipe();
//! const ciphertext = try cipher.seal(allocator, seq, aad, plaintext);
//! const plaintext2 = try cipher.open(allocator, seq, aad, ciphertext);
//! ```
//!
//! ## Backward Compatibility
//!
//! For backward compatibility, code can continue importing from `src/record.zig`,
//! which re-exports all types and functions from this modular structure.

const plaintext = @import("plaintext.zig");
const aead = @import("aead.zig");

// ============================================================================
// Plaintext Types and Functions (RFC 8446 §5.1, §5.4)
// ============================================================================

/// Legacy TLS protocol versions (RFC 8446 §5.1).
pub const LegacyVersion = plaintext.LegacyVersion;

/// Default legacy version for TLS 1.3 (0x0303 = TLS 1.2).
pub const default_legacy_version = plaintext.default_legacy_version;

/// TLS record content types (RFC 8446 §5.1).
pub const ContentType = plaintext.ContentType;

/// Maximum TLSPlaintext fragment length (2^14 bytes).
pub const max_plaintext_fragment = plaintext.max_plaintext_fragment;

/// Maximum padding length for TLSInnerPlaintext.
pub const max_inner_padding = plaintext.max_inner_padding;

/// TLS record processing errors.
pub const RecordError = plaintext.RecordError;

/// Zero-copy view over a TLSPlaintext record (RFC 8446 §5.1).
pub const PlaintextView = plaintext.PlaintextView;

/// Unpacked TLSInnerPlaintext structure (RFC 8446 §5.4).
pub const InnerPlaintext = plaintext.InnerPlaintext;

/// Encode a TLSPlaintext record from content type and fragment.
pub const encodePlaintext = plaintext.encodePlaintext;

/// Decode a TLSPlaintext record from wire format.
pub const decodePlaintext = plaintext.decodePlaintext;

/// Pack content and padding into TLSInnerPlaintext wire format.
pub const packInnerPlaintext = plaintext.packInnerPlaintext;

/// Unpack a TLSInnerPlaintext buffer to extract content, type, and padding.
pub const unpackInnerPlaintext = plaintext.unpackInnerPlaintext;

/// Parse ContentType byte value (for testing).
pub const parseContentType = plaintext.parseContentType;

/// Parse legacy version from two bytes (for testing).
pub const parseLegacyVersion = plaintext.parseLegacyVersion;

// ============================================================================
// AEAD Types and Functions (RFC 8446 §5.2, §5.3, §5.5)
// ============================================================================

/// TLS 1.3 AEAD cipher suites.
pub const CipherSuite = aead.CipherSuite;

/// AEAD usage limits for key lifetime management (RFC 8446 §5.5).
pub const AeadUsageLimits = aead.AeadUsageLimits;

/// AEAD cipher context for TLS 1.3 record protection.
pub const AeadCipher = aead.AeadCipher;

/// Derive per-record nonce by XORing base IV with sequence number (RFC 8446 §5.3).
pub const xorNonce = aead.xorNonce;
