// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! TLS 1.3 for QUIC - Modular Implementation
//!
//! This module provides the public API for TLS 1.3 handshake functionality
//! optimized for QUIC transport integration (RFC 9001 §4).
//!
//! # Architecture Overview
//!
//! The TLS 1.3 implementation is organized into focused modules:
//!
//! - **types**: Core types (Role, HandshakeMetadata, errors)
//! - **transcript**: Transcript hash management (RFC 8446 §4.4.1)
//! - **handshake_state**: State machine and CRYPTO buffering
//! - **secrets**: Traffic secret storage and management
//! - **finished**: Finished message verification (RFC 8446 §4.4.4)
//! - **key_derivation**: TLS 1.3 key schedule wrappers (RFC 8446 §7.1)
//! - **messages**: Handshake message parsing and encoding
//!
//! # RFC References
//! - **RFC 8446**: TLS 1.3 core protocol
//! - **RFC 9001**: Using TLS to Secure QUIC
//! - **RFC 9369**: QUIC Version 2
//! - **RFC 7301**: Application-Layer Protocol Negotiation (ALPN)
//! - **RFC 5280**: X.509 certificate validation (subset)
//!
//! # Usage
//!
//! For backward compatibility, most users should import via `src/lib.zig`:
//! ```zig
//! const ztls = @import("ztls");
//! const tls13 = ztls.tls13;
//! ```
//!
//! Direct imports are also supported:
//! ```zig
//! const tls13 = @import("tls13/mod.zig");
//! const Context = tls13.Context;
//! ```

// ============================================================================
// Core Types and Errors
// ============================================================================

const types = @import("types.zig");

/// TLS endpoint role (Client or Server).
pub const Role = types.Role;

/// Transport mode for the TLS 1.3 handshake: `.quic` (default, RFC 9001 §8.2
/// mandatory transport parameters) or `.tls` (RFC 8446 plain TLS over TCP,
/// transport parameters optional/absent). See `Config.transport_mode`.
pub const TransportMode = types.TransportMode;

/// View of negotiated handshake metadata.
pub const HandshakeMetadata = types.HandshakeMetadata;

/// TLS 1.3 signature scheme (RFC 8446 §4.2.3).
pub const SignatureScheme = types.SignatureScheme;

/// Map CipherSuite to its associated hash algorithm (RFC 8446 Appendix B.4).
pub const cipherSuiteHash = types.cipherSuiteHash;

// ============================================================================
// Transcript Management
// ============================================================================

const transcript = @import("transcript.zig");

/// Transcript hash accumulator (RFC 8446 §4.4.1).
pub const Transcript = transcript.Transcript;

/// Cache of transcript hash digests.
pub const HashDigestCache = transcript.HashDigestCache;

// ============================================================================
// Handshake State Machine
// ============================================================================

const handshake_state = @import("handshake_state.zig");

/// Handshake lifecycle phases.
pub const HandshakePhase = handshake_state.HandshakePhase;

/// Handshake completion flags.
pub const HandshakeFlags = handshake_state.HandshakeFlags;

/// Encryption levels for QUIC integration.
pub const EncryptionLevel = handshake_state.EncryptionLevel;

/// Per-encryption-level CRYPTO buffer.
pub const CryptoBuffer = handshake_state.CryptoBuffer;

/// CRYPTO stream container.
pub const CryptoStreams = handshake_state.CryptoStreams;

/// ClientHello key share view.
pub const ClientHelloKeyShareView = handshake_state.ClientHelloKeyShareView;

/// PSK identity view.
pub const ClientHelloPskIdentityView = handshake_state.ClientHelloPskIdentityView;

/// Pre-shared key extension view.
pub const ClientHelloPreSharedKeyView = handshake_state.ClientHelloPreSharedKeyView;

/// Immutable ClientHello view.
pub const ClientHelloView = handshake_state.ClientHelloView;

/// ClientHello info storage (internal).
pub const ClientHelloInfo = handshake_state.ClientHelloInfo;

/// Handshake state container.
pub const HandshakeState = handshake_state.HandshakeState;

// ============================================================================
// Secret Management
// ============================================================================

const secrets = @import("secrets.zig");

/// Traffic direction (send/recv).
pub const TrafficDirection = secrets.TrafficDirection;

/// Bidirectional key generation numbers (send/recv).
pub const BidirKeyGenerations = secrets.BidirKeyGenerations;

/// Individual traffic secret slot.
pub const SecretSlot = secrets.SecretSlot;

/// Bidirectional secret pair.
pub const BidirSecrets = secrets.BidirSecrets;

/// Unified secret schedule.
pub const SecretSchedule = secrets.SecretSchedule;

// ============================================================================
// Key Derivation
// ============================================================================

const key_derivation = @import("key_derivation.zig");

/// Derive handshake traffic secrets from ECDHE (RFC 8446 §7.1).
pub const deriveHandshakeTraffic = key_derivation.deriveHandshakeTraffic;

/// Derive application traffic secrets (RFC 8446 §7.1).
pub const deriveApplicationTraffic = key_derivation.deriveApplicationTraffic;

/// Derive QUIC handshake keys (RFC 9001 §5.1).
pub const deriveQuicHandshakeKeys = key_derivation.deriveQuicHandshakeKeys;

/// Derive QUIC application keys (RFC 9001 §5.1).
pub const deriveQuicAppKeys = key_derivation.deriveQuicAppKeys;

/// Derive application secrets from ECDHE (convenience).
pub const deriveApplicationTrafficFromEcdhe = key_derivation.deriveApplicationTrafficFromEcdhe;

/// QUIC key material.
pub const QuicKeys = key_derivation.QuicKeys;

/// Derive early secret from PSK (RFC 8446 §7.1).
pub const deriveEarlySecret = key_derivation.deriveEarlySecret;

/// Derive binder key for PSK authentication (RFC 8446 §7.1).
/// Uses "ext binder" label for external PSKs, "res binder" for resumption PSKs.
pub const deriveBinderKey = key_derivation.deriveBinderKey;

/// Fixed-size secret type.
pub const Secret = key_derivation.Secret;

/// Hash algorithm type.
pub const Hash = key_derivation.Hash;

// ============================================================================
// Finished Message
// ============================================================================

const finished = @import("finished.zig");

/// Derive Finished verify_data (RFC 8446 §4.4.4).
pub const deriveFinishedVerifyData = finished.deriveFinishedVerifyData;

// ============================================================================
// Message Parsing and Encoding
// ============================================================================

const messages = @import("messages.zig");

/// Cookie extension helpers (RFC 8446 §4.2.2).
pub const cookie_mod = @import("messages/extensions/cookie.zig");

/// Handshake message types.
pub const HsType = messages.HsType;

/// Parsed handshake message.
pub const HandshakeMessage = messages.HandshakeMessage;

/// KeyUpdate request type (RFC 8446 §4.6.3).
pub const KeyUpdateRequest = messages.KeyUpdateRequest;

/// Build a KeyUpdate message (RFC 8446 §4.6.3).
pub const buildKeyUpdate = messages.buildKeyUpdate;

/// Parse a KeyUpdate message body (RFC 8446 §4.6.3).
pub const parseKeyUpdate = messages.parseKeyUpdate;

/// Build a NewSessionTicket message body (RFC 8446 §4.6.1, GAP-0132).
pub const buildNewSessionTicket = messages.buildNewSessionTicket;

/// Parse a NewSessionTicket message body (RFC 8446 §4.6.1, GAP-0132).
pub const parseNewSessionTicket = messages.parseNewSessionTicket;

/// Parameters accepted by `buildNewSessionTicket`.
pub const NewSessionTicketParams = messages.NewSessionTicketParams;

/// Result type of `parseNewSessionTicket`.
pub const ParsedNewSessionTicket = messages.ParsedNewSessionTicket;

/// Encode handshake message with framing.
pub const encodeHandshake = messages.encodeHandshake;

/// Parse one handshake message from buffer.
pub const parseHandshakeOne = messages.parseHandshakeOne;

/// Generate X25519 keypair and optional shared secret.
pub const x25519KeypairAndShared = messages.x25519KeypairAndShared;

/// Parse minimal Hello public key (testing).
pub const parseMinimalHelloPub = messages.parseMinimalHelloPub;

// ============================================================================
// HelloRetryRequest (RFC 8446 §4.1.4) — exposed for direct regression tests.
// ============================================================================

const hello_retry = @import("context/hello_retry.zig");

/// Parse a HelloRetryRequest body (RFC 8446 §4.1.4). Returns the selected
/// group + optional cookie. Rejects duplicate extensions (GAP-0144 / SEC-104
/// cross-ref) with `HandshakeError.DuplicateExtension`.
pub const parseHelloRetryRequest = hello_retry.parseHelloRetryRequest;

/// Parsed HelloRetryRequest (selected_group + optional cookie borrow).
pub const HrrParsed = hello_retry.HrrParsed;

// ============================================================================
// Configuration
// ============================================================================

const config = @import("config.zig");

/// TLS 1.3 configuration parameters.
pub const Config = config.Config;

// ============================================================================
// Context and Callbacks
// ============================================================================

const context = @import("context.zig");

/// QUIC integration callback hooks.
pub const Callbacks = context.Callbacks;

/// Main TLS 1.3 driver for production use.
pub const Context = context.Context;

/// API operation errors.
pub const ApiError = types.ApiError;

/// Handshake protocol errors.
pub const HandshakeError = types.HandshakeError;

// ============================================================================

// Re-export test helpers for testing
test {
    const std = @import("std");
    std.testing.refAllDecls(@This());
}
