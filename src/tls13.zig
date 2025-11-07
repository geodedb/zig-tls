//! TLS 1.3 Handshake State Machine for QUIC
//!
//! This module implements the core TLS 1.3 handshake state machine optimized for
//! QUIC transport integration (RFC 9001 §4). Unlike traditional TLS implementations
//! that use a record layer, this implementation integrates directly with QUIC's
//! CRYPTO frames, providing a minimal but complete TLS 1.3 handshake flow.
//!
//! # RFC References
//! - **RFC 8446**: TLS 1.3 core protocol (handshake, key schedule, extensions)
//! - **RFC 9001**: Using TLS to Secure QUIC (CRYPTO frames, secret installation)
//! - **RFC 9369**: QUIC v2 (updated key derivation labels)
//! - **RFC 7301**: Application-Layer Protocol Negotiation (ALPN)
//! - **RFC 5280**: X.509 certificate validation (subset)
//!
//! # Modularization Status
//!
//! **Phase 1 COMPLETE**: This file now serves as a backward-compatibility layer,
//! re-exporting types from the modularized src/tls13/ directory.
//!
//! The implementation is organized into focused modules:
//! - **tls13/config.zig**: Config struct (TLS configuration parameters)
//! - **tls13/context.zig**: Callbacks + Context (main TLS driver)
//! - **tls13/engine.zig**: Engine (legacy minimal driver)
//! - **tls13/types.zig**: Core types (Role, errors, metadata)
//! - **tls13/transcript.zig**: Transcript hash management
//! - **tls13/handshake_state.zig**: State machine, CRYPTO buffering
//! - **tls13/secrets.zig**: Traffic secret storage
//! - **tls13/finished.zig**: Finished message verification
//! - **tls13/key_derivation.zig**: Key schedule wrappers
//! - **tls13/messages.zig**: Message parsing and encoding
//!
//! For new code, prefer importing from the modular API:
//! ```zig
//! const tls13 = @import("tls13/mod.zig");
//! const Context = tls13.Context;
//! ```
//!
//! This file maintains the old import path for backward compatibility:
//! ```zig
//! const tls13 = @import("tls13");
//! const Context = tls13.Context;  // Still works!
//! ```

const std = @import("std");

// Import all modularized tls13 modules
const mod = @import("tls13/mod.zig");

// ============================================================================
// Core Types and Errors
// ============================================================================

/// TLS endpoint role (Client or Server).
pub const Role = mod.Role;

/// View of negotiated handshake metadata.
pub const HandshakeMetadata = mod.HandshakeMetadata;

/// TLS 1.3 signature scheme (RFC 8446 §4.2.3).
pub const SignatureScheme = mod.SignatureScheme;

/// API operation errors.
pub const ApiError = mod.ApiError;

/// Handshake parsing and validation errors.
pub const HandshakeError = mod.HandshakeError;

// ============================================================================
// Configuration
// ============================================================================

/// TLS 1.3 configuration parameters.
pub const Config = mod.Config;

// ============================================================================
// Callbacks and Context
// ============================================================================

/// QUIC integration callback hooks.
pub const Callbacks = mod.Callbacks;

/// Main TLS 1.3 driver for production use.
pub const Context = mod.Context;

// ============================================================================
// Engine (Legacy)
// ============================================================================

/// Legacy minimal driver for tests (being phased out).
pub const Engine = mod.Engine;

// ============================================================================
// Encryption and State Management
// ============================================================================

/// Encryption levels for QUIC integration.
pub const EncryptionLevel = mod.EncryptionLevel;

/// Handshake lifecycle phases.
pub const HandshakePhase = mod.HandshakePhase;

/// Handshake completion flags.
pub const HandshakeFlags = mod.HandshakeFlags;

/// Per-encryption-level CRYPTO buffer.
pub const CryptoBuffer = mod.CryptoBuffer;

/// CRYPTO stream container.
pub const CryptoStreams = mod.CryptoStreams;

/// ClientHello key share view.
pub const ClientHelloKeyShareView = mod.ClientHelloKeyShareView;

/// PSK identity view.
pub const ClientHelloPskIdentityView = mod.ClientHelloPskIdentityView;

/// Pre-shared key extension view.
pub const ClientHelloPreSharedKeyView = mod.ClientHelloPreSharedKeyView;

/// Immutable ClientHello view.
pub const ClientHelloView = mod.ClientHelloView;

/// ClientHello info storage (internal).
pub const ClientHelloInfo = mod.ClientHelloInfo;

/// Handshake state container.
pub const HandshakeState = mod.HandshakeState;

// ============================================================================
// Secret Management
// ============================================================================

/// Traffic direction (send/recv).
pub const TrafficDirection = mod.TrafficDirection;

/// Individual traffic secret slot.
pub const SecretSlot = mod.SecretSlot;

/// Bidirectional secret pair.
pub const BidirSecrets = mod.BidirSecrets;

/// Unified secret schedule.
pub const SecretSchedule = mod.SecretSchedule;

// ============================================================================
// Transcript Management
// ============================================================================

/// Transcript hash accumulator (RFC 8446 §4.4.1).
pub const Transcript = mod.Transcript;

/// Cache of transcript hash digests.
pub const HashDigestCache = mod.HashDigestCache;

/// Transcript set for handshake flows.
pub const TranscriptSet = mod.TranscriptSet;

// ============================================================================
// Key Derivation
// ============================================================================

/// Derive handshake traffic secrets from ECDHE (RFC 8446 §7.1).
pub const deriveHandshakeTraffic = mod.deriveHandshakeTraffic;

/// Derive application traffic secrets (RFC 8446 §7.1).
pub const deriveApplicationTraffic = mod.deriveApplicationTraffic;

/// Derive QUIC handshake keys (RFC 9001 §5.1).
pub const deriveQuicHandshakeKeys = mod.deriveQuicHandshakeKeys;

/// Derive QUIC application keys (RFC 9001 §5.1).
pub const deriveQuicAppKeys = mod.deriveQuicAppKeys;

/// Derive application secrets from ECDHE (convenience).
pub const deriveApplicationTrafficFromEcdhe = mod.deriveApplicationTrafficFromEcdhe;

/// QUIC key material.
pub const QuicKeys = mod.QuicKeys;

// ============================================================================
// Finished Message
// ============================================================================

/// Derive Finished verify_data (RFC 8446 §4.4.4).
pub const deriveFinishedVerifyData = mod.deriveFinishedVerifyData;

// ============================================================================
// Message Parsing and Encoding
// ============================================================================

/// Handshake message types.
pub const HsType = mod.HsType;

/// Parsed handshake message.
pub const HandshakeMessage = mod.HandshakeMessage;

/// Encode handshake message with framing.
pub const encodeHandshake = mod.encodeHandshake;

/// Parse one handshake message from buffer.
pub const parseHandshakeOne = mod.parseHandshakeOne;

/// Generate X25519 keypair and optional shared secret.
pub const x25519KeypairAndShared = mod.x25519KeypairAndShared;

/// Encode minimal ClientHello (testing).
pub const encodeMinimalClientHello = mod.encodeMinimalClientHello;

/// Encode minimal ServerHello (testing).
pub const encodeMinimalServerHello = mod.encodeMinimalServerHello;

/// Parse minimal Hello public key (testing).
pub const parseMinimalHelloPub = mod.parseMinimalHelloPub;

// ============================================================================
// Session Tickets (from context.zig)
// ============================================================================

/// Session ticket store.
pub const TicketStore = mod.TicketStore;

/// Session ticket entry.
pub const TicketEntry = mod.TicketEntry;

/// Session ticket entry view.
pub const TicketEntryView = mod.TicketEntryView;

// ============================================================================
// Tests
// ============================================================================

// Re-export test helpers for testing
test {
    std.testing.refAllDecls(@This());
}
