// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Secret Management
//!
//! RFC 8446 §7.1: Key Schedule
//! RFC 9001 §5: Packet Protection
//!
//! This module manages TLS 1.3 traffic secrets used for QUIC packet protection.
//! It provides storage and tracking for secrets at different encryption levels
//! (Initial, Handshake, Application) with bidirectional send/recv separation.
//!
//! # Secret Lifecycle
//!
//! 1. Secrets are derived via key_derivation.zig functions
//! 2. Stored in SecretSlot with generation tracking (for key updates)
//! 3. Retrieved via SecretSchedule.slot(level, direction)
//! 4. Used to derive QUIC packet protection keys
//! 5. Cleared/zeroized when no longer needed

const ks = @import("quic_tls");
const handshake_state = @import("handshake_state.zig");

const Hash = ks.Hash;
const Secret = ks.Secret;
const EncryptionLevel = handshake_state.EncryptionLevel;

/// Traffic direction relative to the current endpoint (RFC 8446 §7.1).
///
/// Used when installing secrets to distinguish between:
/// - send: Secrets for protecting outbound traffic (encryption)
/// - recv: Secrets for processing inbound traffic (decryption)
///
/// Direction is role-dependent:
/// - Client send = Server recv (client_traffic_secret)
/// - Server send = Client recv (server_traffic_secret)
pub const TrafficDirection = enum {
    /// Outbound traffic protection (encryption, sending packets).
    send,
    /// Inbound traffic processing (decryption, receiving packets).
    recv,
};

/// Bidirectional key generation numbers for send and receive directions.
///
/// Used to track the current generation of traffic secrets in both directions,
/// which is critical for:
/// - Key update synchronization (RFC 8446 §4.6.3)
/// - AEAD usage limit tracking (RFC 8446 §5.5)
/// - Debugging and logging key rotation events
pub const BidirKeyGenerations = struct {
    /// Send direction generation number (starts at 0, increments on each key update)
    send: u32,
    /// Receive direction generation number (starts at 0, increments on each key update)
    recv: u32,
};

/// RFC 8446 §7.1–§7.5: individual traffic secret slot with epoch tracking for key updates.
///
/// Each SecretSlot stores a single traffic secret with metadata:
/// - value: The secret bytes (32 or 48 bytes depending on hash)
/// - hash: Hash algorithm (SHA-256 or SHA-384)
/// - valid: Whether secret has been derived and stored
/// - epoch: Encryption level this secret belongs to
/// - generation: Counter incremented on key updates (RFC 8446 §4.6.3)
pub const SecretSlot = struct {
    value: Secret = Secret.empty(),
    hash: Hash = .sha256,
    valid: bool = false,
    epoch: EncryptionLevel = .Initial,
    generation: u32 = 0,

    const Self = @This();

    /// Clear secret and reset to initial state (zeroize).
    pub fn clear(self: *Self) void {
        self.value = Secret.empty();
        self.hash = .sha256;
        self.valid = false;
        self.generation = 0;
        self.epoch = .Initial;
    }

    /// Store a new secret in this slot and increment generation.
    ///
    /// # Parameters
    /// - level: Encryption level (Initial/Handshake/Application)
    /// - hash: Hash algorithm matching cipher suite
    /// - secret: Traffic secret to store
    pub fn store(self: *Self, level: EncryptionLevel, hash: Hash, secret: Secret) void {
        self.value = secret;
        self.hash = hash;
        self.valid = true;
        self.epoch = level;
        self.generation += 1;
    }

    /// Get a read-only slice view of the stored secret.
    pub fn slice(self: *const Self) []const u8 {
        return self.value.slice();
    }
};

/// Bidirectional secret pair (send/recv) for a single packet number space (RFC 9001 §4.1.4).
///
/// Each encryption level has separate send and receive secrets:
/// - send: Encrypting outbound packets
/// - recv: Decrypting inbound packets
///
/// Role determines which peer's secret goes in which slot:
/// - Client: send=client_secret, recv=server_secret
/// - Server: send=server_secret, recv=client_secret
pub const BidirSecrets = struct {
    send: SecretSlot = .{},
    recv: SecretSlot = .{},

    /// Resets both send and receive secret slots to their initial state.
    pub fn reset(self: *BidirSecrets) void {
        self.send.clear();
        self.recv.clear();
    }

    /// Returns the secret slot for the specified traffic direction.
    pub fn slot(self: *BidirSecrets, dir: TrafficDirection) *SecretSlot {
        return switch (dir) {
            .send => &self.send,
            .recv => &self.recv,
        };
    }
};

/// Unified traffic secret store for Initial/Handshake/Application keys (RFC 8446 §7.1, RFC 9001 §5).
///
/// This structure maintains all traffic secrets across the TLS 1.3 handshake lifecycle:
///
/// - **initial**: QUIC initial packet protection (derived outside TLS from connection ID)
/// - **handshake**: Handshake packet protection (after ServerHello, from ECDHE)
/// - **application**: 1-RTT packet protection (after Finished, from master secret)
/// - **exporter_master**: For TLS exporters (channel bindings, etc.)
/// - **resumption_master**: For PSK-based resumption
///
/// Each level has bidirectional secrets (send/recv) except exporter/resumption masters.
pub const SecretSchedule = struct {
    initial: BidirSecrets = .{},
    handshake: BidirSecrets = .{},
    application: BidirSecrets = .{},
    exporter_master: SecretSlot = .{},
    resumption_master: SecretSlot = .{},

    /// Creates a new secret schedule with all secrets in initial state.
    pub fn init() SecretSchedule {
        return .{};
    }

    /// Resets all encryption level secrets to their initial state.
    pub fn reset(self: *SecretSchedule) void {
        self.initial.reset();
        self.handshake.reset();
        self.application.reset();
        self.exporter_master.clear();
        self.resumption_master.clear();
    }

    /// Returns the bidirectional secrets for the specified encryption level.
    pub fn pairForLevel(self: *SecretSchedule, level: EncryptionLevel) *BidirSecrets {
        return switch (level) {
            .Initial => &self.initial,
            .Handshake => &self.handshake,
            .Application => &self.application,
        };
    }

    /// Returns the secret slot for the specified encryption level and traffic direction.
    ///
    /// # Usage
    /// ```zig
    /// const send_secret = schedule.slot(.Handshake, .send);
    /// const recv_secret = schedule.slot(.Handshake, .recv);
    /// ```
    pub fn slot(self: *SecretSchedule, level: EncryptionLevel, dir: TrafficDirection) *SecretSlot {
        return self.pairForLevel(level).slot(dir);
    }
};
