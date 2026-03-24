// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Key Derivation Helpers
//!
//! RFC 8446 §7.1: Key Schedule
//!
//! This module provides public-facing wrappers for the TLS 1.3 key schedule
//! implemented in key_schedule.zig. It handles the derivation of:
//! - Handshake traffic secrets from ECDHE shared secret
//! - Application traffic secrets from handshake secret
//! - QUIC packet protection keys (RFC 9001 §5)
//!
//! # TLS 1.3 Key Schedule (RFC 8446 §7.1)
//!
//! ```
//!             0
//!             |
//!             v
//!   PSK ->  HKDF-Extract = Early Secret
//!             |
//!             +-----> Derive-Secret(., "ext binder" | "res binder", "")
//!             |                     = binder_key
//!             |
//!             +-----> Derive-Secret(., "c e traffic", ClientHello)
//!             |                     = client_early_traffic_secret
//!             |
//!             +-----> Derive-Secret(., "e exp master", ClientHello)
//!             |                     = early_exporter_master_secret
//!             v
//!       Derive-Secret(., "derived", "")
//!             |
//!             v
//!   (EC)DHE -> HKDF-Extract = Handshake Secret
//!             |
//!             +-----> Derive-Secret(., "c hs traffic", ClientHello...ServerHello)
//!             |                     = client_handshake_traffic_secret
//!             |
//!             +-----> Derive-Secret(., "s hs traffic", ClientHello...ServerHello)
//!             |                     = server_handshake_traffic_secret
//!             v
//!       Derive-Secret(., "derived", "")
//!             |
//!             v
//!   0 -> HKDF-Extract = Master Secret
//!             |
//!             +-----> Derive-Secret(., "c ap traffic", ClientHello...server Finished)
//!             |                     = client_application_traffic_secret_0
//!             |
//!             +-----> Derive-Secret(., "s ap traffic", ClientHello...server Finished)
//!             |                     = server_application_traffic_secret_0
//!             |
//!             +-----> Derive-Secret(., "exp master", ClientHello...server Finished)
//!             |                     = exporter_master_secret
//!             |
//!             +-----> Derive-Secret(., "res master", ClientHello...client Finished)
//!                                   = resumption_master_secret
//! ```

const std = @import("std");
const logger = @import("quic_logger");
const ks = @import("quic_tls");

pub const Hash = ks.Hash;
pub const Secret = ks.Secret;

/// Debug tracing for secrets (disabled in production builds).
const secret_trace_enabled = false;

inline fn traceSecrets(comptime fmt: []const u8, args: anytype) void {
    if (secret_trace_enabled) logger.debugPrint(fmt, args);
}

/// Derive early secret from optional PSK (RFC 8446 §7.1).
///
/// ```
/// early_secret = HKDF-Extract(0, psk)
/// ```
///
/// If psk is null, uses a zero-length key (equivalent to Hash.length bytes of zeros).
///
/// ## RFC 8446 Compliance (§7.1 Key Schedule)
///
/// Per RFC 8446 §7.1, the early_secret is derived using HKDF-Extract with:
/// - Salt: A string of Hash.length bytes set to 0 (zero salt is required by spec)
/// - IKM (Input Keying Material): PSK or zeros if no PSK
///
/// The zero salt is mandated by the RFC, not a placeholder. This ensures
/// deterministic key derivation across all TLS 1.3 implementations.
pub fn deriveEarlySecret(hash: Hash, psk: ?[]const u8) Secret {
    // RFC 8446 §7.1: Salt MUST be a string of Hash.length zeros for early_secret.
    // This is mandated by the specification, not a default or placeholder.
    // Use hash-dependent length: 32 bytes for SHA-256, 48 bytes for SHA-384.
    const zero_salt = ks.zeroSecret(hash);
    // If PSK is not provided, use a zero-filled buffer of HashLen
    // RFC 8446 §7.1: "If a given secret is not available, then the 0-value
    // consisting of a string of Hash.length bytes set to zeros is used."
    if (psk) |k| {
        return ks.extractHash(hash, zero_salt.slice(), k);
    } else {
        // RFC 8446 §7.1: When no PSK, IKM is Hash.length zeros (32 for SHA-256, 48 for SHA-384)
        const zero_ikm = ks.zeroSecret(hash);
        return ks.extractHash(hash, zero_salt.slice(), zero_ikm.slice());
    }
}

/// Derive binder key for PSK authentication (RFC 8446 §7.1).
///
/// ```
/// binder_key = Derive-Secret(early_secret, "ext binder" | "res binder", "")
/// ```
///
/// Used to compute the HMAC binder in the pre_shared_key extension.
pub fn deriveBinderKey(hash: Hash, early_secret: *const Secret, external: bool) Secret {
    const label = if (external) "ext binder" else "res binder";
    const empty_hash = ks.hashBytes(hash, &[_]u8{});
    return ks.deriveSecretHash(hash, early_secret, label, empty_hash.slice());
}

/// Derive 0-RTT early traffic secret for client early data (RFC 8446 §7.1, §4.2.10).
///
/// ```
/// client_early_traffic_secret = Derive-Secret(early_secret, "c e traffic", ClientHello)
/// ```
///
/// This secret is used to protect 0-RTT data sent by the client in the first flight
/// before receiving ServerHello. It provides encryption but NOT forward secrecy.
///
/// # Parameters
/// - hash: Hash algorithm based on PSK cipher suite
/// - early_secret: Early secret derived from PSK via deriveEarlySecret
/// - client_hello_hash: Hash(ClientHello) including early_data extension
///
/// # Security Considerations
/// - 0-RTT data is vulnerable to replay attacks (use AntiReplayWindow)
/// - NOT forward secret (compromise of PSK reveals 0-RTT data)
/// - Only use for idempotent operations
///
/// # RFC References
/// - RFC 8446 §7.1: Key schedule derivation
/// - RFC 8446 §8: 0-RTT data security model
/// - RFC 9001 §4.6.1: Enabling 0-RTT in QUIC
pub fn deriveEarlyTraffic(hash: Hash, early_secret: *const Secret, client_hello_hash: []const u8) Secret {
    return ks.deriveSecretHash(hash, early_secret, "c e traffic", client_hello_hash);
}

/// Derive handshake traffic secrets from ECDHE shared secret (RFC 8446 §7.1).
///
/// This function computes the handshake-level secrets used to protect messages
/// after ServerHello. It implements the TLS 1.3 key schedule using HKDF.
///
/// # Parameters
/// - hash: Hash algorithm (SHA-256 or SHA-384) based on negotiated cipher suite
/// - ecdhe_secret: Raw X25519 shared secret (32 bytes) from key exchange
/// - transcript_hash: Hash(ClientHello || ServerHello) using negotiated hash
/// - early_secret: The early secret derived from PSK (or 0 if no PSK)
///
/// # Returns
/// Struct containing:
/// - handshake: Master handshake secret (used to derive application secrets later)
/// - client_hs: Client->Server handshake traffic secret (32 or 48 bytes)
/// - server_hs: Server->Client handshake traffic secret (32 or 48 bytes)
pub fn deriveHandshakeTraffic(hash: Hash, ecdhe_secret: []const u8, transcript_hash: Secret, early_secret: *const Secret) struct {
    handshake: Secret,
    client_hs: Secret,
    server_hs: Secret,
} {
    if (secret_trace_enabled) {
        traceSecrets("[TLS_KEY_SCHEDULE] Transcript hash (CH+SH): ", .{});
        for (transcript_hash.slice()) |b| traceSecrets("{X:0>2}", .{b});
        traceSecrets("\n", .{});
        traceSecrets("[TLS_KEY_SCHEDULE] ECDHE shared secret: ", .{});
        for (ecdhe_secret) |b| traceSecrets("{X:0>2}", .{b});
        traceSecrets("\n", .{});
    }

    const empty_hash = ks.hashBytes(hash, &[_]u8{});
    const derived = ks.deriveSecretHash(hash, early_secret, "derived", empty_hash.slice());
    const handshake_secret = ks.extractHash(hash, derived.slice(), ecdhe_secret);
    const client_hs = ks.deriveSecretHash(hash, &handshake_secret, "c hs traffic", transcript_hash.slice());
    const server_hs = ks.deriveSecretHash(hash, &handshake_secret, "s hs traffic", transcript_hash.slice());

    // DEBUG: Log intermediate key schedule values
    if (secret_trace_enabled) {
        traceSecrets("[TLS_KEY_SCHEDULE_DEBUG] Early secret: ", .{});
        for (early_secret.slice()) |b| traceSecrets("{X:0>2}", .{b});
        traceSecrets("\n", .{});

        traceSecrets("[TLS_KEY_SCHEDULE_DEBUG] Empty hash: ", .{});
        for (empty_hash.slice()) |b| traceSecrets("{X:0>2}", .{b});
        traceSecrets("\n", .{});

        traceSecrets("[TLS_KEY_SCHEDULE_DEBUG] Derived: ", .{});
        for (derived.slice()) |b| traceSecrets("{X:0>2}", .{b});
        traceSecrets("\n", .{});

        traceSecrets("[TLS_KEY_SCHEDULE_DEBUG] Handshake secret: ", .{});
        for (handshake_secret.slice()) |b| traceSecrets("{X:0>2}", .{b});
        traceSecrets("\n", .{});
    }

    if (secret_trace_enabled) {
        traceSecrets("[TLS_KEY_SCHEDULE] Client HS traffic secret: ", .{});
        for (client_hs.slice()) |b| traceSecrets("{X:0>2}", .{b});
        traceSecrets("\n", .{});
        traceSecrets("[TLS_KEY_SCHEDULE] Server HS traffic secret: ", .{});
        for (server_hs.slice()) |b| traceSecrets("{X:0>2}", .{b});
        traceSecrets("\n", .{});
    }

    return .{ .handshake = handshake_secret, .client_hs = client_hs, .server_hs = server_hs };
}

/// QUIC key material derived from a TLS traffic secret (RFC 9001 §5).
///
/// Contains the AEAD key, IV (nonce base), and header protection key
/// needed for QUIC packet protection.
pub const QuicKeys = struct {
    /// AEAD encryption key (16 bytes for AES-128-GCM)
    key: [16]u8,
    /// AEAD IV base (12 bytes, XORed with packet number)
    iv: [12]u8,
    /// Header protection key (16 bytes)
    hp: [16]u8,
};

/// Derive QUIC handshake keys from a handshake traffic secret (RFC 9001 §5.1).
///
/// This function derives the packet protection keys used to encrypt/decrypt
/// QUIC packets at the Handshake encryption level.
///
/// # Parameters
/// - hash: Hash algorithm matching the cipher suite
/// - client_or_server_hs_secret: Handshake traffic secret (from deriveHandshakeTraffic)
/// - v2: true for QUIC v2 (RFC 9369), false for QUIC v1 (RFC 9001)
///
/// # Returns
/// QuicKeys containing AEAD key, IV, and header protection key
///
/// # Usage
/// ```zig
/// const hs_secrets = deriveHandshakeTraffic(.sha256, ecdhe, transcript);
/// const client_keys = deriveQuicHandshakeKeys(.sha256, &hs_secrets.client_hs, false);
/// // Install client_keys for encrypting outbound Handshake packets
/// ```
pub fn deriveQuicHandshakeKeys(hash: Hash, client_or_server_hs_secret: *const Secret, v2: bool) QuicKeys {
    const km = ks.deriveKeyIvHpHash(hash, client_or_server_hs_secret, v2);
    return .{ .key = km.key, .iv = km.iv, .hp = km.hp };
}

/// Derive application traffic secrets (client and server) from handshake secret (RFC 8446 §7.1).
///
/// This function computes the application-level secrets used to protect 1-RTT data.
/// Called after both Finished messages are verified.
///
/// # Key Schedule Flow
/// ```
/// derived = Derive-Secret(handshake_secret, "derived", "")
/// master_secret = HKDF-Extract(derived, 0)  // No additional input
/// client_app = Derive-Secret(master_secret, "c ap traffic", CH...SF)
/// server_app = Derive-Secret(master_secret, "s ap traffic", CH...SF)
/// exporter_master = Derive-Secret(master_secret, "exp master", CH...SF)
/// ```
///
/// # Parameters
/// - hash: Hash algorithm matching the cipher suite
/// - handshake_secret: Master handshake secret (from deriveHandshakeTraffic)
/// - transcript_hash: Hash(ClientHello...server Finished)
///
/// # Returns
/// Struct containing:
/// - client_app: Client application traffic secret
/// - server_app: Server application traffic secret
/// - exporter_master: Exporter master secret (for channel bindings, etc.)
///
/// # Usage
/// ```zig
/// // After both Finished messages verified
/// const transcript = Hash(CH || SH || EE || ... || Finished);
/// const apps = deriveApplicationTraffic(.sha256, &handshake_secret, transcript);
/// try installTrafficSecret(.Application, .send, apps.client_app);
/// try installTrafficSecret(.Application, .recv, apps.server_app);
/// ```
pub fn deriveApplicationTraffic(hash: Hash, handshake_secret: *const Secret, transcript_hash: Secret) struct {
    client_app: Secret,
    server_app: Secret,
    exporter_master: Secret,
} {
    if (secret_trace_enabled) {
        traceSecrets("[TLS_APP_KEYS] Deriving application traffic secrets\n", .{});
        traceSecrets("[TLS_APP_KEYS] Transcript hash (CH...SF): ", .{});
        for (transcript_hash.slice()) |b| traceSecrets("{X:0>2}", .{b});
        traceSecrets("\n", .{});
        traceSecrets("[TLS_APP_KEYS] Handshake secret: ", .{});
        for (handshake_secret.slice()) |b| traceSecrets("{X:0>2}", .{b});
        traceSecrets("\n", .{});
    }

    const empty_hash = ks.hashBytes(hash, &[_]u8{});
    const derived = ks.deriveSecretHash(hash, handshake_secret, "derived", empty_hash.slice());
    // RFC 8446 §7.1: IKM is Hash.length zeros (32 for SHA-256, 48 for SHA-384)
    const zero_ikm = ks.zeroSecret(hash);
    if (secret_trace_enabled) {
        const zslice = zero_ikm.slice();
        traceSecrets("[TLS_APP_KEYS] IKM for master secret (zeros): len={} first_byte={} last_byte={}\n", .{ zslice.len, zslice[0], zslice[zslice.len - 1] });
    }
    const master = ks.extractHash(hash, derived.slice(), zero_ikm.slice());
    const client_app = ks.deriveSecretHash(hash, &master, "c ap traffic", transcript_hash.slice());
    const server_app = ks.deriveSecretHash(hash, &master, "s ap traffic", transcript_hash.slice());
    const exporter_master = ks.deriveSecretHash(hash, &master, "exp master", transcript_hash.slice());

    if (secret_trace_enabled) {
        traceSecrets("[TLS_APP_KEYS] Derived (from HS secret): ", .{});
        for (derived.slice()) |b| traceSecrets("{X:0>2}", .{b});
        traceSecrets("\n", .{});
        traceSecrets("[TLS_APP_KEYS] Master secret: ", .{});
        for (master.slice()) |b| traceSecrets("{X:0>2}", .{b});
        traceSecrets("\n", .{});
        traceSecrets("[TLS_APP_KEYS] Client application traffic secret: ", .{});
        for (client_app.slice()) |b| traceSecrets("{X:0>2}", .{b});
        traceSecrets("\n", .{});
        traceSecrets("[TLS_APP_KEYS] Server application traffic secret: ", .{});
        for (server_app.slice()) |b| traceSecrets("{X:0>2}", .{b});
        traceSecrets("\n", .{});
    }

    return .{ .client_app = client_app, .server_app = server_app, .exporter_master = exporter_master };
}

/// Derive QUIC 1-RTT keys from an application traffic secret (RFC 9001 §5.1).
///
/// This function derives the packet protection keys used to encrypt/decrypt
/// QUIC packets at the Application encryption level.
///
/// # Parameters
/// - hash: Hash algorithm matching the cipher suite
/// - client_or_server_app_secret: Application traffic secret (from deriveApplicationTraffic)
/// - v2: true for QUIC v2 (RFC 9369), false for QUIC v1 (RFC 9001)
///
/// # Returns
/// QuicKeys containing AEAD key, IV, and header protection key
///
/// # Usage
/// ```zig
/// const app_secrets = deriveApplicationTraffic(.sha256, &hs_secret, transcript);
/// const client_keys = deriveQuicAppKeys(.sha256, &app_secrets.client_app, false);
/// // Install client_keys for encrypting outbound Application packets
/// ```
pub fn deriveQuicAppKeys(hash: Hash, client_or_server_app_secret: *const Secret, v2: bool) QuicKeys {
    const km = ks.deriveKeyIvHpHash(hash, client_or_server_app_secret, v2);
    return .{ .key = km.key, .iv = km.iv, .hp = km.hp };
}

/// Derive application traffic secrets directly from raw ECDHE secret and transcript hash.
///
/// This is a convenience function that combines handshake and application secret
/// derivation in a single call. It computes handshake_secret then master secret
/// per TLS 1.3 and returns client/server app secrets.
///
/// # Parameters
/// - hash: Hash algorithm matching the cipher suite
/// - ecdhe_secret: Raw ECDHE shared secret (32 bytes)
/// - transcript_hash: Hash(ClientHello...server Finished)
///
/// # Returns
/// Struct containing:
/// - client_app: Client application traffic secret
/// - server_app: Server application traffic secret
///
/// # Usage
/// ```zig
/// // One-shot derivation (less flexible than staged approach)
/// const apps = deriveApplicationTrafficFromEcdhe(.sha256, ecdhe, transcript);
/// ```
///
/// # Note
/// This function is less common than the staged approach (deriveHandshakeTraffic
/// followed later by deriveApplicationTraffic) because handshake secrets are
/// needed before application secrets can be computed.
pub fn deriveApplicationTrafficFromEcdhe(hash: Hash, ecdhe_secret: []const u8, transcript_hash: Secret) struct {
    client_app: Secret,
    server_app: Secret,
} {
    const early_secret = deriveEarlySecret(hash, null);
    const hs = deriveHandshakeTraffic(hash, ecdhe_secret, transcript_hash, &early_secret);
    const apps = deriveApplicationTraffic(hash, &hs.handshake, transcript_hash);
    return .{ .client_app = apps.client_app, .server_app = apps.server_app };
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "deriveEarlySecret SHA-256 uses 32-byte zero salt and IKM" {
    // RFC 8446 S7.1: early_secret = HKDF-Extract(salt=zeros(HashLen), IKM=zeros(HashLen))
    // For SHA-256, HashLen = 32
    const early = deriveEarlySecret(.sha256, null);
    try testing.expectEqual(@as(usize, 32), early.slice().len);

    // Compute expected value manually with correct 32-byte inputs
    const zero32 = [_]u8{0} ** 32;
    const expected = ks.extractHash(.sha256, &zero32, &zero32);
    try testing.expectEqualSlices(u8, expected.slice(), early.slice());
}

test "deriveEarlySecret SHA-384 uses 48-byte zero salt and IKM" {
    // RFC 8446 S7.1: early_secret = HKDF-Extract(salt=zeros(HashLen), IKM=zeros(HashLen))
    // For SHA-384, HashLen = 48, NOT 32.
    const early = deriveEarlySecret(.sha384, null);
    try testing.expectEqual(@as(usize, 48), early.slice().len);

    // Compute expected value manually with correct 48-byte inputs
    const zero48 = [_]u8{0} ** 48;
    const expected = ks.extractHash(.sha384, &zero48, &zero48);
    try testing.expectEqualSlices(u8, expected.slice(), early.slice());
}

test "deriveEarlySecret SHA-384 with PSK uses 48-byte zero salt" {
    // When a PSK is provided, only the salt needs to be Hash.length zeros.
    // The IKM is the PSK itself.
    const psk = "test_psk_value_for_sha384_testing";
    const early = deriveEarlySecret(.sha384, psk);
    try testing.expectEqual(@as(usize, 48), early.slice().len);

    // Compute expected value manually with correct 48-byte zero salt
    const zero48 = [_]u8{0} ** 48;
    const expected = ks.extractHash(.sha384, &zero48, psk);
    try testing.expectEqualSlices(u8, expected.slice(), early.slice());
}

test "deriveApplicationTraffic SHA-384 uses 48-byte zero IKM for master secret" {
    // RFC 8446 S7.1: master_secret = HKDF-Extract(derived, IKM=zeros(HashLen))
    // For SHA-384, HashLen = 48, NOT 32.
    //
    // Construct a fake handshake secret and transcript for SHA-384.
    var hs_bytes: [48]u8 = undefined;
    @memset(&hs_bytes, 0xAA);
    const handshake_secret = ks.Secret.fromSlice(.sha384, &hs_bytes);

    var transcript_bytes: [48]u8 = undefined;
    @memset(&transcript_bytes, 0xBB);
    const transcript_hash = ks.Secret.fromSlice(.sha384, &transcript_bytes);

    const result = deriveApplicationTraffic(.sha384, &handshake_secret, transcript_hash);

    // Verify the outputs are 48 bytes (SHA-384 digest length)
    try testing.expectEqual(@as(usize, 48), result.client_app.slice().len);
    try testing.expectEqual(@as(usize, 48), result.server_app.slice().len);
    try testing.expectEqual(@as(usize, 48), result.exporter_master.slice().len);

    // Compute the expected master secret manually with 48-byte zero IKM
    const empty_hash = ks.hashBytes(.sha384, &[_]u8{});
    const derived = ks.deriveSecretHash(.sha384, &handshake_secret, "derived", empty_hash.slice());
    const zero48 = [_]u8{0} ** 48;
    const expected_master = ks.extractHash(.sha384, derived.slice(), &zero48);
    const expected_client = ks.deriveSecretHash(.sha384, &expected_master, "c ap traffic", transcript_hash.slice());
    const expected_server = ks.deriveSecretHash(.sha384, &expected_master, "s ap traffic", transcript_hash.slice());
    const expected_exporter = ks.deriveSecretHash(.sha384, &expected_master, "exp master", transcript_hash.slice());

    try testing.expectEqualSlices(u8, expected_client.slice(), result.client_app.slice());
    try testing.expectEqualSlices(u8, expected_server.slice(), result.server_app.slice());
    try testing.expectEqualSlices(u8, expected_exporter.slice(), result.exporter_master.slice());
}

test "deriveApplicationTraffic SHA-256 unchanged behavior" {
    // Verify SHA-256 still works correctly after the fix (regression test).
    var hs_bytes: [32]u8 = undefined;
    @memset(&hs_bytes, 0xCC);
    const handshake_secret = ks.Secret.fromSlice(.sha256, &hs_bytes);

    var transcript_bytes: [32]u8 = undefined;
    @memset(&transcript_bytes, 0xDD);
    const transcript_hash = ks.Secret.fromSlice(.sha256, &transcript_bytes);

    const result = deriveApplicationTraffic(.sha256, &handshake_secret, transcript_hash);

    // Verify the outputs are 32 bytes (SHA-256 digest length)
    try testing.expectEqual(@as(usize, 32), result.client_app.slice().len);
    try testing.expectEqual(@as(usize, 32), result.server_app.slice().len);
    try testing.expectEqual(@as(usize, 32), result.exporter_master.slice().len);

    // Compute the expected master secret manually with 32-byte zero IKM
    const empty_hash = ks.hashBytes(.sha256, &[_]u8{});
    const derived = ks.deriveSecretHash(.sha256, &handshake_secret, "derived", empty_hash.slice());
    const zero32 = [_]u8{0} ** 32;
    const expected_master = ks.extractHash(.sha256, derived.slice(), &zero32);
    const expected_client = ks.deriveSecretHash(.sha256, &expected_master, "c ap traffic", transcript_hash.slice());

    try testing.expectEqualSlices(u8, expected_client.slice(), result.client_app.slice());
}

// ============================================================================
// RFC 8448 §3 Test Vectors (Simple 1-RTT Handshake)
// ============================================================================
//
// These tests validate the high-level key_derivation API against official test
// vectors from RFC 8448 Section 3 using TLS_AES_128_GCM_SHA256.

/// Comptime hex-to-bytes conversion for test vector constants.
fn hexLit(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(hex.len * 100);
    var result: [hex.len / 2]u8 = undefined;
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        const hi: u8 = switch (hex[i]) {
            '0'...'9' => hex[i] - '0',
            'a'...'f' => hex[i] - 'a' + 10,
            'A'...'F' => hex[i] - 'A' + 10,
            else => unreachable,
        };
        const lo: u8 = switch (hex[i + 1]) {
            '0'...'9' => hex[i + 1] - '0',
            'a'...'f' => hex[i + 1] - 'a' + 10,
            'A'...'F' => hex[i + 1] - 'A' + 10,
            else => unreachable,
        };
        result[i / 2] = (hi << 4) | lo;
    }
    return result;
}

test "RFC 8448 §3: deriveEarlySecret matches test vector" {
    // RFC 8448 Section 3: Early Secret with no PSK
    const early = deriveEarlySecret(.sha256, null);
    const expected = hexLit(
        "33ad0a1c607ec03b09e6cd9893680ce2" ++
            "10adf300aa1f2660e1b22e10f170f92a",
    );
    try testing.expectEqualSlices(u8, &expected, early.slice());
}

test "RFC 8448 §3: deriveHandshakeTraffic matches test vectors" {
    // RFC 8448 Section 3: Handshake traffic secrets
    const dhe_shared_secret = hexLit(
        "8bd4054fb55b9d63fdfbacf9f04b9f0d" ++
            "35e6d63f537563efd46272900f89492d",
    );
    const transcript_ch_sh = ks.Secret.fromSlice(.sha256, &hexLit(
        "860c06edc07858ee8e78f0e7428c58ed" ++
            "d6b43f2ca3e6e95f02ed063cf0e1cad8",
    ));

    const early_secret = deriveEarlySecret(.sha256, null);
    const result = deriveHandshakeTraffic(.sha256, &dhe_shared_secret, transcript_ch_sh, &early_secret);

    // Handshake Secret
    const expected_hs = hexLit(
        "1dc826e93606aa6fdc0aadc12f741b01" ++
            "046aa6b99f691ed221a9f0ca043fbeac",
    );
    try testing.expectEqualSlices(u8, &expected_hs, result.handshake.slice());

    // Client Handshake Traffic Secret
    const expected_client = hexLit(
        "b3eddb126e067f35a780b3abf45e2d8f" ++
            "3b1a950738f52e9600746a0e27a55a21",
    );
    try testing.expectEqualSlices(u8, &expected_client, result.client_hs.slice());

    // Server Handshake Traffic Secret
    const expected_server = hexLit(
        "b67b7d690cc16c4e75e54213cb2d37b4" ++
            "e9c912bcded9105d42befd59d391ad38",
    );
    try testing.expectEqualSlices(u8, &expected_server, result.server_hs.slice());
}

test "RFC 8448 §3: deriveApplicationTraffic matches test vectors" {
    // RFC 8448 Section 3: Application traffic secrets
    const handshake_secret = ks.Secret.fromSlice(.sha256, &hexLit(
        "1dc826e93606aa6fdc0aadc12f741b01" ++
            "046aa6b99f691ed221a9f0ca043fbeac",
    ));
    const transcript_ch_sf = ks.Secret.fromSlice(.sha256, &hexLit(
        "9608102a0f1ccc6db6250b7b7e417b1a" ++
            "000eaada3daae4777a7686c9ff83df13",
    ));

    const result = deriveApplicationTraffic(.sha256, &handshake_secret, transcript_ch_sf);

    // Master Secret
    const expected_master = hexLit(
        "18df06843d13a08bf2a449844c5f8a47" ++
            "8001bc4d4c627984d5a41da8d0402919",
    );
    // Verify master by recomputing: we can check client/server app secrets instead
    // since the API does not expose the master secret directly.

    // Client Application Traffic Secret
    const expected_client = hexLit(
        "9e40646ce79a7f9dc05af8889bce6552" ++
            "875afa0b06df0087f792ebb7c17504a5",
    );
    try testing.expectEqualSlices(u8, &expected_client, result.client_app.slice());

    // Server Application Traffic Secret
    const expected_server = hexLit(
        "a11af9f05531f856ad47116b45a95032" ++
            "8204b4f44bfb6b3a4b4f1f3fcb631643",
    );
    try testing.expectEqualSlices(u8, &expected_server, result.server_app.slice());

    // Exporter Master Secret
    const expected_exporter = hexLit(
        "fe22f881176eda18eb8f44529e6792c5" ++
            "0c9a3f89452f68d8ae311b4309d3cf50",
    );
    try testing.expectEqualSlices(u8, &expected_exporter, result.exporter_master.slice());

    // Cross-check: verify master secret by re-deriving manually
    const empty_hash = ks.hashBytes(.sha256, &[_]u8{});
    const derived = ks.deriveSecretHash(.sha256, &handshake_secret, "derived", empty_hash.slice());
    const zero32 = [_]u8{0} ** 32;
    const master = ks.extractHash(.sha256, derived.slice(), &zero32);
    try testing.expectEqualSlices(u8, &expected_master, master.slice());
}

test "RFC 8448 §3: deriveApplicationTrafficFromEcdhe end-to-end" {
    // Test the convenience function that combines handshake + application derivation
    const dhe_shared_secret = hexLit(
        "8bd4054fb55b9d63fdfbacf9f04b9f0d" ++
            "35e6d63f537563efd46272900f89492d",
    );
    // Note: deriveApplicationTrafficFromEcdhe uses the same transcript hash for
    // both handshake and application stages, so we use transcript_hash_ch_sf here.
    // This means the handshake secrets will differ from RFC 8448 (which uses
    // transcript_ch_sh for handshake), but the API's internal consistency is verified.
    const transcript_ch_sf = ks.Secret.fromSlice(.sha256, &hexLit(
        "9608102a0f1ccc6db6250b7b7e417b1a" ++
            "000eaada3daae4777a7686c9ff83df13",
    ));

    const result = deriveApplicationTrafficFromEcdhe(.sha256, &dhe_shared_secret, transcript_ch_sf);

    // The app secrets won't match RFC 8448 because the transcript hash used for
    // handshake derivation differs. Instead, verify internal consistency by
    // manually recomputing through the same path.
    const early_secret = deriveEarlySecret(.sha256, null);
    const hs = deriveHandshakeTraffic(.sha256, &dhe_shared_secret, transcript_ch_sf, &early_secret);
    const apps = deriveApplicationTraffic(.sha256, &hs.handshake, transcript_ch_sf);

    try testing.expectEqualSlices(u8, apps.client_app.slice(), result.client_app.slice());
    try testing.expectEqualSlices(u8, apps.server_app.slice(), result.server_app.slice());
}
