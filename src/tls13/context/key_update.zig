// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUAL-317: post-handshake KeyUpdate flow (RFC 8446 §4.6.3 + §7.2).
//!
//! Pure-function module — takes a current traffic secret + hash, returns the
//! rotated secret and (for the outbound path) the wire-format KeyUpdate
//! handshake message. Also exposes the AEAD-usage threshold predicate from
//! RFC 8446 §5.5.
//!
//! # Security Invariants
//!
//! 1. **secureZero on OLD secret stays in the Context shell.** This module is
//!    intentionally unable to leak the old secret: it takes a
//!    `*const ks.Secret` pointer and only reads it (to derive the successor
//!    via HKDF-Expand-Label). The *caller* owns the lifetime and MUST zeroize
//!    the old secret *before* installing the returned new secret. This module
//!    MUST NOT contain a single `secureZero` call.
//!
//! 2. **KeyUpdate does NOT update the transcript hash.** RFC 8446 §4.4.1
//!    explicitly excludes post-handshake messages from the handshake-hash
//!    transcript. This module never touches `Transcript` — the Context shell
//!    must pass `transcript_update=false` when appending the wire message.
//!
//! 3. **KU is only valid after handshake_complete.** The ordering check stays
//!    in the Context shell (this module has no notion of phase).
//!
//! # RFC References
//!
//! - RFC 8446 §4.6.3 — KeyUpdate message format (update_not_requested = 0,
//!   update_requested = 1).
//! - RFC 8446 §7.2 — application_traffic_secret_N+1 =
//!   HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "",
//!   Hash.length).
//! - RFC 8446 §5.5 — AEAD usage limits: implementations SHOULD trigger a
//!   KeyUpdate before reaching the confidentiality bound of the current cipher.

const std = @import("std");
const ks = @import("quic_tls");
const messages_mod = @import("../messages.zig");
const secrets_mod = @import("../secrets.zig");

pub const TrafficDirection = secrets_mod.TrafficDirection;
pub const KeyUpdateRequest = messages_mod.KeyUpdateRequest;

/// Output of `buildLocalKeyUpdate`.
///
/// `new_secret` is the rotated traffic secret (HKDF-Expand-Label derivation).
/// `wire_message` is a newly-allocated handshake-wrapped KeyUpdate message
/// (type + 3-byte length + 1-byte body) — the caller owns the slice and is
/// responsible for freeing it.
pub const KeyUpdateBuildResult = struct {
    new_secret: ks.Secret,
    wire_message: []u8,
};

/// Trigger a local KeyUpdate — compute the successor traffic secret and
/// produce the outbound wire message.
///
/// Pure: does not mutate any state. Allocates the returned `wire_message`
/// slice; the caller must free it.
///
/// The caller (Context shell) is responsible for:
///   1. Zeroizing the OLD secret at `current_secret` before replacing it with
///      `new_secret` in its secret store.
///   2. Appending `wire_message` to the outbound stream with
///      transcript_update=false (RFC 8446 §4.4.1 — KeyUpdate is excluded from
///      the handshake transcript).
///   3. Installing `new_secret` into the QUIC packet-protection stack via
///      its own `installTrafficSecret` path.
pub fn buildLocalKeyUpdate(
    alloc: std.mem.Allocator,
    hash: ks.Hash,
    current_secret: *const ks.Secret,
    request_peer_update: bool,
) !KeyUpdateBuildResult {
    const new_secret = ks.updateTrafficSecretHash(hash, current_secret);
    const wire_message = try messages_mod.buildKeyUpdate(alloc, request_peer_update);
    return .{
        .new_secret = new_secret,
        .wire_message = wire_message,
    };
}

/// Compute the successor traffic secret for an inbound KeyUpdate.
///
/// Pure: does not mutate `current_secret`. The returned `ks.Secret` is the
/// next-generation secret derived via HKDF-Expand-Label (RFC 8446 §7.2).
///
/// The caller (Context shell) is responsible for zeroizing the OLD secret
/// before overwriting it with the returned value.
///
/// NOTE: the `request` parameter is not consulted here — whether the peer
/// requested a reciprocal update is the caller's policy decision
/// (RFC 8446 §4.6.3 says the responder MUST send KeyUpdate with
/// `update_not_requested` to avoid infinite ping-pong). The parameter is
/// accepted so that the adapter call site remains self-documenting and so
/// future policy hooks (rate limiting, etc.) can be added here.
pub fn rotatePeerSecret(
    request: KeyUpdateRequest,
    hash: ks.Hash,
    current_secret: *const ks.Secret,
) ks.Secret {
    _ = request; // policy decision handled by caller
    return ks.updateTrafficSecretHash(hash, current_secret);
}

/// RFC 8446 §5.5 — predicate for whether the current send direction has
/// crossed the configured AEAD-usage threshold.
///
/// `threshold_percent` is the percentage of `confidentiality_limit` at which
/// an update should fire (e.g. 90 = trigger at 90 % of the hard bound).
/// Returns `false` when the inputs are nonsensical (limit == 0, percent == 0
/// or > 100) so the caller can fail-closed without propagating an error.
///
/// Arithmetic widens to u128 to prevent overflow on the `limit * percent`
/// multiplication — matching the previous inline implementation.
pub fn shouldTriggerKeyUpdate(
    encrypted_count: u64,
    confidentiality_limit: u64,
    threshold_percent: u8,
) bool {
    if (threshold_percent == 0 or threshold_percent > 100) return false;
    if (confidentiality_limit == 0) return false;
    const limit_u128: u128 = confidentiality_limit;
    const pct_u128: u128 = @as(u128, threshold_percent);
    const threshold_count: u64 = @intCast((limit_u128 * pct_u128) / 100);
    return encrypted_count >= threshold_count;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "buildLocalKeyUpdate: wire format round-trip with update_not_requested" {
    // RFC 8446 §4.6.3: KeyUpdate message is [type=24][length=0x000001][body=00].
    var secret = ks.Secret.empty();
    secret.len = 32;
    @memset(secret.bytes[0..32], 0xAB);

    const result = try buildLocalKeyUpdate(testing.allocator, .sha256, &secret, false);
    defer testing.allocator.free(result.wire_message);

    try testing.expectEqual(@as(usize, 5), result.wire_message.len);
    try testing.expectEqual(@as(u8, 0x18), result.wire_message[0]); // key_update = 24
    try testing.expectEqual(@as(u8, 0x00), result.wire_message[1]);
    try testing.expectEqual(@as(u8, 0x00), result.wire_message[2]);
    try testing.expectEqual(@as(u8, 0x01), result.wire_message[3]);
    try testing.expectEqual(@as(u8, 0x00), result.wire_message[4]); // update_not_requested
}

test "buildLocalKeyUpdate: wire format differs for update_requested" {
    var secret = ks.Secret.empty();
    secret.len = 32;
    @memset(secret.bytes[0..32], 0xCD);

    const result_not = try buildLocalKeyUpdate(testing.allocator, .sha256, &secret, false);
    defer testing.allocator.free(result_not.wire_message);
    const result_req = try buildLocalKeyUpdate(testing.allocator, .sha256, &secret, true);
    defer testing.allocator.free(result_req.wire_message);

    // Wire bodies differ only in the final (request) byte: 0x00 vs 0x01.
    try testing.expectEqualSlices(u8, result_not.wire_message[0..4], result_req.wire_message[0..4]);
    try testing.expectEqual(@as(u8, 0x00), result_not.wire_message[4]);
    try testing.expectEqual(@as(u8, 0x01), result_req.wire_message[4]);

    // Parsing round-trips through messages_mod.parseKeyUpdate.
    const req_not = try messages_mod.parseKeyUpdate(result_not.wire_message[4..5]);
    const req_yes = try messages_mod.parseKeyUpdate(result_req.wire_message[4..5]);
    try testing.expectEqual(KeyUpdateRequest.update_not_requested, req_not);
    try testing.expectEqual(KeyUpdateRequest.update_requested, req_yes);
}

test "buildLocalKeyUpdate: secret derivation matches RFC 8446 §7.2 HKDF-Expand-Label" {
    // The pure module must produce the same successor secret as a direct
    // call to ks.updateTrafficSecretHash (that helper's correctness is
    // tested independently in key_schedule.zig).
    var secret = ks.Secret.empty();
    secret.len = 32;
    for (0..32) |i| secret.bytes[i] = @intCast(i);

    const direct = ks.updateTrafficSecretHash(.sha256, &secret);
    const result = try buildLocalKeyUpdate(testing.allocator, .sha256, &secret, false);
    defer testing.allocator.free(result.wire_message);

    try testing.expectEqualSlices(u8, direct.slice(), result.new_secret.slice());
    // Successor MUST differ from predecessor (HKDF-Expand-Label is a PRF).
    try testing.expect(!std.mem.eql(u8, direct.slice(), secret.slice()));
}

test "rotatePeerSecret: matches buildLocalKeyUpdate for the same inputs" {
    // Both code paths derive the successor via the same HKDF-Expand-Label
    // step; they MUST produce byte-identical secrets for identical inputs.
    var secret = ks.Secret.empty();
    secret.len = 48;
    @memset(secret.bytes[0..48], 0x5A);

    const outbound = try buildLocalKeyUpdate(testing.allocator, .sha384, &secret, false);
    defer testing.allocator.free(outbound.wire_message);
    const inbound = rotatePeerSecret(.update_not_requested, .sha384, &secret);

    try testing.expectEqualSlices(u8, outbound.new_secret.slice(), inbound.slice());
}

test "rotatePeerSecret: ignores request flag (RFC 8446 §4.6.3 policy is caller's)" {
    // The request flag does not change the rotated secret — responding to a
    // peer request is a separate decision the caller makes.
    var secret = ks.Secret.empty();
    secret.len = 32;
    @memset(secret.bytes[0..32], 0x7E);

    const no_req = rotatePeerSecret(.update_not_requested, .sha256, &secret);
    const with_req = rotatePeerSecret(.update_requested, .sha256, &secret);
    try testing.expectEqualSlices(u8, no_req.slice(), with_req.slice());
}

test "rotatePeerSecret: hash algorithm determines secret length (empty-transcript invariant)" {
    // RFC 8446 §4.4.1: KeyUpdate is excluded from the handshake transcript
    // hash. This module's API surface enforces that by construction — the
    // rotation functions accept only `(hash, *const Secret)` with NO
    // Transcript parameter. The test below additionally pins the output
    // length to the hash digest size, confirming that derivation happens
    // against the traffic-secret alone and not against any transcript state.
    var secret_256 = ks.Secret.empty();
    secret_256.len = 32;
    @memset(secret_256.bytes[0..32], 0x11);
    var secret_384 = ks.Secret.empty();
    secret_384.len = 48;
    @memset(secret_384.bytes[0..48], 0x22);

    const out_256 = rotatePeerSecret(.update_not_requested, .sha256, &secret_256);
    const out_384 = rotatePeerSecret(.update_not_requested, .sha384, &secret_384);
    try testing.expectEqual(@as(usize, 32), out_256.slice().len);
    try testing.expectEqual(@as(usize, 48), out_384.slice().len);
}

test "buildLocalKeyUpdate: wire format is independent of hash choice" {
    // The wire message is determined solely by request_peer_update — the
    // hash algorithm governs the derived secret but not the bytes on the
    // wire. (Each call uses a properly-sized secret matching its hash to
    // respect the HKDF PRK length constraint.)
    var secret_256 = ks.Secret.empty();
    secret_256.len = 32;
    for (0..32) |i| secret_256.bytes[i] = @intCast(i);
    var secret_384 = ks.Secret.empty();
    secret_384.len = 48;
    for (0..48) |i| secret_384.bytes[i] = @intCast(i);

    const out_256 = try buildLocalKeyUpdate(testing.allocator, .sha256, &secret_256, false);
    defer testing.allocator.free(out_256.wire_message);
    const out_384 = try buildLocalKeyUpdate(testing.allocator, .sha384, &secret_384, false);
    defer testing.allocator.free(out_384.wire_message);

    // Wire messages match (hash-independent) but derived-secret lengths differ.
    try testing.expectEqualSlices(u8, out_256.wire_message, out_384.wire_message);
    try testing.expectEqual(@as(usize, 32), out_256.new_secret.slice().len);
    try testing.expectEqual(@as(usize, 48), out_384.new_secret.slice().len);
}

test "shouldTriggerKeyUpdate: boundary and below threshold" {
    // Exactly at threshold triggers; one below does not.
    try testing.expect(!shouldTriggerKeyUpdate(899, 1000, 90));
    try testing.expect(shouldTriggerKeyUpdate(900, 1000, 90));
    try testing.expect(shouldTriggerKeyUpdate(1000, 1000, 90)); // above
    try testing.expect(shouldTriggerKeyUpdate(5_000_000, 5_000_000, 100));
}

test "shouldTriggerKeyUpdate: invalid inputs fail closed" {
    // limit == 0 → never trigger
    try testing.expect(!shouldTriggerKeyUpdate(1_000_000, 0, 90));
    // percent == 0 → never trigger
    try testing.expect(!shouldTriggerKeyUpdate(900, 1000, 0));
    // percent > 100 → never trigger
    try testing.expect(!shouldTriggerKeyUpdate(900, 1000, 101));
}

test "shouldTriggerKeyUpdate: realistic AES-128-GCM 2^24 limit" {
    // RFC 8446 §5.5: AES-128-GCM confidentiality limit is 2^24.5 records,
    // implementations commonly approximate to 2^24.
    const aes_gcm_limit: u64 = 1 << 24;
    const ninety_percent: u64 = @intCast((@as(u128, aes_gcm_limit) * 90) / 100);
    try testing.expect(!shouldTriggerKeyUpdate(ninety_percent - 1, aes_gcm_limit, 90));
    try testing.expect(shouldTriggerKeyUpdate(ninety_percent, aes_gcm_limit, 90));
}
