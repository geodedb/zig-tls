// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUAL-317: PSK identity selection + binder transcript hashing.
//!
//! Pure module: caller constructs a PskInput, this module returns PskOutput.
//! The timing_safe comparisons on both PSK identity matching (SEC-046) and
//! PSK binder verification (RFC 8446 §4.2.11.2) live INSIDE this module and
//! are directly testable without a Context.
//!
//! Architecture note: the production codebase exposes ticket lookup via a
//! callback (`on_ticket_lookup: *const fn(*Context, []const u8) ?[]const u8`)
//! rather than a ticket store struct. This module therefore abstracts the
//! callback as a type-erased function pointer + opaque context pointer; the
//! caller in context.zig constructs a thin wrapper that restores the
//! `*Context` typing and forwards to the real callback.
//!
//! No allocator needed — the original function body allocates nothing.

const std = @import("std");
const ks = @import("quic_tls");
const backend = @import("crypto_backend");
const types = @import("../types.zig");
const key_derivation_mod = @import("../key_derivation.zig");
const handshake_state_mod = @import("../handshake_state.zig");
const messages_mod = @import("../messages.zig");
// fips-exempt: non-security — constant-time comparison primitives, not crypto algorithms.
const timing_safe = std.crypto.timing_safe;

const HandshakeError = types.HandshakeError;
const HsType = messages_mod.HsType;
pub const Hash = ks.Hash;
pub const Secret = ks.Secret;
pub const ClientHelloPskIdentityView = handshake_state_mod.ClientHelloPskIdentityView;

/// Callback that resolves a PSK identity to its secret bytes. Returns null
/// if no ticket matches the identity. The `ctx` pointer is opaque — callers
/// cast it back to their concrete type inside the shim.
pub const TicketLookupFn = *const fn (ctx: *anyopaque, identity: []const u8) ?[]const u8;

/// Inputs to `selectPsk`. All slices are borrowed; caller guarantees
/// lifetime covers the call.
pub const PskInput = struct {
    /// PSK identities advertised by client in pre_shared_key extension.
    offered_identities: []const ClientHelloPskIdentityView,
    /// HMAC binders (one per identity, same order).
    offered_binders: []const []const u8,
    /// psk_key_exchange_modes extension contents (RFC 8446 §4.2.9). MUST be
    /// present when PSK is offered; otherwise caller is expected to pass null.
    psk_key_exchange_modes: ?[]const u8,
    /// Raw ClientHello body (for computing truncated-binder transcript).
    ch_raw: []const u8,
    /// Cipher-suite-derived hash algorithm for HKDF + transcript.
    hash_kind: Hash,
    /// External (out-of-band provisioned) PSK secret, if configured.
    external_psk: ?[]const u8,
    /// Identity associated with `external_psk`.
    external_psk_identity: ?[]const u8,
    /// Type-erased ticket lookup callback (used for resumption PSKs).
    /// Caller wraps production `on_ticket_lookup` to cast `ctx` back to
    /// `*Context`. Pass null to disable resumption PSK lookup.
    ticket_lookup: ?TicketLookupFn,
    /// Opaque context pointer forwarded to `ticket_lookup`.
    ticket_lookup_ctx: ?*anyopaque,
};

/// Output of `selectPsk` — mirrors the former private `PskSelection` struct
/// inside context.zig.
pub const PskOutput = struct {
    early_secret: Secret,
    selected_index: u16,
};

/// Compute the PSK binder transcript hash per RFC 8446 §4.2.11.2.
///
/// The hash is over the concatenation of:
/// - Handshake header (4 bytes: Type + 3-byte length)
/// - Truncated ClientHello body (up to but not including binders)
///
/// We compute this incrementally to avoid allocating a buffer.
///
/// Ported verbatim from src/tls13/context.zig (pre-QUAL-317): the original
/// was already pure (no `self` references), so no renames were required.
pub fn computeBinderTranscriptHash(hash: Hash, header: *const [4]u8, truncated_body: []const u8) Secret {
    // Incremental Transcript-Hash(header || truncated_body) routed through the
    // seam's streaming Hash API (byte-identical to the prior std init/update/
    // final under -Dfips=false; validated provider under -Dfips=true).
    const alg: backend.policy.Hash = switch (hash) {
        .sha256 => .sha256,
        .sha384 => .sha384,
    };
    var hasher = backend.HashStream.init(alg) catch unreachable;
    defer hasher.deinit();
    hasher.update(header);
    hasher.update(truncated_body);
    var digest: [ks.max_digest_length]u8 = undefined;
    const n = hasher.final(digest[0..]) catch unreachable;
    return ks.Secret.fromSlice(hash, digest[0..n]);
}

/// Select a PSK identity from the ClientHello offered PSKs (RFC 8446 §4.2.11)
/// and verify its binder.
///
/// Returns null when:
///   - `offered_identities` is empty (no PSK offered)
///   - both `external_psk` is unset AND `ticket_lookup` is null (nothing to match)
///   - no offered identity matches either the external PSK or a resumption
///     ticket
///
/// Returns an error when:
///   - `psk_key_exchange_modes` is null → MissingPskKeyExchangeModes
///   - `psk_dhe_ke` (0x01) mode is not advertised → PskDheKeModeRequired
///   - the binder transcript is malformed → UnexpectedMessage
///   - the binder does not verify → DecryptError
///
/// Ported from src/tls13/context.zig:selectPsk (pre-QUAL-317) with the
/// following renames:
///   self.callbacks.on_ticket_lookup    → input.ticket_lookup (type-erased)
///   self.config.external_psk           → input.external_psk
///   self.config.external_psk_identity  → input.external_psk_identity
///   self.hash_kind                     → input.hash_kind
///   ch_view.pre_shared_key.identities  → input.offered_identities
///   ch_view.pre_shared_key.binders     → input.offered_binders
///   ch_view.psk_key_exchange_modes     → input.psk_key_exchange_modes
///   ch_view.raw                        → input.ch_raw
///
/// CRITICAL: the `timing_safe.compare` identity comparison (SEC-046)
/// and `timing_safe.eql` binder comparison (RFC 8446 §4.2.11.2)
/// are preserved verbatim. Do NOT replace them with `std.mem.eql` or similar.
pub fn selectPsk(input: PskInput) !?PskOutput {
    if (input.offered_identities.len == 0) return null;

    // If neither lookup source is configured, we cannot match anything.
    if (input.external_psk == null and input.ticket_lookup == null) return null;

    // RFC 8446 §4.2.9: Validate psk_key_exchange_modes extension is present
    // When using PSK, client MUST include psk_key_exchange_modes extension
    const psk_modes = input.psk_key_exchange_modes orelse {
        return HandshakeError.MissingPskKeyExchangeModes;
    };

    // RFC 8446 §4.2.9: Verify psk_dhe_ke (0x01) is supported
    // TLS 1.3 requires (EC)DHE with PSK for forward secrecy
    var supports_psk_dhe_ke = false;
    for (psk_modes) |mode| {
        if (mode == 0x01) { // psk_dhe_ke
            supports_psk_dhe_ke = true;
            break;
        }
    }
    if (!supports_psk_dhe_ke) {
        return HandshakeError.PskDheKeModeRequired;
    }

    // Iterate over identities
    for (input.offered_identities, 0..) |ident, idx| {
        // RFC 8446 §4.2.11.1: Validate obfuscated_ticket_age bounds
        // The ticket age should not be unreasonably large (e.g., > 7 days in milliseconds)
        // This is a basic sanity check; full validation must be done by the callback
        const max_ticket_age_ms = 7 * 24 * 60 * 60 * 1000; // 7 days
        if (ident.obfuscated_ticket_age > max_ticket_age_ms * 2) {
            // Skip this PSK if the obfuscated age is unreasonably large
            // Note: The factor of 2 accounts for obfuscation via ticket_age_add
            continue;
        }

        // RFC 8446 §4.2.11: Try external PSK config first, then fall back to ticket lookup callback.
        // External PSKs are provisioned out-of-band and use "ext binder" label.
        // Resumption PSKs come from NewSessionTicket and use "res binder" label.
        // SEC-046: Use constant-time comparison for PSK identity matching to prevent
        // timing side-channel leaks (CWE-208). Length check is non-secret.
        // SAFETY: .? unwraps below are guarded by the preceding `!= null` checks
        // in this `and`-chain; Zig evaluates `and` left-to-right with short-circuit.
        const is_external_psk = input.external_psk != null and
            input.external_psk_identity != null and
            ident.identity.len == input.external_psk_identity.?.len and
            timing_safe.compare(u8, ident.identity, input.external_psk_identity.?, .big) == .eq;
        const psk_bytes_opt: ?[]const u8 = if (is_external_psk)
            input.external_psk
        else if (input.ticket_lookup) |cb|
            cb(input.ticket_lookup_ctx.?, ident.identity)
        else
            null;
        if (psk_bytes_opt) |psk_bytes| {
            // Found a matching PSK. Now verify the binder.
            // RFC 8446 §4.2.11: Binder validation
            // NOTE: For resumption PSKs, the callback MUST have validated ticket age/lifetime before returning PSK

            // 1. Derive early secret and binder key (RFC 8446 §7.1)
            // early_secret = HKDF-Extract(0, psk)
            const early_secret = key_derivation_mod.deriveEarlySecret(input.hash_kind, psk_bytes);
            // binder_key = Derive-Secret(early_secret, "ext binder" | "res binder", "")
            // RFC 8446 §7.1: Use "ext binder" for external PSKs, "res binder" for resumption PSKs.
            const binder_key = key_derivation_mod.deriveBinderKey(input.hash_kind, &early_secret, is_external_psk);

            // 2. Calculate truncated ClientHello for binder verification (RFC 8446 §4.2.11.2)
            // The transcript for binder computation is the ClientHello truncated before the binders list.
            // Calculate binders length (each binder is 1-byte length + binder bytes)
            var binders_len: usize = 0;
            for (input.offered_binders) |b| {
                binders_len += 1 + b.len;
            }

            // Validate we have enough bytes for truncation
            // binders_len + 2 = binders list length (2 bytes) + binder entries
            if (input.ch_raw.len < binders_len + 2) return HandshakeError.UnexpectedMessage;
            const truncated_len = input.ch_raw.len - (binders_len + 2);
            const truncated_ch = input.ch_raw[0..truncated_len];

            // Check if we have a binder for this identity
            if (idx >= input.offered_binders.len) return HandshakeError.UnexpectedMessage;
            const received_binder = input.offered_binders[idx];

            // 3. Compute transcript hash for binder (RFC 8446 §4.2.11.2)
            // The transcript includes the handshake header (Type + Length) + truncated body.
            // ch_raw is just the body, so we need to prepend the header.
            var header: [4]u8 = undefined;
            header[0] = @intFromEnum(HsType.client_hello);
            header[1] = @intCast((input.ch_raw.len >> 16) & 0xFF);
            header[2] = @intCast((input.ch_raw.len >> 8) & 0xFF);
            header[3] = @intCast(input.ch_raw.len & 0xFF);

            // Compute hash of (Header + TruncatedBody)
            // For first ClientHello (no HRR), this is the entire binder transcript.
            // For ClientHello2 after HRR, we would need to include prior messages,
            // but since we handle HRR separately and this is called for the initial CH,
            // we compute the hash directly here.
            const transcript_hash = computeBinderTranscriptHash(input.hash_kind, &header, truncated_ch);

            // 4. Compute expected binder (RFC 8446 §4.2.11.2)
            // finished_key = HKDF-Expand-Label(binder_key, "finished", "", Hash.length)
            // binder = HMAC(finished_key, Transcript-Hash(Truncated ClientHello))
            const digest_len = ks.digestLength(input.hash_kind);
            var finished_key_buf: [ks.max_digest_length]u8 = undefined;
            const finished_key = finished_key_buf[0..digest_len];
            ks.expandLabelHash(input.hash_kind, &binder_key, "finished", &[_]u8{}, finished_key) catch {
                return HandshakeError.CryptoError;
            };

            const expected_binder = ks.hmacHash(input.hash_kind, finished_key, transcript_hash.slice());

            // 5. Verify binder using constant-time comparison (security critical!)
            // RFC 8446 §4.2.11.2: "Servers SHOULD check that it is valid"
            // We use constant-time comparison to prevent timing attacks.
            const expected_len = ks.digestLength(input.hash_kind);
            if (received_binder.len != expected_len or expected_binder.len != expected_len) {
                return HandshakeError.DecryptError; // Binder length mismatch
            }
            const binder_ok = switch (input.hash_kind) {
                .sha256 => blk: {
                    const received_bytes: *const [32]u8 = received_binder[0..32];
                    const expected_bytes: *const [32]u8 = expected_binder.bytes[0..32];
                    break :blk timing_safe.eql([32]u8, received_bytes.*, expected_bytes.*);
                },
                .sha384 => blk: {
                    const received_bytes: *const [48]u8 = received_binder[0..48];
                    const expected_bytes: *const [48]u8 = expected_binder.bytes[0..48];
                    break :blk timing_safe.eql([48]u8, received_bytes.*, expected_bytes.*);
                },
            };
            if (!binder_ok) {
                return HandshakeError.DecryptError; // Binder verification failed
            }

            // Binder verified successfully - PSK is authentic
            return PskOutput{
                .early_secret = early_secret,
                .selected_index = @intCast(idx),
            };
        }
    }
    return null;
}

// ------------------------------------------------------------
// Tests
// ------------------------------------------------------------

const testing = std.testing;

/// Build a minimal PskInput with no ticket sources — useful for early-exit tests.
fn makeEmptyInput() PskInput {
    return PskInput{
        .offered_identities = &.{},
        .offered_binders = &.{},
        .psk_key_exchange_modes = null,
        .ch_raw = &.{},
        .hash_kind = .sha256,
        .external_psk = null,
        .external_psk_identity = null,
        .ticket_lookup = null,
        .ticket_lookup_ctx = null,
    };
}

/// Compute a valid binder for a given external-PSK scenario. Mirrors the
/// production algorithm (deriveEarlySecret → deriveBinderKey → HKDF-Expand-Label
/// "finished" → HMAC over transcript).
fn computeExpectedBinder(
    hash: Hash,
    psk_bytes: []const u8,
    external: bool,
    ch_raw: []const u8,
    binders_len: usize,
    out_buf: *[ks.max_digest_length]u8,
) []u8 {
    const early_secret = key_derivation_mod.deriveEarlySecret(hash, psk_bytes);
    const binder_key = key_derivation_mod.deriveBinderKey(hash, &early_secret, external);

    const digest_len = ks.digestLength(hash);
    var finished_key_buf: [ks.max_digest_length]u8 = undefined;
    const finished_key = finished_key_buf[0..digest_len];
    ks.expandLabelHash(hash, &binder_key, "finished", &[_]u8{}, finished_key) catch unreachable;

    // Transcript = header || truncated_ch where truncated_ch = ch_raw[0 .. len - binders_len - 2]
    const truncated_len = ch_raw.len - (binders_len + 2);
    const truncated_ch = ch_raw[0..truncated_len];
    var header: [4]u8 = undefined;
    header[0] = @intFromEnum(HsType.client_hello);
    header[1] = @intCast((ch_raw.len >> 16) & 0xFF);
    header[2] = @intCast((ch_raw.len >> 8) & 0xFF);
    header[3] = @intCast(ch_raw.len & 0xFF);
    const transcript_hash = computeBinderTranscriptHash(hash, &header, truncated_ch);

    const expected = ks.hmacHash(hash, finished_key, transcript_hash.slice());
    @memcpy(out_buf[0..digest_len], expected.bytes[0..digest_len]);
    return out_buf[0..digest_len];
}

/// Build a synthetic ch_raw where the last `binders_len + 2` bytes are the
/// binders section and everything before is the "pre-binder" transcript.
fn makeSyntheticChRaw(pre_binder_body: []const u8, binders_len: usize, scratch: []u8) []u8 {
    std.debug.assert(scratch.len >= pre_binder_body.len + binders_len + 2);
    @memcpy(scratch[0..pre_binder_body.len], pre_binder_body);
    @memset(scratch[pre_binder_body.len .. pre_binder_body.len + binders_len + 2], 0xEE);
    return scratch[0 .. pre_binder_body.len + binders_len + 2];
}

test "psk_selection: no offered identities returns null" {
    try testing.expect(try selectPsk(makeEmptyInput()) == null);
}

test "psk_selection: no ticket source configured returns null" {
    var input = makeEmptyInput();
    const idents = [_]ClientHelloPskIdentityView{
        .{ .identity = "hello", .obfuscated_ticket_age = 0 },
    };
    const binders = [_][]const u8{&[_]u8{0} ** 32};
    input.offered_identities = &idents;
    input.offered_binders = &binders;
    try testing.expect(try selectPsk(input) == null);
}

test "psk_selection: missing psk_key_exchange_modes errors" {
    var input = makeEmptyInput();
    const idents = [_]ClientHelloPskIdentityView{
        .{ .identity = "id", .obfuscated_ticket_age = 0 },
    };
    const binders = [_][]const u8{&[_]u8{0} ** 32};
    input.offered_identities = &idents;
    input.offered_binders = &binders;
    input.external_psk = "secret";
    input.external_psk_identity = "id";
    try testing.expectError(HandshakeError.MissingPskKeyExchangeModes, selectPsk(input));
}

test "psk_selection: psk_dhe_ke mode required" {
    var input = makeEmptyInput();
    const idents = [_]ClientHelloPskIdentityView{
        .{ .identity = "id", .obfuscated_ticket_age = 0 },
    };
    const binders = [_][]const u8{&[_]u8{0} ** 32};
    input.offered_identities = &idents;
    input.offered_binders = &binders;
    input.external_psk = "secret";
    input.external_psk_identity = "id";
    // psk_ke (0x00) only — missing psk_dhe_ke (0x01)
    input.psk_key_exchange_modes = &[_]u8{0x00};
    try testing.expectError(HandshakeError.PskDheKeModeRequired, selectPsk(input));
}

test "psk_selection: excessive obfuscated ticket age skipped" {
    var input = makeEmptyInput();
    const idents = [_]ClientHelloPskIdentityView{
        .{ .identity = "id", .obfuscated_ticket_age = std.math.maxInt(u32) },
    };
    const binders = [_][]const u8{&[_]u8{0} ** 32};
    input.offered_identities = &idents;
    input.offered_binders = &binders;
    input.external_psk = "secret";
    input.external_psk_identity = "id";
    input.psk_key_exchange_modes = &[_]u8{0x01};
    // Excessive age → identity skipped → no match → null
    try testing.expect(try selectPsk(input) == null);
}

test "psk_selection: valid external PSK match returns correct index + early secret" {
    const psk_bytes = "my-external-psk-secret";
    const identity = "ext-id-001";

    const pre_binder = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04 };
    const digest_len = ks.digestLength(.sha256);
    const binders_len: usize = 1 + digest_len;

    var ch_raw_buf: [128]u8 = undefined;
    const ch_raw = makeSyntheticChRaw(&pre_binder, binders_len, &ch_raw_buf);

    var expected_binder_buf: [ks.max_digest_length]u8 = undefined;
    const valid_binder = computeExpectedBinder(.sha256, psk_bytes, true, ch_raw, binders_len, &expected_binder_buf);

    const idents = [_]ClientHelloPskIdentityView{
        .{ .identity = identity, .obfuscated_ticket_age = 0 },
    };
    const binders = [_][]const u8{valid_binder};

    const input = PskInput{
        .offered_identities = &idents,
        .offered_binders = &binders,
        .psk_key_exchange_modes = &[_]u8{0x01},
        .ch_raw = ch_raw,
        .hash_kind = .sha256,
        .external_psk = psk_bytes,
        .external_psk_identity = identity,
        .ticket_lookup = null,
        .ticket_lookup_ctx = null,
    };

    const result = (try selectPsk(input)).?;
    try testing.expectEqual(@as(u16, 0), result.selected_index);
    const expected_early = key_derivation_mod.deriveEarlySecret(.sha256, psk_bytes);
    try testing.expectEqualSlices(u8, expected_early.bytes[0..digest_len], result.early_secret.bytes[0..digest_len]);
}

test "psk_selection: binder mismatch returns DecryptError" {
    const psk_bytes = "my-external-psk-secret";
    const identity = "ext-id-001";

    const pre_binder = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const digest_len = ks.digestLength(.sha256);
    const binders_len: usize = 1 + digest_len;

    var ch_raw_buf: [128]u8 = undefined;
    const ch_raw = makeSyntheticChRaw(&pre_binder, binders_len, &ch_raw_buf);

    var expected_binder_buf: [ks.max_digest_length]u8 = undefined;
    const valid_binder = computeExpectedBinder(.sha256, psk_bytes, true, ch_raw, binders_len, &expected_binder_buf);

    // Mutate the last byte of the binder → mismatch
    var bad_binder_buf: [32]u8 = undefined;
    @memcpy(&bad_binder_buf, valid_binder[0..32]);
    bad_binder_buf[31] ^= 0x01;

    const idents = [_]ClientHelloPskIdentityView{
        .{ .identity = identity, .obfuscated_ticket_age = 0 },
    };
    const binders = [_][]const u8{&bad_binder_buf};

    const input = PskInput{
        .offered_identities = &idents,
        .offered_binders = &binders,
        .psk_key_exchange_modes = &[_]u8{0x01},
        .ch_raw = ch_raw,
        .hash_kind = .sha256,
        .external_psk = psk_bytes,
        .external_psk_identity = identity,
        .ticket_lookup = null,
        .ticket_lookup_ctx = null,
    };

    try testing.expectError(HandshakeError.DecryptError, selectPsk(input));
}

test "psk_selection: timing_safe — mutated binder with identical prefix still rejects" {
    // Security regression probe: if someone swaps timing_safe.eql for a
    // short-circuit byte comparison, a binder that matches on the first
    // N bytes but diverges at the last byte would leak timing. This test
    // ensures such a binder is still rejected.
    const psk_bytes = "my-external-psk-secret";
    const identity = "ext-id-001";

    const pre_binder = [_]u8{ 0x11, 0x22 };
    const digest_len = ks.digestLength(.sha256);
    const binders_len: usize = 1 + digest_len;

    var ch_raw_buf: [128]u8 = undefined;
    const ch_raw = makeSyntheticChRaw(&pre_binder, binders_len, &ch_raw_buf);

    var expected_binder_buf: [ks.max_digest_length]u8 = undefined;
    const valid_binder = computeExpectedBinder(.sha256, psk_bytes, true, ch_raw, binders_len, &expected_binder_buf);

    // Same first 31 bytes, flipped last byte
    var near_miss: [32]u8 = undefined;
    @memcpy(&near_miss, valid_binder[0..32]);
    near_miss[31] ^= 0xFF;

    const idents = [_]ClientHelloPskIdentityView{
        .{ .identity = identity, .obfuscated_ticket_age = 0 },
    };
    const binders = [_][]const u8{&near_miss};

    const input = PskInput{
        .offered_identities = &idents,
        .offered_binders = &binders,
        .psk_key_exchange_modes = &[_]u8{0x01},
        .ch_raw = ch_raw,
        .hash_kind = .sha256,
        .external_psk = psk_bytes,
        .external_psk_identity = identity,
        .ticket_lookup = null,
        .ticket_lookup_ctx = null,
    };

    try testing.expectError(HandshakeError.DecryptError, selectPsk(input));
}

test "psk_selection: truncated binders list errors" {
    const psk_bytes = "my-external-psk-secret";
    const identity = "ext-id-001";

    const idents = [_]ClientHelloPskIdentityView{
        .{ .identity = identity, .obfuscated_ticket_age = 0 },
    };
    const b: [32]u8 = undefined;
    const binders = [_][]const u8{&b};

    var tiny_ch_raw: [10]u8 = [_]u8{0} ** 10;

    const input = PskInput{
        .offered_identities = &idents,
        .offered_binders = &binders,
        .psk_key_exchange_modes = &[_]u8{0x01},
        .ch_raw = &tiny_ch_raw,
        .hash_kind = .sha256,
        .external_psk = psk_bytes,
        .external_psk_identity = identity,
        .ticket_lookup = null,
        .ticket_lookup_ctx = null,
    };

    try testing.expectError(HandshakeError.UnexpectedMessage, selectPsk(input));
}

test "psk_selection: multiple identities offered — second matches" {
    const psk_bytes = "my-external-psk-secret";
    const identity = "ext-id-002";

    const pre_binder = [_]u8{ 0x33, 0x44, 0x55 };
    const digest_len = ks.digestLength(.sha256);
    const binders_len: usize = 2 * (1 + digest_len);

    var ch_raw_buf: [256]u8 = undefined;
    const ch_raw = makeSyntheticChRaw(&pre_binder, binders_len, &ch_raw_buf);

    var expected_binder_buf: [ks.max_digest_length]u8 = undefined;
    const valid_binder = computeExpectedBinder(.sha256, psk_bytes, true, ch_raw, binders_len, &expected_binder_buf);

    // First identity doesn't match external_psk_identity (and no ticket_lookup) → skipped.
    // Second identity matches → binder verified.
    const idents = [_]ClientHelloPskIdentityView{
        .{ .identity = "other-id", .obfuscated_ticket_age = 0 },
        .{ .identity = identity, .obfuscated_ticket_age = 0 },
    };
    const dummy: [32]u8 = [_]u8{0} ** 32;
    const binders = [_][]const u8{ &dummy, valid_binder };

    const input = PskInput{
        .offered_identities = &idents,
        .offered_binders = &binders,
        .psk_key_exchange_modes = &[_]u8{0x01},
        .ch_raw = ch_raw,
        .hash_kind = .sha256,
        .external_psk = psk_bytes,
        .external_psk_identity = identity,
        .ticket_lookup = null,
        .ticket_lookup_ctx = null,
    };

    const result = (try selectPsk(input)).?;
    try testing.expectEqual(@as(u16, 1), result.selected_index);
}

test "psk_selection: ticket_lookup callback invoked when external PSK doesn't match" {
    const psk_bytes_resumption = "resumption-secret-bytes";
    const identity = "ticket-abc";

    const pre_binder = [_]u8{ 0x77, 0x88 };
    const digest_len = ks.digestLength(.sha256);
    const binders_len: usize = 1 + digest_len;

    var ch_raw_buf: [128]u8 = undefined;
    const ch_raw = makeSyntheticChRaw(&pre_binder, binders_len, &ch_raw_buf);

    // external=false — this is a resumption PSK
    var expected_binder_buf: [ks.max_digest_length]u8 = undefined;
    const valid_binder = computeExpectedBinder(.sha256, psk_bytes_resumption, false, ch_raw, binders_len, &expected_binder_buf);

    const Stub = struct {
        var called_with: []const u8 = &.{};
        var return_bytes: []const u8 = &.{};
        fn lookup(_: *anyopaque, id: []const u8) ?[]const u8 {
            called_with = id;
            return return_bytes;
        }
    };
    Stub.called_with = &.{};
    Stub.return_bytes = psk_bytes_resumption;

    const idents = [_]ClientHelloPskIdentityView{
        .{ .identity = identity, .obfuscated_ticket_age = 100 },
    };
    const binders = [_][]const u8{valid_binder};

    var dummy_ctx: u8 = 0;
    const input = PskInput{
        .offered_identities = &idents,
        .offered_binders = &binders,
        .psk_key_exchange_modes = &[_]u8{0x01},
        .ch_raw = ch_raw,
        .hash_kind = .sha256,
        .external_psk = null,
        .external_psk_identity = null,
        .ticket_lookup = Stub.lookup,
        .ticket_lookup_ctx = @ptrCast(&dummy_ctx),
    };

    const result = (try selectPsk(input)).?;
    try testing.expectEqual(@as(u16, 0), result.selected_index);
    try testing.expectEqualStrings(identity, Stub.called_with);
}

test "psk_selection: ticket_lookup returns null — no match returns null" {
    const Stub = struct {
        fn lookup(_: *anyopaque, _: []const u8) ?[]const u8 {
            return null;
        }
    };

    const idents = [_]ClientHelloPskIdentityView{
        .{ .identity = "unknown", .obfuscated_ticket_age = 100 },
    };
    const binders = [_][]const u8{&[_]u8{0} ** 32};

    var dummy_ctx: u8 = 0;
    const input = PskInput{
        .offered_identities = &idents,
        .offered_binders = &binders,
        .psk_key_exchange_modes = &[_]u8{0x01},
        .ch_raw = &[_]u8{0} ** 64,
        .hash_kind = .sha256,
        .external_psk = null,
        .external_psk_identity = null,
        .ticket_lookup = Stub.lookup,
        .ticket_lookup_ctx = @ptrCast(&dummy_ctx),
    };

    try testing.expect(try selectPsk(input) == null);
}

test "psk_selection: computeBinderTranscriptHash sha256 deterministic" {
    // Deterministic spot-check: same input → same output, no hidden state.
    const header = [4]u8{ 0x01, 0x00, 0x00, 0x10 };
    const body = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE } ** 2;
    const a = computeBinderTranscriptHash(.sha256, &header, &body);
    const b = computeBinderTranscriptHash(.sha256, &header, &body);
    try testing.expectEqualSlices(u8, a.bytes[0..32], b.bytes[0..32]);

    // Changing any input byte changes output
    var body2 = body;
    body2[0] ^= 0x01;
    const c = computeBinderTranscriptHash(.sha256, &header, &body2);
    try testing.expect(!std.mem.eql(u8, a.bytes[0..32], c.bytes[0..32]));
}

test "psk_selection: computeBinderTranscriptHash sha384 deterministic" {
    const header = [4]u8{ 0x01, 0x00, 0x00, 0x20 };
    const body = [_]u8{ 0x11, 0x22, 0x33, 0x44 } ** 8;
    const a = computeBinderTranscriptHash(.sha384, &header, &body);
    const b = computeBinderTranscriptHash(.sha384, &header, &body);
    try testing.expectEqualSlices(u8, a.bytes[0..48], b.bytes[0..48]);
}
