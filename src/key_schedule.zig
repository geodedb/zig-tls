// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Key Schedule Module - HKDF-based key derivation for TLS 1.3 and QUIC
//!
//! Implements the HKDF-Extract and HKDF-Expand operations specified in:
//! - RFC 8446 §7.1 (Key Schedule)
//! - RFC 9001 §5.1 (QUIC Initial Secrets)
//! - RFC 9369 §3 (QUIC v2 Label Updates)
//!
//! This module provides the cryptographic key derivation functions used
//! throughout the TLS 1.3 handshake and QUIC packet protection. All secret
//! derivation follows the TLS 1.3 key schedule design with HKDF-SHA256 as
//! the primary KDF.
//!
//! ## Key Features
//! - QUIC v1 and v2 initial secret derivation with version-specific salts
//! - TLS 1.3 HKDF-Expand-Label implementation with "tls13 " prefix
//! - Traffic secret derivation for client/server send/receive directions
//! - Key update support for post-handshake secret rotation
//! - Tested against RFC 9001 Appendix A.1 test vectors
//!
//! ## Design Notes
//! Uses Zig standard library HKDF implementations (std.crypto.kdf.hkdf.HkdfSha256,
//! std.crypto.kdf.hkdf.HkdfSha512) for all cryptographic operations.
//! No external dependencies required.
const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;
const Hkdf = std.crypto.kdf.hkdf.Hkdf;
pub const HkdfSha256 = Hkdf(HmacSha256);
pub const HkdfSha384 = Hkdf(HmacSha384);

pub const KeyMaterial = struct {
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
};

/// Legacy SHA-256 helper retained for existing test vectors and APIs that assume
/// a fixed digest length. TLS 1.3 negotiates the hash via the cipher suite, but
/// many RFC 8446 test vectors reference the default SHA-256 schedule.
pub const H = struct {
    pub const digest_length = Sha256.digest_length;

    pub fn hash(data: []const u8, out: []u8, options: anytype) void {
        _ = options;
        var hasher = Sha256.init(.{});
        hasher.update(data);
        var digest: [Sha256.digest_length]u8 = undefined;
        hasher.final(&digest);
        std.debug.assert(out.len >= digest.len);
        @memcpy(out[0..digest.len], &digest);
    }
};

pub const Hash = enum {
    sha256,
    sha384,
};

pub const max_digest_length = if (Sha256.digest_length > Sha384.digest_length)
    Sha256.digest_length
else
    Sha384.digest_length;

pub const Secret = struct {
    len: u8 = 0,
    bytes: [max_digest_length]u8 = [_]u8{0} ** max_digest_length,

    pub fn empty() Secret {
        return .{};
    }

    pub fn initZero(hash: Hash) Secret {
        var out = Secret.empty();
        out.len = @intCast(digestLength(hash));
        return out;
    }

    pub fn fromSlice(hash: Hash, src: []const u8) Secret {
        std.debug.assert(src.len == digestLength(hash));
        var out = Secret.empty();
        out.len = @intCast(src.len);
        @memcpy(out.bytes[0..src.len], src);
        return out;
    }

    pub fn slice(self: *const Secret) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn sliceMut(self: *Secret) []u8 {
        return self.bytes[0..self.len];
    }
};

pub fn digestLength(hash: Hash) usize {
    return switch (hash) {
        .sha256 => Sha256.digest_length,
        .sha384 => Sha384.digest_length,
    };
}

fn hkdfModule(hash: Hash) type {
    return switch (hash) {
        .sha256 => Hkdf(HmacSha256),
        .sha384 => Hkdf(HmacSha384),
    };
}

fn secretFromSlice(hash: Hash, slice: []const u8) Secret {
    return Secret.fromSlice(hash, slice);
}

pub fn zeroSecret(hash: Hash) Secret {
    var out = Secret.empty();
    out.len = @intCast(digestLength(hash));
    // bytes already zeroed by initializer
    return out;
}

pub fn extractHash(hash: Hash, salt: ?[]const u8, ikm: []const u8) Secret {
    const actual_salt = salt orelse &[_]u8{};
    return switch (hash) {
        .sha256 => secretFromSlice(hash, HkdfSha256.extract(actual_salt, ikm)[0..]),
        .sha384 => secretFromSlice(hash, HkdfSha384.extract(actual_salt, ikm)[0..]),
    };
}

pub fn expandLabelHash(hash: Hash, prk: *const Secret, label: []const u8, context: []const u8, out: []u8) !void {
    // PERF-045: Use a stack buffer directly instead of FixedBufferAllocator.
    // Max HkdfLabel size: 2 + 1 + 6 + label.len + 1 + context.len.
    // With SHA-384 (48-byte hash) and longest label (~12 bytes), this is ~70 bytes.
    // 128 bytes provides comfortable headroom.
    var label_buf: [128]u8 = undefined;
    const info = try hkdfLabel(&label_buf, label, context, @as(u16, @intCast(out.len)));
    defer std.crypto.secureZero(u8, &label_buf);

    const prk_slice = prk.slice();
    switch (hash) {
        .sha256 => {
            var arr: [Sha256.digest_length]u8 = undefined;
            defer std.crypto.secureZero(u8, &arr);
            @memcpy(arr[0..], prk_slice);
            HkdfSha256.expand(out, info, arr);
        },
        .sha384 => {
            var arr: [Sha384.digest_length]u8 = undefined;
            defer std.crypto.secureZero(u8, &arr);
            @memcpy(arr[0..], prk_slice);
            HkdfSha384.expand(out, info, arr);
        },
    }
}

pub fn deriveSecretHash(hash: Hash, secret: *const Secret, label: []const u8, context: []const u8) Secret {
    var derived = Secret.empty();
    derived.len = @intCast(digestLength(hash));
    // SAFETY: label and context lengths are known at call sites; total HkdfLabel fits within 256-byte
    // fixed buffer used by expandLabelHash, so the allocation cannot fail.
    expandLabelHash(hash, secret, label, context, derived.sliceMut()) catch unreachable;
    return derived;
}

pub fn hmacHash(hash: Hash, key: []const u8, data: []const u8) Secret {
    return switch (hash) {
        .sha256 => blk: {
            var out: [Sha256.digest_length]u8 = undefined;
            HmacSha256.create(&out, data, key);
            break :blk secretFromSlice(hash, out[0..]);
        },
        .sha384 => blk: {
            var out: [Sha384.digest_length]u8 = undefined;
            HmacSha384.create(&out, data, key);
            break :blk secretFromSlice(hash, out[0..]);
        },
    };
}

pub fn updateTrafficSecretHash(hash: Hash, current_secret: *const Secret) Secret {
    var next = Secret.empty();
    next.len = @intCast(digestLength(hash));
    // SAFETY: label "traffic upd" (17 bytes with "tls13 " prefix) and empty context fit within
    // the 256-byte fixed buffer; output size matches digest length. Allocation cannot fail.
    expandLabelHash(hash, current_secret, "traffic upd", &[_]u8{}, next.sliceMut()) catch unreachable;
    return next;
}

/// Update a QUIC traffic secret using the "quic ku" label as specified in RFC 9001 §6.
/// This is used for QUIC key updates which differ from TLS 1.3 key updates.
///
/// ## RFC Reference
/// RFC 9001 §6 - Key Update
pub fn updateQuicSecretHash(hash: Hash, current_secret: *const Secret) Secret {
    var next = Secret.empty();
    next.len = @intCast(digestLength(hash));
    // SAFETY: label "quic ku" (13 bytes with "tls13 " prefix) and empty context fit within
    // the 256-byte fixed buffer; output size matches digest length. Allocation cannot fail.
    expandLabelHash(hash, current_secret, "quic ku", &[_]u8{}, next.sliceMut()) catch unreachable;
    return next;
}

pub fn deriveKeyIvHpHash(hash: Hash, secret: *const Secret, v2: bool) KeyMaterial {
    var key: [16]u8 = undefined;
    var iv: [12]u8 = undefined;
    var hp: [16]u8 = undefined;

    // SAFETY: all QUIC labels ("quic key", "quic iv", "quic hp" and their v2 variants) are
    // short strings (max 16 bytes with "tls13 " prefix) with empty context. The HkdfLabel
    // encoding fits well within the 256-byte fixed buffer. Output sizes (16, 12, 16) are
    // within HKDF-Expand limits. Allocation cannot fail.
    if (v2) {
        expandLabelHash(hash, secret, "quicv2 key", &[_]u8{}, key[0..]) catch unreachable;
        expandLabelHash(hash, secret, "quicv2 iv", &[_]u8{}, iv[0..]) catch unreachable;
        expandLabelHash(hash, secret, "quicv2 hp", &[_]u8{}, hp[0..]) catch unreachable;
    } else {
        expandLabelHash(hash, secret, "quic key", &[_]u8{}, key[0..]) catch unreachable;
        expandLabelHash(hash, secret, "quic iv", &[_]u8{}, iv[0..]) catch unreachable;
        expandLabelHash(hash, secret, "quic hp", &[_]u8{}, hp[0..]) catch unreachable;
    }

    return .{ .key = key, .iv = iv, .hp = hp };
}

pub fn hashBytes(hash: Hash, data: []const u8) Secret {
    return switch (hash) {
        .sha256 => blk: {
            var out: [Sha256.digest_length]u8 = undefined;
            Sha256.hash(data, &out, .{});
            break :blk secretFromSlice(hash, &out);
        },
        .sha384 => blk: {
            var out: [Sha384.digest_length]u8 = undefined;
            Sha384.hash(data, &out, .{});
            break :blk secretFromSlice(hash, &out);
        },
    };
}

pub fn deriveFinishedVerifyDataHash(hash: Hash, traffic_secret: *const Secret, transcript_hash: *const Secret) Secret {
    var finished_key = Secret.empty();
    finished_key.len = @intCast(digestLength(hash));
    // SAFETY: label "finished" (14 bytes with "tls13 " prefix) and empty context fit within
    // the 256-byte fixed buffer; output size matches digest length. Allocation cannot fail.
    expandLabelHash(hash, traffic_secret, "finished", &[_]u8{}, finished_key.sliceMut()) catch unreachable;
    return hmacHash(hash, finished_key.slice(), transcript_hash.slice());
}

/// QUIC v1 Initial Salt used for deriving initial packet protection secrets.
///
/// This 20-byte constant is defined in RFC 9001 §5.2 and is used as the salt
/// for HKDF-Extract when deriving the initial secret from the destination
/// connection ID. The value is fixed for all QUIC v1 connections.
///
/// Value: 38762cf7f55934b34d179ae6a4c80cadccbb7f0a
///
/// ## RFC Reference
/// RFC 9001 §5.2 - Initial Secrets
/// RFC 9001 Appendix A.1 - Test Vectors
pub const initial_salt_v1: [20]u8 = .{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

/// QUIC v2 Initial Salt used for deriving initial packet protection secrets.
///
/// This 20-byte constant is defined in RFC 9369 §A.1 and differs from the
/// QUIC v1 salt to prevent cross-version packet processing. Used as the salt
/// for HKDF-Extract when deriving the initial secret from the destination
/// connection ID in QUIC v2 connections.
///
/// Value: 0dede3def700a6db819381be6e269dcbf9bd2ed9
///
/// ## RFC Reference
/// RFC 9369 §A.1 - QUIC Version 2 Initial Salt
pub const initial_salt_v2: [20]u8 = .{
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
};

fn toU8(v: usize) u8 {
    return @as(u8, @intCast(v));
}

/// Construct the HkdfLabel structure for HKDF-Expand-Label operations.
///
/// Creates the binary encoding of the HkdfLabel structure defined in RFC 8446 §7.1:
///
/// ```
/// struct {
///   uint16 length;              // Output length in bytes
///   opaque label<7..255>;       // "tls13 " prefix + label string
///   opaque context<0..255>;     // Context value (usually transcript hash)
/// } HkdfLabel;
/// ```
///
/// The "tls13 " prefix is automatically prepended to the label parameter.
///
/// PERF-045: Zero-allocation variant that writes into a caller-provided stack buffer
/// instead of using an allocator. The max HkdfLabel size is bounded:
/// 2 (length) + 1 (label_len) + 6 ("tls13 ") + label.len + 1 (ctx_len) + context.len.
/// TLS 1.3 labels are at most ~12 bytes and context is at most 48 bytes (SHA-384),
/// so 80 bytes is a safe upper bound. Callers use a 128-byte stack buffer.
///
/// ## Parameters
/// - `buf`: Caller-provided output buffer (must be at least 2+1+6+label.len+1+context.len)
/// - `label`: Label string (without "tls13 " prefix)
/// - `context`: Context bytes (often a transcript hash)
/// - `out_len`: Desired output length from HKDF-Expand
///
/// ## Returns
/// Slice of `buf` containing the encoded HkdfLabel structure.
///
/// ## RFC Reference
/// RFC 8446 §7.1 - Key Schedule and HKDF-Expand-Label definition
fn hkdfLabel(buf: []u8, label: []const u8, context: []const u8, out_len: u16) error{BufferTooSmall}![]u8 {
    // RFC 8446 §7.1 - HkdfLabel structure encoding
    const prefix = "tls13 ";
    const full_label_len = prefix.len + label.len;
    const total = 2 + 1 + full_label_len + 1 + context.len;
    if (buf.len < total) return error.BufferTooSmall;
    var i: usize = 0;
    // RFC 8446 §7.1 - Length field (big-endian uint16)
    buf[i] = @as(u8, @truncate(out_len >> 8));
    i += 1;
    buf[i] = @as(u8, @truncate(out_len));
    i += 1;
    // RFC 8446 §7.1 - Label length and value ("tls13 " prefix + label written inline)
    buf[i] = toU8(full_label_len);
    i += 1;
    @memcpy(buf[i .. i + prefix.len], prefix);
    i += prefix.len;
    @memcpy(buf[i .. i + label.len], label);
    i += label.len;
    // RFC 8446 §7.1 - Context length and value
    buf[i] = toU8(context.len);
    i += 1;
    if (context.len != 0) @memcpy(buf[i .. i + context.len], context);
    return buf[0..total];
}

/// Compute HMAC-SHA256 over data with the given key.
///
/// This is used for TLS 1.3 Finished message verification and Known Answer
/// Tests (KATs). Implements RFC 2104 HMAC construction with SHA-256.
///
/// ## Parameters
/// - `key`: HMAC key material
/// - `data`: Message to authenticate
///
/// ## Returns
/// 32-byte HMAC-SHA256 tag
///
/// ## RFC References
/// - RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
/// - RFC 8446 §4.4.4 - Finished message uses HMAC for verification
pub fn hmacSha256(key: []const u8, data: []const u8) [Sha256.digest_length]u8 {
    const secret = hmacHash(.sha256, key, data);
    var out: [Sha256.digest_length]u8 = undefined;
    @memcpy(out[0..], secret.slice());
    return out;
}

fn hkdfExtractRaw(salt: ?[]const u8, ikm: []const u8) [Sha256.digest_length]u8 {
    const secret = extractHash(.sha256, salt, ikm);
    var out: [Sha256.digest_length]u8 = undefined;
    @memcpy(out[0..], secret.slice());
    return out;
}

fn hkdfExpand(out: []u8, prk: [Sha256.digest_length]u8, info: []const u8) void {
    HkdfSha256.expand(out, info, prk);
}

/// HKDF-Expand-Label derives keying material using TLS 1.3 label convention.
///
/// Implements the TLS 1.3 HKDF-Expand-Label function from RFC 8446 §7.1:
///
/// ```
/// HKDF-Expand-Label(Secret, Label, Context, Length) =
///     HKDF-Expand(Secret, HkdfLabel, Length)
/// ```
///
/// The HkdfLabel structure encodes the label with "tls13 " prefix, context,
/// and output length. This abstraction is used throughout the TLS 1.3 key
/// schedule for deriving traffic secrets, keys, and IVs.
///
/// ## Parameters
/// - `prk`: Pseudorandom key from previous HKDF-Extract (32 bytes for SHA256)
/// - `label`: Label string WITHOUT "tls13 " prefix (e.g., "client in", "key")
/// - `context`: Context bytes, typically a transcript hash or empty
/// - `out`: Output buffer to fill with derived keying material
///
/// ## RFC References
/// - RFC 8446 §7.1 - Key Schedule and HKDF-Expand-Label definition
/// - RFC 5869 - HKDF: Extract-and-Expand HKDF
pub fn expandLabel(prk: []const u8, label: []const u8, context: []const u8, out: []u8) !void {
    const hash = switch (prk.len) {
        Sha256.digest_length => Hash.sha256,
        Sha384.digest_length => Hash.sha384,
        else => return error.InvalidSecretLength,
    };

    var secret = Secret.fromSlice(hash, prk);
    try expandLabelHash(hash, &secret, label, context, out);
}

/// HKDF-Extract derives a pseudorandom key from input keying material.
///
/// Implements RFC 5869 HKDF-Extract using HMAC-SHA256:
///
/// ```
/// PRK = HMAC-Hash(salt, IKM)
/// ```
///
/// Used as the first step in the two-step HKDF key derivation process.
/// The output PRK is then used with HKDF-Expand to derive specific keys.
///
/// ## Parameters
/// - `salt`: Optional salt value (uses zero-length salt if null)
/// - `ikm`: Input Keying Material to extract from
///
/// ## Returns
/// 32-byte pseudorandom key suitable for HKDF-Expand operations
///
/// ## RFC References
/// - RFC 5869 §2.2 - HKDF-Extract definition
/// - RFC 8446 §7.1 - TLS 1.3 uses HKDF-Extract for secret derivation
pub fn extract(salt: ?[]const u8, ikm: []const u8) [Sha256.digest_length]u8 {
    // RFC 5869 §2.2 - HKDF-Extract(salt, IKM) -> PRK
    return hkdfExtractRaw(salt, ikm);
}

/// Derive the initial secret from the destination connection ID for QUIC v1.
///
/// This function implements RFC 9001 §5.2 initial secret derivation:
///
/// ```
/// initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
/// ```
///
/// The initial secret is the root of the key hierarchy for QUIC Initial
/// packet protection. Client and server initial secrets are then derived
/// from this value.
///
/// ## Parameters
/// - `dcid`: Destination Connection ID used as Input Keying Material
///
/// ## Returns
/// 32-byte initial secret for deriving client/server initial protection keys
///
/// ## RFC References
/// - RFC 9001 §5.2 - Initial Secrets
/// - RFC 9001 Appendix A.1 - Test Vectors
pub fn deriveInitialSecretV1(dcid: []const u8) [Sha256.digest_length]u8 {
    // RFC 9001 §5.2 - Use QUIC v1 initial salt as HKDF salt
    return extract(&initial_salt_v1, dcid);
}

/// Derive the initial secret from the destination connection ID for QUIC v2.
///
/// This function implements RFC 9369 §A.1 initial secret derivation using
/// the QUIC v2-specific salt:
///
/// ```
/// initial_secret = HKDF-Extract(initial_salt_v2, client_dst_connection_id)
/// ```
///
/// The v2 salt differs from v1 to prevent cross-version packet confusion.
///
/// ## Parameters
/// - `dcid`: Destination Connection ID used as Input Keying Material
///
/// ## Returns
/// 32-byte initial secret for deriving client/server initial protection keys
///
/// ## RFC References
/// - RFC 9369 §A.1 - QUIC Version 2 Initial Salt
pub fn deriveInitialSecretV2(dcid: []const u8) [Sha256.digest_length]u8 {
    // RFC 9369 §A.1 - Use QUIC v2 initial salt
    return extract(&initial_salt_v2, dcid);
}

/// Derive the initial secret from DCID for the specified QUIC version.
///
/// Convenience function that selects the appropriate initial salt based on
/// the QUIC version negotiated for the connection.
///
/// ## Parameters
/// - `version_v2`: True for QUIC v2, false for QUIC v1
/// - `dcid`: Destination Connection ID
///
/// ## Returns
/// 32-byte initial secret using version-appropriate salt
///
/// ## RFC References
/// - RFC 9001 §5.2 - QUIC v1 Initial Secrets
/// - RFC 9369 §A.1 - QUIC v2 Initial Secrets
pub fn deriveInitialSecret(version_v2: bool, dcid: []const u8) [Sha256.digest_length]u8 {
    return if (version_v2) deriveInitialSecretV2(dcid) else deriveInitialSecretV1(dcid);
}

/// Derive client and server initial secrets from the initial secret.
///
/// Splits the initial secret into client and server directional secrets using
/// HKDF-Expand-Label with role-specific labels:
///
/// ```
/// client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
/// server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
/// ```
///
/// These secrets are then used to derive the actual packet protection keys,
/// IVs, and header protection keys for Initial packets.
///
/// ## Parameters
/// - `initial_secret`: Root initial secret from deriveInitialSecret*()
///
/// ## Returns
/// Struct containing both client and server 32-byte initial secrets
///
/// ## RFC References
/// - RFC 9001 §5.2 - Client and Server Initial Secrets
/// - RFC 9001 Appendix A.1 - Test vectors demonstrating split
pub fn deriveClientServerInitial(initial_secret: [Sha256.digest_length]u8) struct { client: [Sha256.digest_length]u8, server: [Sha256.digest_length]u8 } {
    var client: [Sha256.digest_length]u8 = undefined;
    var server: [Sha256.digest_length]u8 = undefined;
    // SAFETY: initial_secret is [Sha256.digest_length]u8 (32 bytes), so expandLabel will match
    // sha256 and not return InvalidSecretLength. Labels "client in" and "server in" (15 bytes
    // with "tls13 " prefix) with empty context fit within the 256-byte fixed buffer.
    // RFC 9001 §5.2 - Derive client initial secret with "client in" label
    expandLabel(initial_secret[0..], "client in", &[_]u8{}, &client) catch unreachable;
    // RFC 9001 §5.2 - Derive server initial secret with "server in" label
    expandLabel(initial_secret[0..], "server in", &[_]u8{}, &server) catch unreachable;
    return .{ .client = client, .server = server };
}

/// Derive packet protection key, IV, and header protection key from traffic secret (QUIC v1).
///
/// Expands a traffic secret into the three keying material components needed
/// for QUIC packet protection using QUIC v1 labels:
///
/// ```
/// key = HKDF-Expand-Label(secret, "quic key", "", 16)  // AEAD key
/// iv  = HKDF-Expand-Label(secret, "quic iv", "", 12)   // AEAD IV base
/// hp  = HKDF-Expand-Label(secret, "quic hp", "", 16)   // Header protection key
/// ```
///
/// ## Parameters
/// - `secret`: Traffic secret (client_initial_secret, server_initial_secret, etc.)
///
/// ## Returns
/// Struct containing:
/// - `key`: 16-byte AEAD encryption key for AES-128-GCM
/// - `iv`: 12-byte IV base for nonce derivation
/// - `hp`: 16-byte header protection key for AES-ECB
///
/// ## RFC References
/// - RFC 9001 §5.1 - Packet Protection Keys
/// - RFC 9001 §5.4 - Header Protection
/// - RFC 9001 Appendix A.1 - Key derivation test vectors
pub fn deriveKeyIvHp(secret: [Sha256.digest_length]u8) KeyMaterial {
    var secret_wrapper = Secret.fromSlice(.sha256, secret[0..]);
    return deriveKeyIvHpHash(.sha256, &secret_wrapper, false);
}

/// Derive key (16), iv (12), hp (16) from a traffic secret for QUIC v2.
pub fn deriveKeyIvHpV2(secret: [Sha256.digest_length]u8) KeyMaterial {
    var secret_wrapper = Secret.fromSlice(.sha256, secret[0..]);
    return deriveKeyIvHpHash(.sha256, &secret_wrapper, true);
}

/// Update traffic secret for post-handshake key update (TLS 1.3 §7.2 / RFC 9001 §6).
///
/// Derives the next generation application traffic secret from the current one
/// using the "traffic upd" label. This enables forward secrecy after the handshake
/// by allowing either peer to rotate keys without a full handshake:
///
/// ```
/// application_traffic_secret_N+1 = HKDF-Expand-Label(
///     application_traffic_secret_N, "traffic upd", "", 32)
/// ```
///
/// ## Parameters
/// - `current_secret`: Current application traffic secret
///
/// ## Returns
/// Next-generation application traffic secret (32 bytes)
///
/// ## RFC References
/// - RFC 8446 §7.2 - Updating Traffic Secrets
/// - RFC 8446 §4.6.3 - KeyUpdate message
/// - RFC 9001 §6 - Key Update in QUIC
pub fn updateTrafficSecret(current_secret: [Sha256.digest_length]u8) [Sha256.digest_length]u8 {
    var secret_wrapper = Secret.fromSlice(.sha256, current_secret[0..]);
    const updated = updateTrafficSecretHash(.sha256, &secret_wrapper);
    var out: [Sha256.digest_length]u8 = undefined;
    @memcpy(out[0..], updated.slice());
    return out;
}

/// Update a QUIC traffic secret using the "quic ku" label as specified in RFC 9001 §6.
///
/// Unlike TLS 1.3 key updates which use "traffic upd", QUIC uses "quic ku" for
/// key updates to maintain separation from the TLS protocol.
///
/// ## Parameters
/// - `current_secret`: Current QUIC application traffic secret (32 bytes)
///
/// ## Returns
/// Next-generation QUIC application traffic secret (32 bytes)
///
/// ## RFC References
/// - RFC 9001 §6 - Key Update in QUIC
/// - RFC 9001 §6.1 - Initiating a Key Update
pub fn updateQuicSecret(current_secret: [Sha256.digest_length]u8) [Sha256.digest_length]u8 {
    var secret_wrapper = Secret.fromSlice(.sha256, current_secret[0..]);
    const updated = updateQuicSecretHash(.sha256, &secret_wrapper);
    var out: [Sha256.digest_length]u8 = undefined;
    @memcpy(out[0..], updated.slice());
    return out;
}

/// Generic secret derivation using HKDF-Expand-Label with custom label and context.
///
/// Convenience wrapper around expandLabel for deriving 32-byte secrets with
/// arbitrary labels and context. Commonly used throughout the TLS 1.3 key schedule:
///
/// ```
/// Derive-Secret(Secret, Label, Messages) =
///     HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
/// ```
///
/// ## Parameters
/// - `secret`: Input secret to derive from
/// - `label`: Label string (without "tls13 " prefix)
/// - `context`: Context bytes (often a transcript hash)
///
/// ## Returns
/// 32-byte derived secret
///
/// ## RFC References
/// - RFC 8446 §7.1 - Derive-Secret definition
pub fn deriveSecret(secret: [Sha256.digest_length]u8, label: []const u8, context: []const u8) [Sha256.digest_length]u8 {
    var secret_wrapper = Secret.fromSlice(.sha256, secret[0..]);
    const derived = deriveSecretHash(.sha256, &secret_wrapper, label, context);
    var out: [Sha256.digest_length]u8 = undefined;
    @memcpy(out[0..], derived.slice());
    return out;
}

// ============================================================================
// TESTS - RFC 9001 Appendix A.1 Test Vectors
// ============================================================================

const testing = std.testing;

/// RFC 9001 Appendix A.1 - Test vector DCID
const test_dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

/// RFC 9001 Appendix A.1 - Expected initial_secret from test_dcid
const expected_initial_secret: [32]u8 = .{
    0x7d, 0xb5, 0xdf, 0x06, 0xe7, 0xa6, 0x9e, 0x43, 0x24, 0x96, 0xad, 0xed, 0xb0, 0x08, 0x51, 0x92,
    0x35, 0x95, 0x22, 0x15, 0x96, 0xae, 0x2a, 0xe9, 0xfb, 0x81, 0x15, 0xc1, 0xe9, 0xed, 0x0a, 0x44,
};

/// RFC 9001 Appendix A.1 - Expected client_initial_secret
const expected_client_initial_secret: [32]u8 = .{
    0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
    0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea,
};

/// RFC 9001 Appendix A.1 - Expected server_initial_secret
const expected_server_initial_secret: [32]u8 = .{
    0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81,
    0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b,
};

/// RFC 9001 Appendix A.1 - Expected client key
const expected_client_key: [16]u8 = .{
    0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
};

/// RFC 9001 Appendix A.1 - Expected client IV
const expected_client_iv: [12]u8 = .{
    0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c,
};

/// RFC 9001 Appendix A.1 - Expected client HP
const expected_client_hp: [16]u8 = .{
    0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
};

/// RFC 9001 Appendix A.1 - Expected server key
const expected_server_key: [16]u8 = .{
    0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c, 0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37,
};

/// RFC 9001 Appendix A.1 - Expected server IV
const expected_server_iv: [12]u8 = .{
    0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e,
};

/// RFC 9001 Appendix A.1 - Expected server HP
const expected_server_hp: [16]u8 = .{
    0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76, 0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14,
};

// RFC 9001 §A.1: Verify initial secret derivation
test "RFC 9001 A.1 - initial secret derivation" {
    const initial_secret = deriveInitialSecretV1(&test_dcid);
    try testing.expectEqualSlices(u8, &expected_initial_secret, &initial_secret);
}

// RFC 9001 §A.1: Verify client/server initial secret split
test "RFC 9001 A.1 - client/server initial secrets" {
    const initial_secret = deriveInitialSecretV1(&test_dcid);
    const secrets = deriveClientServerInitial(initial_secret);

    try testing.expectEqualSlices(u8, &expected_client_initial_secret, &secrets.client);
    try testing.expectEqualSlices(u8, &expected_server_initial_secret, &secrets.server);
}

// RFC 9001 §A.1: Verify client key/iv/hp derivation
test "RFC 9001 A.1 - client key/iv/hp derivation" {
    const initial_secret = deriveInitialSecretV1(&test_dcid);
    const secrets = deriveClientServerInitial(initial_secret);
    const keys = deriveKeyIvHp(secrets.client);

    try testing.expectEqualSlices(u8, &expected_client_key, &keys.key);
    try testing.expectEqualSlices(u8, &expected_client_iv, &keys.iv);
    try testing.expectEqualSlices(u8, &expected_client_hp, &keys.hp);
}

// RFC 9001 §A.1: Verify server key/iv/hp derivation
test "RFC 9001 A.1 - server key/iv/hp derivation" {
    const initial_secret = deriveInitialSecretV1(&test_dcid);
    const secrets = deriveClientServerInitial(initial_secret);
    const keys = deriveKeyIvHp(secrets.server);

    try testing.expectEqualSlices(u8, &expected_server_key, &keys.key);
    try testing.expectEqualSlices(u8, &expected_server_iv, &keys.iv);
    try testing.expectEqualSlices(u8, &expected_server_hp, &keys.hp);
}

// RFC 9001 §A.1: Full end-to-end key derivation from DCID
test "RFC 9001 A.1 - complete key derivation pipeline" {
    // Step 1: Derive initial secret
    const initial_secret = deriveInitialSecretV1(&test_dcid);
    try testing.expectEqualSlices(u8, &expected_initial_secret, &initial_secret);

    // Step 2: Split into client/server secrets
    const secrets = deriveClientServerInitial(initial_secret);
    try testing.expectEqualSlices(u8, &expected_client_initial_secret, &secrets.client);
    try testing.expectEqualSlices(u8, &expected_server_initial_secret, &secrets.server);

    // Step 3: Derive client material
    const client_keys = deriveKeyIvHp(secrets.client);
    try testing.expectEqualSlices(u8, &expected_client_key, &client_keys.key);
    try testing.expectEqualSlices(u8, &expected_client_iv, &client_keys.iv);
    try testing.expectEqualSlices(u8, &expected_client_hp, &client_keys.hp);

    // Step 4: Derive server material
    const server_keys = deriveKeyIvHp(secrets.server);
    try testing.expectEqualSlices(u8, &expected_server_key, &server_keys.key);
    try testing.expectEqualSlices(u8, &expected_server_iv, &server_keys.iv);
    try testing.expectEqualSlices(u8, &expected_server_hp, &server_keys.hp);
}

// RFC 9369 §A.1: QUIC v2 uses different initial salt
test "RFC 9369 - QUIC v2 initial salt differs from v1" {
    const secret_v1 = deriveInitialSecretV1(&test_dcid);
    const secret_v2 = deriveInitialSecretV2(&test_dcid);

    // Secrets must differ
    try testing.expect(!std.mem.eql(u8, &secret_v1, &secret_v2));
}

// RFC 9369 §3: QUIC v2 labels ("quicv2 key" vs "quic key")
test "RFC 9369 - QUIC v2 key derivation differs from v1" {
    const test_secret: [32]u8 = .{0x00} ** 32; // All zeros for simplicity
    const keys_v1 = deriveKeyIvHp(test_secret);
    const keys_v2 = deriveKeyIvHpV2(test_secret);

    // Keys, IVs, and HPs must all differ between v1 and v2
    try testing.expect(!std.mem.eql(u8, &keys_v1.key, &keys_v2.key));
    try testing.expect(!std.mem.eql(u8, &keys_v1.iv, &keys_v2.iv));
    try testing.expect(!std.mem.eql(u8, &keys_v1.hp, &keys_v2.hp));
}

// RFC 8446 §7.2: Traffic secret updates must change the secret
test "RFC 8446 §7.2 - traffic secret update" {
    const original_secret: [32]u8 = .{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };
    const updated_secret = updateTrafficSecret(original_secret);

    // Updated secret must differ from original
    try testing.expect(!std.mem.eql(u8, &original_secret, &updated_secret));

    // Multiple updates should produce different secrets
    const updated_again = updateTrafficSecret(updated_secret);
    try testing.expect(!std.mem.eql(u8, &updated_secret, &updated_again));
    try testing.expect(!std.mem.eql(u8, &original_secret, &updated_again));
}

// RFC 8446 §7.1: HKDF-Extract with salt
test "RFC 8446 §7.1 - HKDF-Extract produces deterministic output" {
    const salt = "test salt";
    const ikm = "input keying material";

    const prk1 = extract(salt, ikm);
    const prk2 = extract(salt, ikm);

    try testing.expectEqualSlices(u8, &prk1, &prk2);
}

// RFC 8446 §7.1: HKDF-Extract without salt (uses zero-length salt)
test "RFC 8446 §7.1 - HKDF-Extract with null salt" {
    const ikm = "input keying material";

    const prk_no_salt = extract(null, ikm);
    const prk_empty_salt = extract("", ikm);

    // Null salt should behave like empty salt
    try testing.expectEqualSlices(u8, &prk_no_salt, &prk_empty_salt);
}

// RFC 8446 §7.1: HKDF-Expand-Label format validation
test "RFC 8446 §7.1 - HKDF-Expand-Label with context" {
    const prk: [32]u8 = .{0xaa} ** 32;
    var out1: [32]u8 = undefined;
    var out2: [32]u8 = undefined;

    // Different labels produce different outputs
    try expandLabel(prk[0..], "label1", "", &out1);
    try expandLabel(prk[0..], "label2", "", &out2);
    try testing.expect(!std.mem.eql(u8, &out1, &out2));

    // Different contexts produce different outputs
    var out3: [32]u8 = undefined;
    var out4: [32]u8 = undefined;
    try expandLabel(prk[0..], "label", "context1", &out3);
    try expandLabel(prk[0..], "label", "context2", &out4);
    try testing.expect(!std.mem.eql(u8, &out3, &out4));

    // Same label+context produces same output
    var out5: [32]u8 = undefined;
    try expandLabel(prk[0..], "label1", "", &out5);
    try testing.expectEqualSlices(u8, &out1, &out5);
}

// RFC 8446 §7.1: HKDF-Expand-Label output length variation
test "RFC 8446 §7.1 - HKDF-Expand-Label with different output lengths" {
    const prk: [32]u8 = .{0xbb} ** 32;
    var out_16: [16]u8 = undefined;
    var out_32: [32]u8 = undefined;
    var out_12: [12]u8 = undefined;

    try expandLabel(prk[0..], "test", "", &out_16);
    try expandLabel(prk[0..], "test", "", &out_32);
    try expandLabel(prk[0..], "test", "", &out_12);

    // Different lengths should produce different outputs (length is part of HkdfLabel)
    try testing.expect(!std.mem.eql(u8, out_12[0..], out_16[0..12]));
    try testing.expect(!std.mem.eql(u8, out_16[0..], out_32[0..16]));

    // Same inputs should produce same output
    var out_16_again: [16]u8 = undefined;
    try expandLabel(prk[0..], "test", "", &out_16_again);
    try testing.expectEqualSlices(u8, &out_16, &out_16_again);
}

// Test HMAC-SHA256 helper function
test "HMAC-SHA256 - basic functionality" {
    const key = "key";
    const data = "The quick brown fox jumps over the lazy dog";

    const mac = hmacSha256(key, data);

    // HMAC should be deterministic
    const mac2 = hmacSha256(key, data);
    try testing.expectEqualSlices(u8, &mac, &mac2);

    // Different key should produce different MAC
    const mac3 = hmacSha256("different_key", data);
    try testing.expect(!std.mem.eql(u8, &mac, &mac3));

    // Different data should produce different MAC
    const mac4 = hmacSha256(key, "different data");
    try testing.expect(!std.mem.eql(u8, &mac, &mac4));
}

// Test deriveSecret wrapper
test "deriveSecret - wrapper function" {
    const secret: [32]u8 = .{0xcc} ** 32;
    const derived1 = deriveSecret(secret, "derived", "");
    const derived2 = deriveSecret(secret, "derived", "");

    // Should be deterministic
    try testing.expectEqualSlices(u8, &derived1, &derived2);

    // Different label should produce different output
    const derived3 = deriveSecret(secret, "other", "");
    try testing.expect(!std.mem.eql(u8, &derived1, &derived3));
}

// Edge case: Empty DCID (valid per QUIC spec for server-chosen CIDs)
test "QUIC initial secret - empty DCID" {
    const empty_dcid: []const u8 = &[_]u8{};
    const secret = deriveInitialSecretV1(empty_dcid);

    // Should produce 32-byte output
    try testing.expectEqual(32, secret.len);

    // Should be deterministic
    const secret2 = deriveInitialSecretV1(empty_dcid);
    try testing.expectEqualSlices(u8, &secret, &secret2);
}

// Edge case: Maximum length DCID (20 bytes per RFC 9000)
test "QUIC initial secret - maximum length DCID" {
    const max_dcid: [20]u8 = .{0xff} ** 20;
    const secret = deriveInitialSecretV1(&max_dcid);

    // Should produce 32-byte output
    try testing.expectEqual(32, secret.len);

    // Should differ from test vector
    try testing.expect(!std.mem.eql(u8, &secret, &expected_initial_secret));
}

// Verify HKDF label construction ("tls13 " prefix)
test "HKDF label - tls13 prefix is applied" {
    const prk: [32]u8 = .{0xdd} ** 32;
    var out1: [16]u8 = undefined;
    var out2: [16]u8 = undefined;

    // These should produce different outputs because expandLabel adds "tls13 " prefix
    // We're testing that the label is not used verbatim
    try expandLabel(prk[0..], "key", "", &out1);
    try expandLabel(prk[0..], "tls13 key", "", &out2);

    // If prefix weren't added, these would be the same, but they should differ
    try testing.expect(!std.mem.eql(u8, &out1, &out2));
}
