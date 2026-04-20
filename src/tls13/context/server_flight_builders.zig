// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUAL-317: server-side handshake-flight message builders.
//!
//! Pure, stateless helpers that encode the five server-flight handshake
//! messages (ServerHello, EncryptedExtensions, Certificate, CertificateVerify,
//! Finished). Each returns a newly-allocated body slice (or stack-only Secret
//! in the Finished case) owned by the caller.
//!
//! ## Architecture
//!
//! The three orchestration methods in context.zig --- `negotiateCipherAndKeys`,
//! `emitServerFlight`, `driveServerHandshakeFlight` --- touch too much mutable
//! Context state (transcripts, handshake_secret, phase, anti_replay, streams,
//! outbound queues, traffic-secret installation, markLocalFinished, …) to port
//! as pure functions without dragging that state through a state-slice wide
//! enough to defeat the point. Following the Task 5-7 precedent, they remain
//! as thin Context adapters and delegate the per-message byte encoding to the
//! five pure builders below.
//!
//! ## Security Invariants (preserved verbatim)
//!
//! - RFC 8446 §4.1.3: ServerHello structure --- legacy_version, random,
//!   legacy_session_id_echo, cipher_suite, legacy_compression_method,
//!   extensions (supported_versions, key_share, optional pre_shared_key).
//!   Delegated to `tls13_full.buildServerHello`.
//! - RFC 8446 §4.3.1: EncryptedExtensions --- ALPN (RFC 7301) when negotiated,
//!   QUIC transport_parameters (RFC 9001) when non-null. Delegated to
//!   `tls13_full.buildEncryptedExtensions`.
//! - RFC 8446 §4.4.2: Certificate --- empty context for server, single-entry
//!   leaf chain (intermediates elided on the current code path, matching
//!   previous behavior).
//! - RFC 8446 §4.4.3: CertificateVerify context-string
//!   `"TLS 1.3, server CertificateVerify"` (SEC-045 timing-sensitive signing
//!   preserved by delegating to `sig.signCertificateVerify`).
//! - RFC 8446 §4.4.4: Finished verify_data = HMAC(finished_key, transcript_hash)
//!   via `finished_mod.deriveFinishedVerifyData`.

const std = @import("std");
const tls13_full = @import("tls13_full");
const ks = @import("quic_tls");
const sig = @import("sig");
const types = @import("../types.zig");
const finished_mod = @import("../finished.zig");

const HandshakeError = types.HandshakeError;
const Secret = ks.Secret;
const Hash = ks.Hash;

/// Inputs for `buildServerHelloMsg`.
///
/// Borrowed, no ownership transferred. `session_id` is echoed per
/// RFC 8446 §4.1.3 (may be null to emit an empty session_id).
/// `selected_psk_index` is non-null iff PSK was selected during negotiation.
pub const ServerHelloInput = struct {
    cipher: tls13_full.CipherSuite,
    key_share_group: tls13_full.NamedGroup,
    server_random: [32]u8,
    server_public_key: []const u8,
    session_id: ?[]const u8,
    selected_psk_index: ?u16,
};

/// Inputs for `buildEncryptedExtensionsMsg`.
///
/// Both fields are optional --- absent extensions are not emitted.
pub const EncryptedExtensionsInput = struct {
    alpn: ?[]const u8,
    quic_transport_parameters: ?[]const u8,
};

/// Inputs for `buildCertificateVerifyMsg`.
///
/// `transcript_hash` is the transcript-hash-so-far (i.e. through Certificate)
/// computed by the caller --- it is signed directly with the TLS 1.3
/// server CertificateVerify context string.
pub const CertificateVerifyInput = struct {
    signature_scheme: tls13_full.SignatureScheme,
    private_key_der: []const u8,
    transcript_hash: Secret,
};

/// RFC 8446 §4.1.3: build ServerHello body (no handshake header).
///
/// Pure wrapper around `tls13_full.buildServerHello`; extracted for
/// unit-testability at the Context layer and to keep the pure-module boundary
/// honest. Caller owns the returned buffer.
pub fn buildServerHelloMsg(
    alloc: std.mem.Allocator,
    input: ServerHelloInput,
) ![]u8 {
    return tls13_full.buildServerHello(
        alloc,
        input.server_random,
        input.cipher,
        input.key_share_group,
        input.server_public_key,
        input.session_id,
        null, // QUIC transport_parameters go in EncryptedExtensions, not ServerHello
        input.selected_psk_index,
    );
}

/// RFC 8446 §4.3.1: build EncryptedExtensions body (no handshake header).
///
/// `input.alpn` / `input.quic_transport_parameters` are emitted only when
/// non-null. Caller owns the returned buffer.
pub fn buildEncryptedExtensionsMsg(
    alloc: std.mem.Allocator,
    input: EncryptedExtensionsInput,
) ![]u8 {
    return tls13_full.buildEncryptedExtensions(
        alloc,
        input.alpn,
        input.quic_transport_parameters,
    );
}

/// RFC 8446 §4.4.2: build server Certificate body (no handshake header).
///
/// `cert_der` is the DER-encoded leaf certificate (single-entry chain on this
/// code path; server-side does not currently emit intermediates nor stapled
/// OCSP/SCT --- matches prior inline behavior verbatim).
///
/// `psk_selected` is the nullability switch:
/// - `psk_selected == true`  ⇒ returns `null` (PSK auth skips Cert/CV).
/// - `psk_selected == false`, `cert_der == null`  ⇒ `MissingCertificate`.
/// - otherwise, returns the encoded Certificate body.
///
/// Caller owns the returned buffer (when non-null).
pub fn buildCertificateMsg(
    alloc: std.mem.Allocator,
    cert_der: ?[]const u8,
    psk_selected: bool,
) !?[]u8 {
    const leaf = cert_der orelse {
        if (!psk_selected) return HandshakeError.MissingCertificate;
        return null;
    };
    const cert_entries = [_]tls13_full.CertificateEntryData{.{ .cert = leaf }};
    return try tls13_full.buildCertificate(alloc, &[_]u8{}, &cert_entries);
}

/// RFC 8446 §4.4.3: build CertificateVerify body (no handshake header).
///
/// Computes the signature over the fixed 64-byte prefix + context string
/// `"TLS 1.3, server CertificateVerify"` + 0x00 separator + `transcript_hash`
/// per RFC 8446 §4.4.3, using the negotiated signature scheme.
///
/// Preserves SEC-045 timing-sensitive signing semantics by delegating directly
/// to `sig.signCertificateVerify`. Caller owns the returned buffer.
///
/// `allocator` is used both for the temporary signature buffer (freed before
/// return) and the final wire-format CertificateVerify body.
pub fn buildCertificateVerifyMsg(
    alloc: std.mem.Allocator,
    input: CertificateVerifyInput,
) ![]u8 {
    const sig_alg: sig.SigAlg = switch (input.signature_scheme) {
        .ecdsa_secp256r1_sha256 => .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384 => .ecdsa_secp384r1_sha384,
        .rsa_pss_rsae_sha256 => .rsa_pss_sha256,
        .ed25519 => .ed25519,
        else => return HandshakeError.UnsupportedSignatureAlgorithm,
    };

    const signature = try sig.signCertificateVerify(
        sig_alg,
        input.private_key_der,
        "TLS 1.3, server CertificateVerify",
        input.transcript_hash.slice(),
        alloc,
    );
    defer alloc.free(signature);

    return tls13_full.buildCertificateVerify(alloc, input.signature_scheme, signature);
}

/// RFC 8446 §4.4.4: compute Finished verify_data.
///
/// Pure: no allocator, no transcript mutation. The caller is expected to have
/// already finalized the transcript-hash-through-CertificateVerify and cached
/// it (Context stores it in `transcripts.finished_hash` before invoking).
///
/// `server_hs_secret` is the server-side handshake traffic secret, from which
/// the finished_key is derived internally by `finished_mod`.
pub fn buildFinishedMsg(
    hash_kind: Hash,
    server_hs_secret: *const Secret,
    transcript_hash: Secret,
) Secret {
    return finished_mod.deriveFinishedVerifyData(hash_kind, server_hs_secret, transcript_hash);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "server_flight_builders: buildServerHelloMsg emits RFC 8446 §4.1.3 structure" {
    const alloc = testing.allocator;
    var server_random: [32]u8 = undefined;
    @memset(&server_random, 0xAB);
    var server_pub: [32]u8 = undefined;
    @memset(&server_pub, 0xCD);

    const body = try buildServerHelloMsg(alloc, .{
        .cipher = .TLS_AES_128_GCM_SHA256,
        .key_share_group = .x25519,
        .server_random = server_random,
        .server_public_key = server_pub[0..],
        .session_id = null,
        .selected_psk_index = null,
    });
    defer alloc.free(body);

    // legacy_version (0x0303) + random(32) + sid_len(0) + cipher(2) + compr(1)
    try testing.expect(body.len >= 2 + 32 + 1 + 2 + 1);
    try testing.expectEqual(@as(u8, 0x03), body[0]);
    try testing.expectEqual(@as(u8, 0x03), body[1]);
    try testing.expectEqual(@as(u8, 0xAB), body[2]);
    try testing.expectEqual(@as(u8, 0xAB), body[33]);
    try testing.expectEqual(@as(u8, 0x00), body[34]); // empty session_id
}

test "server_flight_builders: buildServerHelloMsg echoes client session_id" {
    const alloc = testing.allocator;
    var server_random: [32]u8 = undefined;
    @memset(&server_random, 0);
    var server_pub: [32]u8 = undefined;
    @memset(&server_pub, 0);

    const sid = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const body = try buildServerHelloMsg(alloc, .{
        .cipher = .TLS_AES_128_GCM_SHA256,
        .key_share_group = .x25519,
        .server_random = server_random,
        .server_public_key = server_pub[0..],
        .session_id = sid[0..],
        .selected_psk_index = null,
    });
    defer alloc.free(body);

    // After legacy_version(2) + random(32), the sid_len byte must equal 4 and
    // the following 4 bytes must match our sid.
    try testing.expectEqual(@as(u8, 4), body[34]);
    try testing.expectEqualSlices(u8, sid[0..], body[35..39]);
}

test "server_flight_builders: buildServerHelloMsg PSK selected emits pre_shared_key extension" {
    const alloc = testing.allocator;
    var server_random: [32]u8 = undefined;
    @memset(&server_random, 0);
    var server_pub: [32]u8 = undefined;
    @memset(&server_pub, 0);

    const body_psk = try buildServerHelloMsg(alloc, .{
        .cipher = .TLS_AES_128_GCM_SHA256,
        .key_share_group = .x25519,
        .server_random = server_random,
        .server_public_key = server_pub[0..],
        .session_id = null,
        .selected_psk_index = 0,
    });
    defer alloc.free(body_psk);

    const body_no_psk = try buildServerHelloMsg(alloc, .{
        .cipher = .TLS_AES_128_GCM_SHA256,
        .key_share_group = .x25519,
        .server_random = server_random,
        .server_public_key = server_pub[0..],
        .session_id = null,
        .selected_psk_index = null,
    });
    defer alloc.free(body_no_psk);

    // With PSK selected, the ServerHello is strictly longer (pre_shared_key
    // extension adds the selected_identity u16 plus 4 bytes of extension
    // header).
    try testing.expect(body_psk.len > body_no_psk.len);
}

test "server_flight_builders: buildEncryptedExtensionsMsg ALPN present emits extension" {
    const alloc = testing.allocator;
    const body_with_alpn = try buildEncryptedExtensionsMsg(alloc, .{
        .alpn = "h3",
        .quic_transport_parameters = null,
    });
    defer alloc.free(body_with_alpn);

    const body_no_alpn = try buildEncryptedExtensionsMsg(alloc, .{
        .alpn = null,
        .quic_transport_parameters = null,
    });
    defer alloc.free(body_no_alpn);

    try testing.expect(body_with_alpn.len > body_no_alpn.len);
}

test "server_flight_builders: buildEncryptedExtensionsMsg QUIC transport params emitted" {
    const alloc = testing.allocator;
    const tp_bytes = [_]u8{ 0x01, 0x02, 0x03 };
    const body_with_tp = try buildEncryptedExtensionsMsg(alloc, .{
        .alpn = null,
        .quic_transport_parameters = tp_bytes[0..],
    });
    defer alloc.free(body_with_tp);

    const body_no_tp = try buildEncryptedExtensionsMsg(alloc, .{
        .alpn = null,
        .quic_transport_parameters = null,
    });
    defer alloc.free(body_no_tp);

    try testing.expect(body_with_tp.len > body_no_tp.len);
}

test "server_flight_builders: buildCertificateMsg PSK path returns null" {
    const alloc = testing.allocator;
    const result = try buildCertificateMsg(alloc, null, true);
    try testing.expectEqual(@as(?[]u8, null), result);
}

test "server_flight_builders: buildCertificateMsg non-PSK without cert errors" {
    const alloc = testing.allocator;
    try testing.expectError(
        HandshakeError.MissingCertificate,
        buildCertificateMsg(alloc, null, false),
    );
}

test "server_flight_builders: buildCertificateMsg emits empty context + single leaf" {
    const alloc = testing.allocator;
    const fake_cert = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const body = try buildCertificateMsg(alloc, fake_cert[0..], false);
    defer if (body) |b| alloc.free(b);

    try testing.expect(body != null);
    const b = body.?;
    // Certificate body = certificate_request_context(1-byte len = 0) +
    //                    certificate_list(u24 len) + entries.
    try testing.expectEqual(@as(u8, 0), b[0]); // empty server context
    // u24 list_len at bytes [1..4]
    const list_len: u32 = (@as(u32, b[1]) << 16) | (@as(u32, b[2]) << 8) | b[3];
    // One entry: u24 cert_len(3) + cert(4 bytes) + u16 ext_len(2) = 9 bytes.
    try testing.expectEqual(@as(u32, 9), list_len);
}

test "server_flight_builders: buildCertificateVerifyMsg unsupported scheme errors" {
    const alloc = testing.allocator;
    var digest: [32]u8 = undefined;
    @memset(&digest, 0);
    const hash_secret = Secret.fromSlice(.sha256, digest[0..]);

    try testing.expectError(
        HandshakeError.UnsupportedSignatureAlgorithm,
        buildCertificateVerifyMsg(alloc, .{
            .signature_scheme = .rsa_pkcs1_sha256, // not supported by our signer
            .private_key_der = &[_]u8{},
            .transcript_hash = hash_secret,
        }),
    );
}

test "server_flight_builders: buildFinishedMsg matches direct deriveFinishedVerifyData" {
    var hs_digest: [32]u8 = undefined;
    @memset(&hs_digest, 0x11);
    const hs_secret = Secret.fromSlice(.sha256, hs_digest[0..]);

    var tx_digest: [32]u8 = undefined;
    @memset(&tx_digest, 0x22);
    const tx_hash = Secret.fromSlice(.sha256, tx_digest[0..]);

    const via_builder = buildFinishedMsg(.sha256, &hs_secret, tx_hash);
    const direct = finished_mod.deriveFinishedVerifyData(.sha256, &hs_secret, tx_hash);
    try testing.expectEqualSlices(u8, direct.slice(), via_builder.slice());
}
