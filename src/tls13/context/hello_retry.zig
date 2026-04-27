// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUAL-317: HelloRetryRequest — server emit + client handle + CH2 rebuild.
//!
//! Per RFC 8446 §4.1.4 (HRR semantics) + §4.4.1 (transcript transformation).
//!
//! ## Architecture
//!
//! The HRR flow touches many Context-owned pieces of mutable state
//! (`client_priv`, `client_pub`, `client_random`, `hrr_received`, `hrr_sent`,
//! `streams`, `transcripts`, `server_secret_generated`, …) which makes a
//! fully-pure single-call refactor impractical. Following the Task 5-6
//! precedent, this module exposes the *algorithmic* pieces as pure functions
//! and Context keeps thin adapters that glue those pieces to its state:
//!
//! - `parseHelloRetryRequest` — byte parsing of the HRR body (no allocator).
//! - `applyHrrTranscript`    — transcript replay-prefix transformation
//!                             (RFC 8446 §4.4.1); mutable `*Transcript` is
//!                             the documented escape hatch in the QUAL-317
//!                             spec since the transformation is in-place.
//! - `buildClientHello2Body` — CH2 body encoding via `tls13_full.buildClientHello`.
//! - `buildHrrBody`          — server-side HRR body encoding via
//!                             `tls13_full.buildHelloRetryRequest` +
//!                             `cookie.generateCookie`.
//!
//! Context retains three thin `Context` methods:
//!   `handleHelloRetryRequest`  → parses + transcript-updates + triggers CH2
//!   `sendClientHello2`         → does SEC-036/SEC-050 zeroize + getrandom +
//!                                stores priv/pub in Context, then delegates
//!                                to `buildClientHello2Body` + outbound frame
//!   `sendHelloRetryRequest`    → sets hrr_sent + outbound frame + delegates
//!                                body build to `buildHrrBody`
//!
//! ## Security Invariants (preserved verbatim)
//!
//! - RFC 8446 §4.1.4: double-HRR rejection — caller consults
//!   `Context.hrr_received` before invoking `parseHelloRetryRequest`; on first
//!   success, caller (Context) sets `hrr_received = true`.
//! - RFC 8446 §4.4.1: on HRR, the transcript's original ClientHello1 message
//!   is replaced with a `message_hash` wrapper, followed by the HRR replay.
//!   Implemented inside `applyHrrTranscript`.
//! - Cookie pass-through (RFC 8446 §4.2.2): opaque cookie bytes borrowed from
//!   HRR body are returned unchanged for CH2 re-emission.
//! - RFC 8446 §4.2.8: missing / malformed key_share selected_group ⇒
//!   `HandshakeError.MissingKeyShare`.
//! - SEC-036 + SEC-050 (secureZero of stack + Context-stored ephemeral priv):
//!   remains in the Context adapter for `sendClientHello2` since it depends on
//!   Context-owned `client_priv`.

const std = @import("std");
const tls13_full = @import("tls13_full");
const ks = @import("quic_tls");
const types = @import("../types.zig");
const transcript_mod = @import("../transcript.zig");
const messages_mod = @import("../messages.zig");
const cookie_mod = @import("../messages/extensions/cookie.zig");

const HandshakeError = types.HandshakeError;
const Transcript = transcript_mod.Transcript;
const HsType = messages_mod.HsType;
pub const Hash = ks.Hash;

const readU16 = tls13_full.readU16;

/// Result of `parseHelloRetryRequest`.
///
/// `cookie` is a borrowed slice into the original HRR body; it remains valid
/// as long as the caller-owned body buffer remains valid. `selected_group`
/// is never null — an absent or malformed key_share causes the parser to
/// return `HandshakeError.MissingKeyShare`.
pub const HrrParsed = struct {
    selected_group: tls13_full.NamedGroup,
    cookie: ?[]const u8,
};

/// Parse the body of a HelloRetryRequest handshake message (RFC 8446 §4.1.4).
///
/// Extracts the `key_share` extension's selected_group (RFC 8446 §4.2.8) and
/// the optional `cookie` extension (RFC 8446 §4.2.2). All other extensions
/// are ignored (parser is strict only on bounds).
///
/// Does NOT allocate — cookie is a borrow into `body`.
pub fn parseHelloRetryRequest(body: []const u8) !HrrParsed {
    // Minimum HRR body: legacy_version(2) + random(32) + session_id_len(1) = 35.
    if (body.len < 2 + 32 + 1) return HandshakeError.UnexpectedMessage;
    var pos: usize = 2 + 32; // skip legacy_version + random

    // Skip session_id (SEC-035: bounds-check sid_len before advancing pos).
    if (pos >= body.len) return HandshakeError.UnexpectedMessage;
    const sid_len: usize = body[pos];
    if (pos + 1 + sid_len > body.len) return HandshakeError.UnexpectedMessage;
    pos += 1 + sid_len;

    // Skip cipher_suite + legacy_compression_method.
    if (pos + 2 + 1 > body.len) return HandshakeError.UnexpectedMessage;
    pos += 2 + 1;

    // Extensions list length.
    if (pos + 2 > body.len) return HandshakeError.UnexpectedMessage;
    const exts_len: usize = readU16(body[pos .. pos + 2]);
    pos += 2;
    if (pos + exts_len > body.len) return HandshakeError.UnexpectedMessage;

    const exts_end = pos + exts_len;
    var cookie: ?[]const u8 = null;
    var selected_group: ?tls13_full.NamedGroup = null;

    // GAP-0144 / SEC-104 (cross-ref): RFC 8446 §4.2 forbids more than one
    // extension of the same type in a given block. Without this gate, a
    // second `cookie` extension overwrites the previously-stored borrow at
    // the assignment below — letting an off-path peer steer the CH2 echo.
    // Same parse-class as SEC-066 (ClientHello), SEC-092 (EE/SH), and
    // SEC-079 (X.509). Pattern mirrors `encrypted_extensions.zig:220`.
    var seen = std.EnumSet(tls13_full.ExtensionType).initEmpty();

    while (pos + 4 <= exts_end) {
        const etype = readU16(body[pos .. pos + 2]);
        const elen: usize = readU16(body[pos + 2 .. pos + 4]);
        pos += 4;
        if (pos + elen > exts_end) return HandshakeError.UnexpectedMessage;

        if (std.enums.fromInt(tls13_full.ExtensionType, etype)) |etag| {
            if (seen.contains(etag)) return HandshakeError.DuplicateExtension;
            seen.insert(etag);
        }

        // RFC 8446 §4.2.2: cookie extension. The ext_data carries a
        // `Cookie` struct: `opaque cookie<1..2^16-1>` — i.e. a 2-byte
        // length prefix followed by the cookie bytes.
        if (etype == @intFromEnum(tls13_full.ExtensionType.cookie)) {
            if (elen < 2) return HandshakeError.UnexpectedMessage;
            const ck_len: usize = readU16(body[pos .. pos + 2]);
            if (2 + ck_len > elen) return HandshakeError.UnexpectedMessage;
            cookie = body[pos + 2 .. pos + 2 + ck_len];
        }
        // RFC 8446 §4.2.8: key_share HRR variant — 2-byte selected_group.
        else if (etype == @intFromEnum(tls13_full.ExtensionType.key_share)) {
            if (elen == 2) {
                const group_val = readU16(body[pos .. pos + 2]);
                selected_group = std.enums.fromInt(tls13_full.NamedGroup, group_val);
            }
        }

        pos += elen;
    }

    // Cookie is optional in HRR, but selected_group is required.
    const group = selected_group orelse return HandshakeError.MissingKeyShare;

    return HrrParsed{
        .selected_group = group,
        .cookie = cookie,
    };
}

/// RFC 8446 §4.4.1: Apply the HelloRetryRequest transcript transformation.
///
/// Given a transcript that currently contains exactly ClientHello1, this
/// replaces its contents with `message_hash(ClientHello1) || HelloRetryRequest`
/// (where HelloRetryRequest is framed with its 4-byte handshake header).
///
/// Symmetric for client (ingesting received HRR bytes) and server (emitting
/// its own HRR bytes) — both sides must end up with identical transcripts.
///
/// `*Transcript` is the explicit escape hatch per the QUAL-317 spec.
///
/// PERF-203 / PERF-204: zero-alloc — the 4-byte handshake header is stamped
/// on the stack and fed to the incremental `update` method rather than
/// re-encoding the whole HRR message through `encodeHandshake`.
pub fn applyHrrTranscript(
    transcript: *Transcript,
    hash_kind: ks.Hash,
    ch1_raw: []const u8,
    hrr_body: []const u8,
) void {
    // Step 1: replace CH1 bytes with message_hash(CH1) wrapper.
    transcript.handleHelloRetryRequest(ch1_raw, hash_kind);

    // Step 2: feed the HRR handshake header + body (zero-alloc).
    var hrr_hdr: [4]u8 = undefined;
    hrr_hdr[0] = @intFromEnum(HsType.server_hello);
    const hrr_len: u32 = @intCast(hrr_body.len);
    hrr_hdr[1] = @intCast((hrr_len >> 16) & 0xff);
    hrr_hdr[2] = @intCast((hrr_len >> 8) & 0xff);
    hrr_hdr[3] = @intCast(hrr_len & 0xff);
    transcript.update(&hrr_hdr);
    transcript.update(hrr_body);
}

/// Inputs to `buildClientHello2Body`. Caller supplies the ephemeral X25519
/// public key (generated + stored on Context side to keep SEC-036 zeroize of
/// old priv in the Context adapter).
///
/// RFC 8446 §4.1.4: CH2 MUST reuse the exact ClientHello1 random, selected_group
/// MUST match the HRR selection, cookie MUST be echoed unchanged.
pub const ClientHello2Input = struct {
    /// Client random from CH1 — MUST be byte-for-byte identical (RFC 8446 §4.1.4).
    client_random: [32]u8,
    /// Ephemeral public key for the HRR-selected group.
    client_pub: [32]u8,
    /// Group the server requested in HRR's key_share (RFC 8446 §4.2.8).
    selected_group: tls13_full.NamedGroup,
    /// Cipher suites to re-offer (normally the same list as CH1).
    cipher_suites: []const tls13_full.CipherSuite,
    /// Named groups we support (same list as CH1).
    supported_groups: []const tls13_full.NamedGroup,
    /// Signature schemes (same list as CH1).
    signature_algorithms: []const tls13_full.SignatureScheme,
    /// ALPN protocols (same list as CH1).
    alpn_protocols: ?[]const []const u8,
    /// QUIC transport parameters (either Context-local dup or config).
    quic_transport_parameters: ?[]const u8,
    /// Cookie bytes echoed from HRR (RFC 8446 §4.2.2).
    cookie: ?[]const u8,
};

/// Build the CH2 body (no handshake header) per RFC 8446 §4.1.4.
///
/// Delegates to `tls13_full.buildClientHello`. Caller owns the returned
/// `ClientHelloResult.body`.
pub fn buildClientHello2Body(
    alloc: std.mem.Allocator,
    input: ClientHello2Input,
) !tls13_full.ClientHelloResult {
    return try tls13_full.buildClientHello(alloc, .{
        .random = input.client_random,
        .client_pub = input.client_pub,
        .key_share_group = input.selected_group,
        .cipher_suites = input.cipher_suites,
        .supported_groups = input.supported_groups,
        .signature_algorithms = input.signature_algorithms,
        .alpn_protocols = input.alpn_protocols,
        .quic_transport_parameters = input.quic_transport_parameters,
        .cookie = input.cookie,
    });
}

/// Inputs to `buildHrrBody` (server-side). All slices / bytes are borrowed;
/// caller guarantees lifetime until the call returns.
pub const HrrBuildInput = struct {
    /// Server secret used to HMAC the cookie (RFC 8446 §4.2.2).
    server_secret: []const u8,
    /// Client random from CH1 (used as additional authenticated data on the
    /// cookie HMAC to bind the HRR to this specific client).
    client_random: [32]u8,
    /// Hash of CH1 transcript (the cookie MACs this so the server can
    /// validate, on CH2 arrival, that the client hasn't swapped CH1s).
    ch1_transcript_hash: []const u8,
    /// Group the server is requesting via HRR.
    selected_group: tls13_full.NamedGroup,
    /// Client's original session_id (echoed back per RFC 8446 §4.1.3);
    /// empty / null → session_id field is omitted in HRR.
    session_id: ?[]const u8,
};

/// Result from `buildHrrBody`.
pub const HrrBuildResult = struct {
    /// HRR handshake body (NOT including 4-byte header). Caller owns.
    body: []u8,
    /// Length of the cookie that was embedded in `body`. Informational only
    /// (so tests can assert cookie presence without re-parsing).
    cookie_len: usize,
};

/// Build a HelloRetryRequest body (RFC 8446 §4.1.4).
///
/// Generates an HMAC-authenticated cookie (RFC 8446 §4.2.2) over
/// `(server_secret, client_random, ch1_transcript_hash)` and then encodes the
/// HRR message via `tls13_full.buildHelloRetryRequest`.
///
/// Caller owns the returned `body` and must `alloc.free(body)`.
pub fn buildHrrBody(
    alloc: std.mem.Allocator,
    input: HrrBuildInput,
) !HrrBuildResult {
    const cookie = try cookie_mod.generateCookie(
        alloc,
        input.server_secret,
        input.client_random,
        input.ch1_transcript_hash,
    );
    defer alloc.free(cookie);

    const sid = if (input.session_id) |s| (if (s.len > 0) s else null) else null;

    const body = try tls13_full.buildHelloRetryRequest(
        alloc,
        input.selected_group,
        cookie,
        sid,
    );

    return HrrBuildResult{
        .body = body,
        .cookie_len = cookie.len,
    };
}

// ------------------------------------------------------------
// Tests
// ------------------------------------------------------------

const testing = std.testing;

/// Build a minimal valid HRR body with key_share(selected_group) + optional
/// cookie extension. Returned slice is owned by the caller.
fn buildTestHrrBody(
    alloc: std.mem.Allocator,
    selected_group: tls13_full.NamedGroup,
    cookie: ?[]const u8,
) ![]u8 {
    var buf = try std.ArrayList(u8).initCapacity(alloc, 128);
    errdefer buf.deinit(alloc);

    // legacy_version (2) + random (32)
    try buf.appendSlice(alloc, &[_]u8{ 0x03, 0x03 });
    try buf.appendNTimes(alloc, 0, 32);

    // session_id_len = 0
    try buf.append(alloc, 0);

    // cipher_suite (2) + compression (1)
    try buf.appendSlice(alloc, &[_]u8{ 0x13, 0x01, 0x00 });

    // Extensions
    var exts = try std.ArrayList(u8).initCapacity(alloc, 32);
    defer exts.deinit(alloc);

    // key_share (0x0033): 2-byte selected_group
    try exts.appendSlice(alloc, &[_]u8{ 0x00, 0x33, 0x00, 0x02 });
    const gv: u16 = @intFromEnum(selected_group);
    try exts.append(alloc, @intCast((gv >> 8) & 0xff));
    try exts.append(alloc, @intCast(gv & 0xff));

    if (cookie) |c| {
        // RFC 8446 §4.2.2: ext_data wraps `opaque cookie<1..2^16-1>` —
        // 2-byte ext_data_len, then 2-byte inner cookie length, then bytes.
        const ext_data_len: u16 = @intCast(c.len + 2);
        const inner_len: u16 = @intCast(c.len);
        try exts.appendSlice(alloc, &[_]u8{
            0x00,                                 0x2c,
            @intCast((ext_data_len >> 8) & 0xff), @intCast(ext_data_len & 0xff),
            @intCast((inner_len >> 8) & 0xff),    @intCast(inner_len & 0xff),
        });
        try exts.appendSlice(alloc, c);
    }

    // Extensions length
    const exts_len: u16 = @intCast(exts.items.len);
    try buf.append(alloc, @intCast((exts_len >> 8) & 0xff));
    try buf.append(alloc, @intCast(exts_len & 0xff));
    try buf.appendSlice(alloc, exts.items);

    return try buf.toOwnedSlice(alloc);
}

test "hello_retry: parseHelloRetryRequest extracts selected_group + cookie" {
    const alloc = testing.allocator;
    const cookie_bytes = "testcookie\xaa\xbb\xcc";
    const body = try buildTestHrrBody(alloc, .x25519, cookie_bytes);
    defer alloc.free(body);

    const parsed = try parseHelloRetryRequest(body);
    try testing.expectEqual(tls13_full.NamedGroup.x25519, parsed.selected_group);
    try testing.expect(parsed.cookie != null);
    try testing.expectEqualSlices(u8, cookie_bytes, parsed.cookie.?);
}

test "hello_retry: parseHelloRetryRequest missing key_share rejected (RFC 8446 §4.2.8)" {
    const alloc = testing.allocator;
    var buf = try std.ArrayList(u8).initCapacity(alloc, 64);
    defer buf.deinit(alloc);

    // legacy_version + random + sid_len(0) + cipher(2) + compr(1) + exts_len(2) with empty exts
    try buf.appendSlice(alloc, &[_]u8{ 0x03, 0x03 });
    try buf.appendNTimes(alloc, 0, 32);
    try buf.append(alloc, 0);
    try buf.appendSlice(alloc, &[_]u8{ 0x13, 0x01, 0x00 });
    try buf.appendSlice(alloc, &[_]u8{ 0x00, 0x00 }); // exts_len = 0

    try testing.expectError(HandshakeError.MissingKeyShare, parseHelloRetryRequest(buf.items));
}

test "hello_retry: parseHelloRetryRequest truncated body rejected" {
    // Shorter than minimum (2 + 32 + 1 = 35).
    const truncated = [_]u8{0x03} ** 10;
    try testing.expectError(HandshakeError.UnexpectedMessage, parseHelloRetryRequest(&truncated));
}

test "hello_retry: parseHelloRetryRequest cookie absent is permitted (§4.2.2 optional)" {
    const alloc = testing.allocator;
    const body = try buildTestHrrBody(alloc, .x25519, null);
    defer alloc.free(body);

    const parsed = try parseHelloRetryRequest(body);
    try testing.expectEqual(tls13_full.NamedGroup.x25519, parsed.selected_group);
    try testing.expectEqual(@as(?[]const u8, null), parsed.cookie);
}

test "hello_retry: applyHrrTranscript replaces CH1 with message_hash + HRR" {
    // Two transcripts: one gets applyHrrTranscript; the other manually calls
    // handleHelloRetryRequest + update(hdr) + update(body). They MUST match —
    // this is the core RFC 8446 §4.4.1 invariant.
    var t1 = Transcript.init();
    var t2 = Transcript.init();

    const ch1_raw = "fakeclienthello1body";
    const hrr_body = "fakehrrbody";
    const hash_kind: ks.Hash = .sha256;

    // Seed both with CH1 bytes.
    t1.update(ch1_raw);
    t2.update(ch1_raw);

    // Path A: helper.
    applyHrrTranscript(&t1, hash_kind, ch1_raw, hrr_body);

    // Path B: manual.
    t2.handleHelloRetryRequest(ch1_raw, hash_kind);
    var hdr: [4]u8 = undefined;
    hdr[0] = @intFromEnum(HsType.server_hello);
    const body_len: u32 = @intCast(hrr_body.len);
    hdr[1] = @intCast((body_len >> 16) & 0xff);
    hdr[2] = @intCast((body_len >> 8) & 0xff);
    hdr[3] = @intCast(body_len & 0xff);
    t2.update(&hdr);
    t2.update(hrr_body);

    const h1 = t1.finalize(hash_kind);
    const h2 = t2.finalize(hash_kind);
    try testing.expectEqualSlices(u8, h1.slice(), h2.slice());
}

test "hello_retry: buildHrrBody — body parse-round-trips to same selected_group" {
    const alloc = testing.allocator;
    const server_secret = [_]u8{0x7b} ** 32;
    const ch1_hash = [_]u8{0x55} ** 32;
    const client_random = [_]u8{0x11} ** 32;

    const result = try buildHrrBody(alloc, .{
        .server_secret = &server_secret,
        .client_random = client_random,
        .ch1_transcript_hash = &ch1_hash,
        .selected_group = .x25519,
        .session_id = null,
    });
    defer alloc.free(result.body);

    try testing.expect(result.cookie_len > 0);

    const parsed = try parseHelloRetryRequest(result.body);
    try testing.expectEqual(tls13_full.NamedGroup.x25519, parsed.selected_group);
    // Cookie must be present in a server-built HRR (cookie is always generated).
    try testing.expect(parsed.cookie != null);
    try testing.expectEqual(result.cookie_len, parsed.cookie.?.len);
}

test "hello_retry: buildClientHello2Body — echoes cookie + selected_group" {
    const alloc = testing.allocator;

    const client_random = [_]u8{0xab} ** 32;
    const client_pub = [_]u8{0xcd} ** 32;
    const cookie_bytes = "servercookie42";

    const ciphers = [_]tls13_full.CipherSuite{.TLS_AES_128_GCM_SHA256};
    const groups = [_]tls13_full.NamedGroup{.x25519};
    const sigs = [_]tls13_full.SignatureScheme{.rsa_pss_rsae_sha256};

    const result = try buildClientHello2Body(alloc, .{
        .client_random = client_random,
        .client_pub = client_pub,
        .selected_group = .x25519,
        .cipher_suites = &ciphers,
        .supported_groups = &groups,
        .signature_algorithms = &sigs,
        .alpn_protocols = null,
        .quic_transport_parameters = null,
        .cookie = cookie_bytes,
    });
    defer alloc.free(result.body);

    // Sanity: the cookie bytes appear verbatim somewhere in the CH2 body.
    try testing.expect(std.mem.indexOf(u8, result.body, cookie_bytes) != null);

    // And the client_random is the 32 bytes immediately after legacy_version (2).
    try testing.expectEqualSlices(u8, &client_random, result.body[2 .. 2 + 32]);
}

test "hello_retry: buildClientHello2Body — different cookie produces different body (not a constant)" {
    const alloc = testing.allocator;
    const rnd = [_]u8{0x01} ** 32;
    const cpub = [_]u8{0x02} ** 32;
    const ciphers = [_]tls13_full.CipherSuite{.TLS_AES_128_GCM_SHA256};
    const groups = [_]tls13_full.NamedGroup{.x25519};
    const sigs = [_]tls13_full.SignatureScheme{.rsa_pss_rsae_sha256};

    const base = try buildClientHello2Body(alloc, .{
        .client_random = rnd,
        .client_pub = cpub,
        .selected_group = .x25519,
        .cipher_suites = &ciphers,
        .supported_groups = &groups,
        .signature_algorithms = &sigs,
        .alpn_protocols = null,
        .quic_transport_parameters = null,
        .cookie = "cookieA",
    });
    defer alloc.free(base.body);

    const other = try buildClientHello2Body(alloc, .{
        .client_random = rnd,
        .client_pub = cpub,
        .selected_group = .x25519,
        .cipher_suites = &ciphers,
        .supported_groups = &groups,
        .signature_algorithms = &sigs,
        .alpn_protocols = null,
        .quic_transport_parameters = null,
        .cookie = "cookieBBBBB",
    });
    defer alloc.free(other.body);

    // Different cookie ⇒ different body length at minimum.
    try testing.expect(base.body.len != other.body.len);
}
