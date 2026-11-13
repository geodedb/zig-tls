// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUAL-317: certificate-chain validation + CertificateVerify signature checks.
//!
//! Four flows unified behind shared state slices: server-cert, server-cert-verify,
//! client-cert, client-cert-verify. Per-role behavior branches on `Role` enum.
//!
//! Security invariants preserved verbatim (from the former inline handlers in
//! `src/tls13/context.zig`):
//!
//! - x509 chain depth bound (enforced inside `x509.validateChainReturnParsed`).
//! - EKU filter: `.server_auth` when verifying a server cert, `.client_auth`
//!   when verifying a client cert (SEC-031).
//! - SNI match on peer_role=.server only; for client certs the SNI field is
//!   passed as `""` — no hostname validation on mTLS (RFC 8446 §4.4.2).
//! - OCSP stapled-response validation (RFC 6960 + RFC 8446 §4.4.2.1).
//! - SCT presence + callback enforcement (RFC 6962 + RFC 8446 §4.4.2.1).
//! - RFC 8446 §4.4.3 signature context-string selection:
//!     server cert → `"TLS 1.3, server CertificateVerify"`
//!     client cert → `"TLS 1.3, client CertificateVerify"`
//! - `allow_insecure` short-circuit (skip validation when explicitly opted in).
//! - `require_ocsp` / `require_scts` / `require_client_cert` gating.
//!
//! Architecture: the 4 original Context methods mutated many fields
//! (peer_cert_chain, peer_cert_chain_buf, peer_ocsp_response, peer_sct_list,
//! peer_cert_verify_sig, peer_cert_verify_alg). Rather than plumb every
//! mutable field through a single state-slice, this module exposes the
//! *algorithmic* pieces as pure functions, and Context.zig keeps thin
//! adapters that glue those pieces to its mutable state (free-old / store-new).
//! The pattern mirrors Task 5 (psk_selection) where the Context method
//! remained but delegated all security logic to the pure module.

const std = @import("std");
const ks = @import("quic_tls");
const x509 = @import("x509");
const sig = @import("sig");
const ocsp = @import("ocsp");
const sct = @import("sct");
const tls13_full = @import("tls13_full");
const types = @import("../types.zig");

const HandshakeError = types.HandshakeError;

pub const Role = enum { client, server };

/// Owned storage for a parsed certificate chain.
///
/// Mirrors the `peer_cert_chain` + `peer_cert_chain_buf` pair on Context.
/// Caller takes ownership of both slices (free `buf` first if non-null, then
/// `chain`). OCSP response and SCT list are separately allocated dupes of
/// the leaf-cert extensions (may be null when absent).
pub const ChainStorage = struct {
    chain: [][]const u8,
    /// PERF-042: single contiguous backing buffer for all cert bytes.
    buf: []u8,
    /// RFC 8446 §4.4.2.1: OCSP response from leaf entry extension.
    ocsp_response: ?[]u8,
    /// RFC 8446 §4.4.2.1: SCT list from leaf entry extension.
    sct_list: ?[]u8,
};

/// Input to `parseAndStoreChain` — role-agnostic because chain parsing is
/// identical for server and client cert messages.
pub const ChainParseInput = struct {
    body: []const u8,
    /// When true (client-cert path), empty chain is allowed (mTLS — client
    /// sends empty Certificate to signal "no client cert"). Caller is then
    /// expected to enforce `require_client_cert` separately.
    ///
    /// When false (server-cert path), empty chain returns
    /// `HandshakeError.EmptyCertificateChain` per RFC 8446 §4.4.2.
    allow_empty: bool,
};

/// Result of `parseAndStoreChain`.
///
/// When `was_empty` is true (only possible on client-cert path when
/// `allow_empty=true`), `storage` is null and the caller should free any
/// existing chain and treat this as "peer sent no certificate".
pub const ChainParseResult = struct {
    storage: ?ChainStorage,
    was_empty: bool,
};

/// NEWGAP-10: extract the `certificate_request_context` length from a
/// Certificate message body (RFC 8446 §4.4.2: a 1-byte length prefix). Callers
/// validate it *before* `parseAndStoreChain` allocates, so a context violation
/// aborts without leaking a freshly-parsed chain. Returns the context length,
/// or `error.IllegalCertificateRequestContext` if the body is too short to
/// carry the prefix.
pub fn certificateRequestContextLen(body: []const u8) !usize {
    if (body.len < 1) return HandshakeError.IllegalCertificateRequestContext;
    return body[0];
}

/// Parse a Certificate handshake message body and allocate a ChainStorage.
///
/// Preserves the PERF-042 single-backing-buffer layout from the original
/// inline code (one cert_buf + one chain slice array = 2 allocations rather
/// than N+1). OCSP and SCT extensions on the leaf entry are dup'd into owned
/// slices (callers that already hold peer_ocsp_response / peer_sct_list must
/// free the old ones — this module never mutates Context state).
///
/// On any error, all intermediate allocations are released before return.
pub fn parseAndStoreChain(
    alloc: std.mem.Allocator,
    input: ChainParseInput,
) !ChainParseResult {
    const parsed = try tls13_full.parseCertificate(alloc, input.body);
    defer alloc.free(parsed.entries);

    if (parsed.entries.len == 0) {
        if (input.allow_empty) {
            return ChainParseResult{ .storage = null, .was_empty = true };
        }
        return HandshakeError.EmptyCertificateChain;
    }

    // PERF-042: single contiguous buffer.
    var total_cert_bytes: usize = 0;
    for (parsed.entries) |cert_entry| {
        total_cert_bytes += cert_entry.cert.len;
    }
    const cert_buf = try alloc.alloc(u8, total_cert_bytes);
    errdefer alloc.free(cert_buf);

    var chain = try alloc.alloc([]const u8, parsed.entries.len);
    errdefer alloc.free(chain);

    var offset: usize = 0;
    for (parsed.entries, 0..) |cert_entry, i| {
        @memcpy(cert_buf[offset..][0..cert_entry.cert.len], cert_entry.cert);
        chain[i] = cert_buf[offset..][0..cert_entry.cert.len];
        offset += cert_entry.cert.len;
    }

    // Dup OCSP + SCT (QUAL-128: dup before caller frees old to avoid dangling).
    var ocsp_copy: ?[]u8 = null;
    errdefer if (ocsp_copy) |o| alloc.free(o);
    if (parsed.entries[0].ocsp_response) |ocsp_data| {
        ocsp_copy = try alloc.dupe(u8, ocsp_data);
    }

    var sct_copy: ?[]u8 = null;
    errdefer if (sct_copy) |s| alloc.free(s);
    if (parsed.entries[0].sct_list) |sct_data| {
        sct_copy = try alloc.dupe(u8, sct_data);
    }

    return ChainParseResult{
        .storage = ChainStorage{
            .chain = chain,
            .buf = cert_buf,
            .ocsp_response = ocsp_copy,
            .sct_list = sct_copy,
        },
        .was_empty = false,
    };
}

/// RFC 8446 §4.4.3: select the signature context string for TLS 1.3
/// CertificateVerify construction.
///
/// These are the exact byte strings the spec requires — prefix of 64 space
/// bytes + this string + 0x00 + transcript hash is the TBS input.
pub fn contextStringForRole(role: Role) []const u8 {
    return switch (role) {
        .server => "TLS 1.3, server CertificateVerify",
        .client => "TLS 1.3, client CertificateVerify",
    };
}

/// RFC 8446 §4.2.3: check that a signature scheme announced in
/// CertificateVerify is in the locally-configured supported set.
/// Returns `error.UnsupportedSignatureAlgorithm` when not found.
pub fn validateSignatureAlgorithm(
    scheme: anytype,
    supported: []const @TypeOf(scheme),
) !void {
    for (supported) |s| {
        if (s == scheme) return;
    }
    return HandshakeError.UnsupportedSignatureAlgorithm;
}

/// Input to `verifyCertVerifySignature`. The leaf SPKI is sourced from the
/// x509 module's `validateChainReturnParsed` (SPKI DER, not the full cert).
pub const CertVerifyInput = struct {
    role: Role,
    leaf_spki: []const u8,
    signature: []const u8,
    signature_scheme: u16,
    transcript_hash: []const u8,
};

/// RFC 8446 §4.4.3: verify the CertificateVerify signature.
///
/// Wraps `sig.verifyCertificateVerify` with the role-appropriate context
/// string. Returns `HandshakeError.InvalidSignature` on signature mismatch,
/// or `HandshakeError.UnsupportedSignatureAlgorithm` if the scheme can't be
/// mapped to a `sig.SigAlg`.
pub fn verifyCertVerifySignature(
    input: CertVerifyInput,
    alloc: std.mem.Allocator,
) !void {
    const sig_alg = sig.fromTls13SignatureScheme(input.signature_scheme) catch {
        return HandshakeError.UnsupportedSignatureAlgorithm;
    };
    const verified = try sig.verifyCertificateVerify(
        sig_alg,
        input.leaf_spki,
        input.signature,
        contextStringForRole(input.role),
        input.transcript_hash,
        alloc,
    );
    if (!verified) return HandshakeError.InvalidSignature;
}

/// GAP-0838: per-connection trust anchors for the duration of one synchronous
/// chain-validation call. The chain validator's `TrustStore` callback is a
/// bare (stateless) function pointer, so we publish the anchor SPKIs through
/// a thread-local that `anchorTrustStoreIsTrusted` reads. Safe because TLS
/// handshake certificate validation runs synchronously on one connection's
/// thread and never re-enters chain validation. Always saved/restored.
threadlocal var tl_trusted_anchor_spkis: []const []const u8 = &.{};

fn anchorTrustStoreIsTrusted(spki_der: []const u8) bool {
    for (tl_trusted_anchor_spkis) |anchor_spki| {
        if (std.mem.eql(u8, anchor_spki, spki_der)) return true;
    }
    return false;
}

/// GAP-0838: leaf-only wrapper over `validateChainLeafAndIssuer` — validates
/// the chain (honoring per-connection `trusted_ca_der` anchors) and returns
/// just the parsed leaf.
pub fn validateChainAndLeaf(
    alloc: std.mem.Allocator,
    chain: [][]const u8,
    now_unix: i64,
    server_name: []const u8,
    insecure: x509.InsecureValidation,
    trust_store_override: ?x509.TrustStore,
    trusted_ca_der: []const []const u8,
) !x509.Certificate {
    var parsed = try validateChainLeafAndIssuer(
        alloc,
        chain,
        now_unix,
        server_name,
        insecure,
        trust_store_override,
        trusted_ca_der,
    );
    if (parsed.issuer) |*iss| iss.deinit(alloc);
    return parsed.leaf;
}

/// QUAL-357 / PERF-262: Validates the chain and returns the parsed leaf AND
/// issuer (`chain[1]`), normalizing errors to
/// `HandshakeError.CertificateValidationFailed` for the alert dispatcher.
///
/// RFC 5280 §6: full chain validation — validity, hostname (SNI), EKU
/// (server_auth), basic constraints, and signature verification along the
/// chain. PERF-207: validate + parse leaf in one pass. PERF-016: cached trust
/// store avoids RwLock contention. SEC-077: in insecure testing mode the
/// underlying x509 call short-circuits validation but STILL returns the parsed
/// leaf (needed for downstream CertificateVerify).
///
/// GAP-0838: when `trusted_ca_der` is non-empty, validation is pinned to those
/// caller-provided anchors — (a) each anchor's SPKI becomes the trust root,
/// and (b) the anchors that issued the presented chain are appended, so a
/// server that sends only its leaf still chains up to a trusted CA
/// (`validateWithAnchors`).
pub fn validateChainLeafAndIssuer(
    alloc: std.mem.Allocator,
    chain: [][]const u8,
    now_unix: i64,
    server_name: []const u8,
    insecure: x509.InsecureValidation,
    trust_store_override: ?x509.TrustStore,
    trusted_ca_der: []const []const u8,
) !x509.LeafAndIssuer {
    // Fast path: no per-connection anchors — preserve prior behavior exactly.
    if (trusted_ca_der.len == 0) {
        return x509.validateChainReturnLeafAndIssuer(
            alloc,
            chain,
            now_unix,
            server_name,
            insecure,
            .server_auth,
            trust_store_override,
        ) catch return HandshakeError.CertificateValidationFailed;
    }

    return validateWithAnchors(alloc, chain, now_unix, server_name, insecure, .server_auth, trusted_ca_der) catch |e| switch (e) {
        error.OutOfMemory => e,
        else => HandshakeError.CertificateValidationFailed,
    };
}

/// SONNY-6457: validate a client certificate chain (mTLS, `.client_auth`
/// EKU, no name check) against the server's configured anchors, completing
/// a leaf-only chain from them exactly as `validateChainLeafAndIssuer` does
/// for server certificates. Returns the parsed leaf (caller owns).
pub fn validateClientChainAndLeaf(
    alloc: std.mem.Allocator,
    chain: [][]const u8,
    now_unix: i64,
    trusted_ca_der: []const []const u8,
) !x509.Certificate {
    if (trusted_ca_der.len == 0) return HandshakeError.CertificateValidationFailed;
    var parsed = validateWithAnchors(alloc, chain, now_unix, "", .secure, .client_auth, trusted_ca_der) catch |e| switch (e) {
        error.OutOfMemory => return e,
        else => return HandshakeError.CertificateValidationFailed,
    };
    if (parsed.issuer) |*iss| iss.deinit(alloc);
    return parsed.leaf;
}

/// Build a complete path to a caller-pinned trust anchor and validate it.
///
/// (a) Trust anchors by SPKI: each configured CA's SubjectPublicKeyInfo is
///     the only trusted root for this call.
/// (b) Complete the chain (RFC 5280 §6.1): starting from the last
///     certificate the peer sent, append the configured anchor whose subject
///     is that certificate's issuer, until the path ends in a self-issued
///     certificate or no anchor issued it. SONNY-6457: this used to append
///     EVERY anchor the peer had not sent, so the chain walk (each
///     certificate signed by the next) failed as soon as a second, unrelated
///     anchor was configured.
fn validateWithAnchors(
    alloc: std.mem.Allocator,
    chain: [][]const u8,
    now_unix: i64,
    server_name: []const u8,
    insecure: x509.InsecureValidation,
    purpose: x509.EkuPurpose,
    trusted_ca_der: []const []const u8,
) !x509.LeafAndIssuer {
    if (chain.len == 0) return HandshakeError.CertificateValidationFailed;

    var anchor_spkis = std.ArrayList([]const u8).empty;
    defer {
        for (anchor_spkis.items) |sp| alloc.free(sp);
        anchor_spkis.deinit(alloc);
    }
    var anchor_subjects = std.ArrayList(struct { der: []const u8, subject: []u8 }).empty;
    defer {
        for (anchor_subjects.items) |a| alloc.free(a.subject);
        anchor_subjects.deinit(alloc);
    }
    for (trusted_ca_der) |anchor_der| {
        var parsed = x509.parseCert(alloc, anchor_der) catch continue;
        defer parsed.deinit(alloc);
        const spki_copy = try alloc.dupe(u8, parsed.spki);
        anchor_spkis.append(alloc, spki_copy) catch |e| {
            alloc.free(spki_copy);
            return e;
        };
        const subject_copy = try alloc.dupe(u8, parsed.subject_der);
        anchor_subjects.append(alloc, .{ .der = anchor_der, .subject = subject_copy }) catch |e| {
            alloc.free(subject_copy);
            return e;
        };
    }

    var effective = std.ArrayList([]const u8).empty;
    defer effective.deinit(alloc);
    try effective.appendSlice(alloc, chain);
    var added: usize = 0;
    while (added < anchor_subjects.items.len) : (added += 1) {
        var last = x509.parseCert(alloc, effective.items[effective.items.len - 1]) catch break;
        defer last.deinit(alloc);
        if (std.mem.eql(u8, last.subject_der, last.issuer_der)) break; // path ends at a self-issued cert
        const next: ?[]const u8 = for (anchor_subjects.items) |a| {
            if (!std.mem.eql(u8, a.subject, last.issuer_der)) continue;
            const already = for (effective.items) |e| {
                if (std.mem.eql(u8, e, a.der)) break true;
            } else false;
            if (!already) break a.der;
        } else null;
        try effective.append(alloc, next orelse break);
    }

    const prev = tl_trusted_anchor_spkis;
    tl_trusted_anchor_spkis = anchor_spkis.items;
    defer tl_trusted_anchor_spkis = prev;

    const anchor_ts = x509.TrustStore{ .isTrustedSpki = anchorTrustStoreIsTrusted };
    return x509.validateChainReturnLeafAndIssuer(
        alloc,
        effective.items,
        now_unix,
        server_name,
        insecure,
        purpose,
        anchor_ts,
    );
}

/// QUAL-357: Validates an OCSP stapled response against the leaf certificate.
///
/// Behavior matrix:
///   - `ocsp_bytes == null` + `require_ocsp == true`  → MissingOcspResponse
///   - `ocsp_bytes == null` + `require_ocsp == false` → ok (no-op)
///   - Validation failure (for non-null bytes)        → OcspValidationFailed
///
/// RFC 6960 + RFC 8446 §4.4.2.1: OCSP stapling validation. When a chain of
/// length >= 2 is provided, the issuer cert is parsed and passed to the
/// validator so the OCSP response's issuer key hash can be verified.
pub fn validateOcspStaple(
    alloc: std.mem.Allocator,
    ocsp_bytes: ?[]const u8,
    leaf_parsed: *x509.Certificate,
    chain: [][]const u8,
    now_unix: i64,
    require_ocsp: bool,
    /// PERF-262: pre-parsed issuer (`chain[1]`) from the chain-validation pass.
    /// When non-null and the chain has >= 2 certs, it is reused instead of
    /// re-parsing `chain[1]` here.
    issuer_parsed: ?*x509.Certificate,
) !void {
    if (ocsp_bytes == null) {
        if (require_ocsp) return HandshakeError.MissingOcspResponse;
        return;
    }

    // PERF-262: reuse the issuer parsed during chain validation when available;
    // only fall back to a fresh parse if the caller did not supply it.
    var owned_issuer: x509.Certificate = undefined;
    var owns_issuer = false;
    defer if (owns_issuer) owned_issuer.deinit(alloc);

    const issuer_info: ?ocsp.IssuerInfo = if (chain.len >= 2) blk: {
        const issuer_ptr: *x509.Certificate = if (issuer_parsed) |iss| iss else inner: {
            owned_issuer = try x509.parseCert(alloc, chain[1]);
            owns_issuer = true;
            break :inner &owned_issuer;
        };
        break :blk ocsp.IssuerInfo{ .cert = issuer_ptr, .der = chain[1] };
    } else null;

    ocsp.validateStapledResponse(
        alloc,
        ocsp_bytes.?,
        leaf_parsed,
        chain[0],
        issuer_info,
        now_unix,
    ) catch return HandshakeError.OcspValidationFailed;
}

/// QUAL-357: Parses the SCT list and invokes the user callback (if any).
///
/// RFC 6962 + RFC 8446 §4.4.2.1: Signed Certificate Timestamp validation.
///
/// Behavior matrix:
///   - `sct_bytes == null` + `require_scts == true`  → MissingSctList
///   - `sct_bytes == null` + `require_scts == false` → ok (no-op)
///   - Parse failure            → SctParsingFailed
///   - Empty list + required    → EmptySctList
///   - Callback rejects         → SctCallbackRejected
pub fn validateSctList(
    alloc: std.mem.Allocator,
    sct_bytes: ?[]const u8,
    require_scts: bool,
    on_sct_list: ?*const fn ([]sct.SignedCertificateTimestamp) anyerror!void,
) !void {
    if (sct_bytes == null) {
        if (require_scts) return HandshakeError.MissingSctList;
        return;
    }

    const parsed_scts = sct.parseList(alloc, sct_bytes.?) catch return HandshakeError.SctParsingFailed;
    defer alloc.free(parsed_scts);

    if (parsed_scts.len == 0 and require_scts) return HandshakeError.EmptySctList;

    if (on_sct_list) |cb| {
        cb(parsed_scts) catch return HandshakeError.SctCallbackRejected;
    }
}

// ------------------------------------------------------------
// Tests
// ------------------------------------------------------------

const testing = std.testing;

test "cert_handlers: contextStringForRole — server matches RFC 8446 §4.4.3 exactly" {
    // RFC 8446 §4.4.3 mandates the exact byte string
    // "TLS 1.3, server CertificateVerify" (33 bytes) for server-cert signatures.
    const expected = "TLS 1.3, server CertificateVerify";
    const actual = contextStringForRole(.server);
    try testing.expectEqualStrings(expected, actual);
    try testing.expectEqual(@as(usize, 33), actual.len);
}

test "cert_handlers: contextStringForRole — client matches RFC 8446 §4.4.3 exactly" {
    // RFC 8446 §4.4.3 mandates the exact byte string
    // "TLS 1.3, client CertificateVerify" (33 bytes) for client-cert signatures.
    const expected = "TLS 1.3, client CertificateVerify";
    const actual = contextStringForRole(.client);
    try testing.expectEqualStrings(expected, actual);
    try testing.expectEqual(@as(usize, 33), actual.len);
}

test "cert_handlers: contextStringForRole — server and client strings differ (not aliased)" {
    // Defence against accidentally returning the same string for both roles:
    // cross-role signature confusion would be catastrophic (a client could
    // replay a server's signature, etc.).
    const srv = contextStringForRole(.server);
    const cli = contextStringForRole(.client);
    try testing.expect(!std.mem.eql(u8, srv, cli));
}

test "cert_handlers: validateSignatureAlgorithm — accepts scheme in supported list" {
    const schemes = [_]u16{ 0x0403, 0x0804, 0x0807 };
    try validateSignatureAlgorithm(@as(u16, 0x0804), &schemes);
    try validateSignatureAlgorithm(@as(u16, 0x0403), &schemes);
    try validateSignatureAlgorithm(@as(u16, 0x0807), &schemes);
}

test "cert_handlers: validateSignatureAlgorithm — rejects scheme not in list" {
    const schemes = [_]u16{ 0x0403, 0x0804 };
    try testing.expectError(
        HandshakeError.UnsupportedSignatureAlgorithm,
        validateSignatureAlgorithm(@as(u16, 0x0807), &schemes),
    );
}

test "cert_handlers: validateSignatureAlgorithm — empty supported list rejects everything" {
    const schemes: [0]u16 = .{};
    try testing.expectError(
        HandshakeError.UnsupportedSignatureAlgorithm,
        validateSignatureAlgorithm(@as(u16, 0x0403), &schemes),
    );
}

test "cert_handlers: parseAndStoreChain — empty chain rejected when allow_empty=false" {
    // Valid Certificate message with empty cert list:
    //   request_context_len (1 byte) = 0
    //   cert_list_len (3 bytes) = 0
    const empty_cert_msg = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    try testing.expectError(
        HandshakeError.EmptyCertificateChain,
        parseAndStoreChain(testing.allocator, .{
            .body = &empty_cert_msg,
            .allow_empty = false,
        }),
    );
}

test "cert_handlers: parseAndStoreChain — empty chain allowed when allow_empty=true (mTLS no-cert)" {
    // RFC 8446 §4.4.2: client MAY send empty Certificate in mTLS when it has
    // no certificate to offer. Server-side parsing must accept this as a
    // "no cert" signal and defer the require_client_cert decision.
    const empty_cert_msg = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    const result = try parseAndStoreChain(testing.allocator, .{
        .body = &empty_cert_msg,
        .allow_empty = true,
    });
    try testing.expectEqual(@as(?ChainStorage, null), result.storage);
    try testing.expect(result.was_empty);
}

// GAP-0838: a CA-issued peer that presents only its leaf (no intermediates /
// root) must still verify when the verifier pins the issuing CA via
// trusted_ca_der — validateChainAndLeaf completes the path to that anchor.
test "cert_handlers: validateChainAndLeaf completes leaf-only chain via trusted_ca_der (GAP-0838)" {
    const leaf = @embedFile("gap838_leaf.der");
    const ca = @embedFile("gap838_ca.der");
    var leaf_only = [_][]const u8{leaf};
    const anchors = [_][]const u8{ca};
    const now: i64 = 1780185764;
    const sni = "geode-0.geode.divelife-qa.svc.cluster.local";

    // No trust anchor + leaf-only presentation: cannot build a path → fails.
    try std.testing.expectError(
        HandshakeError.CertificateValidationFailed,
        validateChainAndLeaf(std.testing.allocator, leaf_only[0..], now, sni, .secure, null, &.{}),
    );

    // With the issuing CA pinned via trusted_ca_der: path is completed and the
    // anchor is trusted → verifies (this is the divelife cluster-peer case).
    var ok = try validateChainAndLeaf(std.testing.allocator, leaf_only[0..], now, sni, .secure, null, &anchors);
    ok.deinit(std.testing.allocator);

    // A pinned anchor that did NOT issue the leaf must not spuriously verify.
    var wrong_anchor = [_][]const u8{leaf}; // leaf is not a CA for itself
    try std.testing.expectError(
        HandshakeError.CertificateValidationFailed,
        validateChainAndLeaf(std.testing.allocator, leaf_only[0..], now, sni, .secure, null, &wrong_anchor),
    );
}

test "NEWGAP-10: certificateRequestContextLen reads the §4.4.2 length prefix" {
    // Empty context (server-auth Certificate).
    try testing.expectEqual(@as(usize, 0), try certificateRequestContextLen(&[_]u8{ 0x00, 0x00, 0x00, 0x00 }));
    // Non-empty context (length 4) — handlers reject this per RFC 8446 §4.4.2.
    try testing.expectEqual(@as(usize, 4), try certificateRequestContextLen(&[_]u8{ 0x04, 0xDE, 0xAD, 0xBE, 0xEF }));
    // Too short to even carry the length prefix.
    try testing.expectError(HandshakeError.IllegalCertificateRequestContext, certificateRequestContextLen(&[_]u8{}));
}
