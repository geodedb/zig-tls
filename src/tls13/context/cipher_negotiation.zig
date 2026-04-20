// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUAL-317: cipher-suite and signature-scheme selection.
//!
//! Pure table lookups over client-offered vs server-supported lists.
//! No TLS state, no Context, no allocations.
//!
//! Extracted from `src/tls13/context.zig` (`chooseCipherSuite` and
//! `selectServerSignatureScheme`). Both are now value-in / value-out;
//! the caller (Context) is responsible for mutating the negotiated-state
//! fields (`negotiated_signature`) on success.
//!
//! Selection semantics preserved from the original (server-list order
//! wins; first match against the client-offered list is returned):
//!
//!   for each server candidate:
//!       for each client offer:
//!           if equal: return
//!   return null
//!
//! This mirrors RFC 8446 §4.2.3 guidance that the server's preference
//! order is authoritative for signature-scheme negotiation, and the
//! equivalent cipher-suite selection contract.

const std = @import("std");
const tls13_full = @import("tls13_full");

/// Return the first server-supported cipher suite that also appears in the
/// client-offered list. Server-list order is authoritative. Returns `null`
/// when there is no overlap (or when either list is empty).
pub fn chooseCipherSuite(
    offered: []const tls13_full.CipherSuite,
    supported: []const tls13_full.CipherSuite,
) ?tls13_full.CipherSuite {
    for (supported) |s| {
        for (offered) |c| {
            if (s == c) return s;
        }
    }
    return null;
}

/// Return the first server-supported signature scheme that also appears in
/// the peer's offered list. Server-list order is authoritative. Returns
/// `null` when there is no overlap (or when either list is empty).
///
/// Note: this function is pure. The original `Context.selectServerSignatureScheme`
/// also mutated `self.negotiated_signature`; that assignment now lives in the
/// call site that owns the Context.
pub fn chooseSignatureScheme(
    peer_schemes: []const tls13_full.SignatureScheme,
    local_schemes: []const tls13_full.SignatureScheme,
) ?tls13_full.SignatureScheme {
    for (local_schemes) |l| {
        for (peer_schemes) |p| {
            if (l == p) return l;
        }
    }
    return null;
}

// ============================================================================
// Unit Tests (QUAL-317)
// ============================================================================

const testing = std.testing;
const CS = tls13_full.CipherSuite;
const SS = tls13_full.SignatureScheme;

test "chooseCipherSuite: happy path returns first server-preferred match" {
    const offered = [_]CS{ .TLS_CHACHA20_POLY1305_SHA256, .TLS_AES_128_GCM_SHA256 };
    const supported = [_]CS{ .TLS_AES_128_GCM_SHA256, .TLS_CHACHA20_POLY1305_SHA256 };
    try testing.expectEqual(CS.TLS_AES_128_GCM_SHA256, chooseCipherSuite(&offered, &supported).?);
}

test "chooseCipherSuite: no overlap returns null" {
    const offered = [_]CS{.TLS_AES_128_CCM_SHA256};
    const supported = [_]CS{ .TLS_AES_128_GCM_SHA256, .TLS_AES_256_GCM_SHA384 };
    try testing.expectEqual(@as(?CS, null), chooseCipherSuite(&offered, &supported));
}

test "chooseCipherSuite: empty offered returns null" {
    const offered = [_]CS{};
    const supported = [_]CS{.TLS_AES_128_GCM_SHA256};
    try testing.expectEqual(@as(?CS, null), chooseCipherSuite(&offered, &supported));
}

test "chooseCipherSuite: empty supported returns null" {
    const offered = [_]CS{.TLS_AES_128_GCM_SHA256};
    const supported = [_]CS{};
    try testing.expectEqual(@as(?CS, null), chooseCipherSuite(&offered, &supported));
}

test "chooseCipherSuite: server-first preference wins" {
    // Both lists contain the same two suites but in opposite orders. The
    // server's preference (supported[0]) must win.
    const offered = [_]CS{ .TLS_CHACHA20_POLY1305_SHA256, .TLS_AES_256_GCM_SHA384 };
    const supported = [_]CS{ .TLS_AES_256_GCM_SHA384, .TLS_CHACHA20_POLY1305_SHA256 };
    try testing.expectEqual(CS.TLS_AES_256_GCM_SHA384, chooseCipherSuite(&offered, &supported).?);
}

test "chooseSignatureScheme: happy path with Ed25519 overlap" {
    const peer = [_]SS{ .ed25519, .ecdsa_secp256r1_sha256 };
    const local = [_]SS{ .ed25519, .rsa_pss_rsae_sha256 };
    try testing.expectEqual(SS.ed25519, chooseSignatureScheme(&peer, &local).?);
}

test "chooseSignatureScheme: server-first preference wins" {
    // Peer offers RSA-PSS first but the server prefers ECDSA first — server
    // preference is authoritative per RFC 8446 section 4.2.3.
    const peer = [_]SS{ .rsa_pss_rsae_sha256, .ecdsa_secp256r1_sha256 };
    const local = [_]SS{ .ecdsa_secp256r1_sha256, .rsa_pss_rsae_sha256 };
    try testing.expectEqual(SS.ecdsa_secp256r1_sha256, chooseSignatureScheme(&peer, &local).?);
}

test "chooseSignatureScheme: no overlap returns null" {
    const peer = [_]SS{.rsa_pkcs1_sha256};
    const local = [_]SS{ .ed25519, .ecdsa_secp256r1_sha256 };
    try testing.expectEqual(@as(?SS, null), chooseSignatureScheme(&peer, &local));
}
