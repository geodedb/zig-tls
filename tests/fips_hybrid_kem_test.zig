// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const cb = @import("crypto_backend");
const ks = @import("quic_tls");

// The hybrid KEM shared secret must drive the TLS 1.3 handshake key
// schedule: encap/decap agree, and deriveHandshakeTraffic over that
// secret is deterministic for both peers. fips-only.
test "FIPS hybrid KEM - X25519MLKEM768 shared secret feeds key schedule" {
    if (comptime !cb.fips_enabled) return error.SkipZigTest;
    var kp = try cb.Kem.generate(.x25519_ml_kem_768);
    defer kp.deinit();
    var ct: [2048]u8 = undefined;
    var ss_a: [64]u8 = undefined;
    const e = try cb.Kem.encapsulate(.x25519_ml_kem_768, &kp, &ct, &ss_a);
    var ss_b: [64]u8 = undefined;
    const d = try cb.Kem.decapsulate(.x25519_ml_kem_768, &kp, ct[0..e.ct_len], &ss_b);
    try std.testing.expectEqualSlices(u8, ss_a[0..e.ss_len], ss_b[0..d]);

    // Both peers feed the agreed shared secret into the TLS 1.3 key
    // schedule and derive the same handshake secret. We use the
    // quic_tls (key_schedule.zig) primitives directly because the
    // full deriveHandshakeTraffic helper lives in the internal
    // tls13/key_derivation.zig: HandshakeSecret = HKDF-Extract(
    //   Derive-Secret(EarlySecret,"derived",""), shared_secret).
    const early = ks.zeroSecret(.sha384);
    const empty_hash = ks.hashBytes(.sha384, "");
    const derived = ks.deriveSecretHash(.sha384, &early, "derived", empty_hash.slice());
    const hs_a = ks.extractHash(.sha384, derived.slice(), ss_a[0..e.ss_len]);
    const hs_b = ks.extractHash(.sha384, derived.slice(), ss_b[0..d]);
    try std.testing.expectEqualSlices(u8, hs_a.slice(), hs_b.slice());
}
