// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const cb = @import("crypto_backend");
const tls13_full = @import("tls13_full");

// The hybrid key_share byte layout (draft-kwiatkowski-tls-ecdhe-mlkem §3):
// ClientHello entry = ML-KEM-768 encap key (1184) || X25519 pub (32) = 1216;
// ServerHello entry = ML-KEM-768 ciphertext (1088) || X25519 pub (32) = 1120;
// the combined shared secret is 64 bytes.
//
// IMPORTANT (OpenSSL provider behavior, confirmed against 3.6.5): the
// "X25519MLKEM768" provider KEM is a COMPLETE hybrid — `encapsulate`
// returns the full 1120-byte ServerHello key_share as the ciphertext
// (the X25519 ephemeral public key is concatenated by the provider, ECDH
// share placement per draft) and the full 64-byte combined shared secret.
// The consumer does NOT manually concatenate the X25519 leg; OpenSSL owns
// both legs. So enc.ct_len == sh_keyshare_len (1120) and enc.ss_len == 64.
// This test pins those provider-reported lengths and the pinned
// Kem.EncapResult named return type against a locally-owned keypair (NOT
// the server-against-peer path, covered by fips_hybrid_handshake_test.zig).
// fips-only.
test "FIPS hybrid key_share - draft sizes and concat order" {
    if (comptime !cb.fips_enabled) return error.SkipZigTest;
    try std.testing.expectEqual(@as(usize, 1216), tls13_full.x25519_mlkem768_ch_keyshare_len);
    try std.testing.expectEqual(@as(usize, 1120), tls13_full.x25519_mlkem768_sh_keyshare_len);
    try std.testing.expectEqual(@as(usize, 1088), tls13_full.mlkem768_ciphertext_len);
    try std.testing.expectEqual(@as(usize, 1184), tls13_full.mlkem768_encap_key_len);
    try std.testing.expectEqual(@as(usize, 32), tls13_full.x25519_len);

    var kem_kp = try cb.Kem.generate(.x25519_ml_kem_768);
    defer kem_kp.deinit();
    // Oversize the ciphertext buffer to absorb whatever exact length the
    // provider reports; assert it equals the draft-fixed SH key_share size.
    var ct: [tls13_full.x25519_mlkem768_sh_keyshare_len + 64]u8 = undefined;
    var ss_a: [64]u8 = undefined;
    const enc: cb.Kem.EncapResult = try cb.Kem.encapsulate(.x25519_ml_kem_768, &kem_kp, &ct, &ss_a);
    // The OpenSSL hybrid ciphertext IS the full 1120-byte ServerHello
    // key_share, and the combined shared secret is 64 bytes.
    try std.testing.expectEqual(tls13_full.x25519_mlkem768_sh_keyshare_len, enc.ct_len);
    try std.testing.expectEqual(@as(usize, 64), enc.ss_len);
    // The server key_share to put on the wire is exactly ct[0..enc.ct_len].
    const sh_keyshare = ct[0..enc.ct_len];
    try std.testing.expectEqual(@as(usize, 1120), sh_keyshare.len);
    // Decapsulate round-trips against the locally-owned keypair (the
    // client-side path the handshake actually uses).
    var ss_b: [64]u8 = undefined;
    const dn = try cb.Kem.decapsulate(.x25519_ml_kem_768, &kem_kp, ct[0..enc.ct_len], &ss_b);
    try std.testing.expectEqualSlices(u8, ss_a[0..enc.ss_len], ss_b[0..dn]);
}
