//! RFC 9001 §6: QUIC Key Update Tests (GAP-0121 part 2)
//!
//! §6 layers QUIC's implicit key-phase-bit key update on top of RFC
//! 8446 §7.2's "traffic upd" label, using the QUIC-specific
//! "quic ku" label for the subsequent HKDF-Expand-Label derivation.
//!
//! This file pins the QUIC-specific wiring: that `expandLabelHash`
//! with label "quic ku" is reachable and produces a deterministic
//! output of the correct length.

const std = @import("std");
const ks = @import("quic_tls");

test "RFC 9001 §6: quic ku label derives a digest-length secret" {
    var seed_bytes: [32]u8 = [_]u8{0} ** 32;
    var secret = ks.Secret.fromSlice(.sha256, &seed_bytes);

    var out: [32]u8 = undefined;
    try ks.expandLabelHash(.sha256, &secret, "quic ku", &[_]u8{}, &out);

    // Derivation must not equal the input.
    try std.testing.expect(!std.mem.eql(u8, &seed_bytes, &out));

    // And re-deriving with the same input must produce the same output.
    var out2: [32]u8 = undefined;
    try ks.expandLabelHash(.sha256, &secret, "quic ku", &[_]u8{}, &out2);
    try std.testing.expectEqualSlices(u8, &out, &out2);
}
