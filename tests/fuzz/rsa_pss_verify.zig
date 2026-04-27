// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// GAP-0109: Differential fuzz harness for RSA-PSS verification.
//
// PERF-237b (0.2.0): the harness used to drive both the SHA-256 entry
// point (`sig.rsa_pss_verify_sha256`) and the now-removed
// `parallel.verifyRsaPssWithHash`. After deleting `src/parallel.zig` we
// canonicalised on `sig.rsaPssVerifyGeneric`, so the differential
// comparison degenerated to a self-comparison. We keep the seed-corpus
// drivers because they remain a useful smoke test against accidental
// regressions in the SHA-256 / SHA-384 verify paths.
//
// Input layout (consumed from the seed corpus):
//   offset 0:           u8  hash_id   (0 = sha256, 1 = sha384)
//   offset 1:           u16 spki_len  (big-endian)
//   offset 3:           [spki_len] pubkey_spki_der
//   offset 3+spki_len:  u16 msg_len   (big-endian)
//   ...:                [msg_len]  msg
//   ...:                u16 sig_len   (big-endian)
//   ...:                [sig_len]  signature
//
// The harness tolerates short/malformed envelopes by bailing out — only
// crashes are flagged.
//
// NOTE on coverage-guided fuzzing: Zig 0.16.0's `std.testing.fuzz` triggers
// a stdlib compile error (`*builtin.StackTrace` vs `*debug.StackTrace` in
// `lib/compiler/test_runner.zig:566`) when invoked with `-ffuzz`. Until the
// upstream fix lands, this harness enumerates a committed seed corpus as a
// conventional test.

const std = @import("std");
const testing = std.testing;

const sigmod = @import("sig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;

/// Parsed fuzz envelope. All slices borrow from the caller-owned buffer.
const FuzzInput = struct {
    hash_id: u8,
    spki: []const u8,
    msg: []const u8,
    sig: []const u8,

    fn parse(bytes: []const u8) ?FuzzInput {
        if (bytes.len < 1 + 2) return null;
        const hash_id = bytes[0];
        if (hash_id > 1) return null;
        var off: usize = 1;

        if (off + 2 > bytes.len) return null;
        const spki_len = std.mem.readInt(u16, bytes[off..][0..2], .big);
        off += 2;
        if (off + spki_len > bytes.len) return null;
        const spki = bytes[off..][0..spki_len];
        off += spki_len;

        if (off + 2 > bytes.len) return null;
        const msg_len = std.mem.readInt(u16, bytes[off..][0..2], .big);
        off += 2;
        if (off + msg_len > bytes.len) return null;
        const msg = bytes[off..][0..msg_len];
        off += msg_len;

        if (off + 2 > bytes.len) return null;
        const sig_len = std.mem.readInt(u16, bytes[off..][0..2], .big);
        off += 2;
        if (off + sig_len > bytes.len) return null;
        const sig = bytes[off..][0..sig_len];

        return .{ .hash_id = hash_id, .spki = spki, .msg = msg, .sig = sig };
    }
};

/// Drive the canonical verifier for the parsed envelope and assert the
/// SHA-256 entry point and the generic helper agree (degenerate
/// equivalence after PERF-237b but kept as a smoke test).
fn smokeVerify(input: []const u8) !void {
    const parsed = FuzzInput.parse(input) orelse return; // malformed envelope; skip

    var alloc_buf: [16 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&alloc_buf);
    const alloc = fba.allocator();

    switch (parsed.hash_id) {
        0 => {
            fba.reset();
            const wrapper = sigmod.rsa_pss_verify_sha256(parsed.spki, parsed.msg, parsed.sig, 32, alloc) catch false;
            fba.reset();
            const generic = sigmod.rsaPssVerifyGeneric(Sha256, parsed.spki, parsed.msg, parsed.sig, alloc) catch false;
            if (wrapper != generic) return error.DifferentialDivergence;
        },
        1 => {
            fba.reset();
            _ = sigmod.rsaPssVerifyGeneric(Sha384, parsed.spki, parsed.msg, parsed.sig, alloc) catch return; // tolerate malformed
        },
        else => unreachable,
    }
}

// Seed corpus enumerated as an ordinary test (see NOTE at top of file).
test "rsa_pss verify (seed corpus)" {
    const seeds = [_][]const u8{
        @embedFile("corpus/rsa_pss/sha256_valid_2048.bin"),
        @embedFile("corpus/rsa_pss/sha256_valid_3072.bin"),
        @embedFile("corpus/rsa_pss/sha384_valid_2048.bin"),
        @embedFile("corpus/rsa_pss/sha384_valid_3072.bin"),
        @embedFile("corpus/rsa_pss/sha256_corrupt.bin"),
    };
    for (seeds) |seed| try smokeVerify(seed);
}

test "rsa_pss seed corpus: SHA-256 valid 2048 verifies" {
    const bytes = @embedFile("corpus/rsa_pss/sha256_valid_2048.bin");
    const parsed = FuzzInput.parse(bytes) orelse return error.MalformedSeed;
    try testing.expectEqual(@as(u8, 0), parsed.hash_id);

    var alloc_buf: [16 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&alloc_buf);
    const alloc = fba.allocator();

    const r = try sigmod.rsa_pss_verify_sha256(parsed.spki, parsed.msg, parsed.sig, 32, alloc);
    try testing.expect(r);
}

test "rsa_pss seed corpus: SHA-256 corrupt rejected" {
    const bytes = @embedFile("corpus/rsa_pss/sha256_corrupt.bin");
    const parsed = FuzzInput.parse(bytes) orelse return error.MalformedSeed;

    var alloc_buf: [16 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&alloc_buf);
    const alloc = fba.allocator();

    const r = try sigmod.rsa_pss_verify_sha256(parsed.spki, parsed.msg, parsed.sig, 32, alloc);
    try testing.expect(!r);
}

test "rsa_pss seed corpus: SHA-384 valid 2048 verifies via rsaPssVerifyGeneric" {
    const bytes = @embedFile("corpus/rsa_pss/sha384_valid_2048.bin");
    const parsed = FuzzInput.parse(bytes) orelse return error.MalformedSeed;
    try testing.expectEqual(@as(u8, 1), parsed.hash_id);

    var alloc_buf: [16 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&alloc_buf);
    const alloc = fba.allocator();

    const r = try sigmod.rsaPssVerifyGeneric(Sha384, parsed.spki, parsed.msg, parsed.sig, alloc);
    try testing.expect(r);
}
