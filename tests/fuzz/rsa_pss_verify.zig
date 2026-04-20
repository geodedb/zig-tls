// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// GAP-0109: Differential fuzz harness for RSA-PSS verification.
//
// Drives both `sig.rsa_pss_verify_sha256` (TLS 1.3 CertificateVerify path)
// and `parallel.verifyRsaPssWithHash` (parallel-verify path) with identical
// inputs and asserts that they produce byte-equivalent verdicts. Establishes
// the empirical oracle required before canonicalizing both implementations
// onto a shared `sig.rsaPssVerifyGeneric` core.
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
// The harness tolerates short/malformed envelopes by bailing out — the only
// failure mode it cares about is `DifferentialDivergence`, meaning the two
// verifiers disagreed on a well-formed triple.
//
// NOTE on coverage-guided fuzzing: Zig 0.16.0's `std.testing.fuzz` triggers
// a stdlib compile error (`*builtin.StackTrace` vs `*debug.StackTrace` in
// `lib/compiler/test_runner.zig:566`) when invoked with `-ffuzz`. Until the
// upstream fix lands, this harness enumerates a committed seed corpus as a
// conventional test. When `std.testing.fuzz` is functional, wrap the
// `differentialVerify` call in a `std.testing.fuzz({}, ...)` block and gate
// the CI job on `zig build fuzz-rsa-pss --fuzz -- --duration 60`.

const std = @import("std");
const testing = std.testing;

const sigmod = @import("sig");
const parallel = @import("parallel");

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

/// Drive both verifiers with the same input and assert byte-equivalent
/// results. The `sig.zig` entry point only covers SHA-256 today, so for
/// SHA-384 envelopes we only sanity-check that the parallel path does not
/// crash — divergence is only flagged when both paths have coverage.
fn differentialVerify(input: []const u8) !void {
    const parsed = FuzzInput.parse(input) orelse return; // malformed envelope; skip

    var alloc_buf: [16 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&alloc_buf);
    const alloc = fba.allocator();

    // sig.zig path — SHA-256 only; salt length is ignored by the implementation.
    const sig_result: ?bool = blk: {
        if (parsed.hash_id != 0) break :blk null;
        fba.reset();
        const r = sigmod.rsa_pss_verify_sha256(parsed.spki, parsed.msg, parsed.sig, 32, alloc) catch {
            break :blk false;
        };
        break :blk r;
    };

    // parallel.zig path — comptime-generic over the hash type.
    fba.reset();
    const parallel_in = parallel.SignatureVerifyInput{
        .algorithm = switch (parsed.hash_id) {
            0 => .rsa_pss_rsae_sha256,
            1 => .rsa_pss_rsae_sha384,
            else => unreachable,
        },
        .public_key_der = parsed.spki,
        .signed_data = parsed.msg,
        .signature = parsed.sig,
    };
    const parallel_res = switch (parsed.hash_id) {
        0 => parallel.verifyRsaPssWithHash(Sha256, parallel_in, alloc),
        1 => parallel.verifyRsaPssWithHash(Sha384, parallel_in, alloc),
        else => unreachable,
    };

    // SHA-256 path: both verifiers MUST agree.
    if (sig_result) |sr| {
        if (sr != parallel_res.valid) {
            std.debug.print(
                "GAP-0109: RSA-PSS verifiers diverged: sig={}, parallel={}, hash_id={}, spki_len={}, msg_len={}, sig_len={}\n",
                .{ sr, parallel_res.valid, parsed.hash_id, parsed.spki.len, parsed.msg.len, parsed.sig.len },
            );
            return error.DifferentialDivergence;
        }
    }
}

// Seed corpus enumerated as an ordinary test (see NOTE at top of file).
test "rsa_pss differential fuzz (seed corpus)" {
    const seeds = [_][]const u8{
        @embedFile("corpus/rsa_pss/sha256_valid_2048.bin"),
        @embedFile("corpus/rsa_pss/sha256_valid_3072.bin"),
        @embedFile("corpus/rsa_pss/sha384_valid_2048.bin"),
        @embedFile("corpus/rsa_pss/sha384_valid_3072.bin"),
        @embedFile("corpus/rsa_pss/sha256_corrupt.bin"),
    };
    for (seeds) |seed| try differentialVerify(seed);
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

test "rsa_pss seed corpus: SHA-384 valid 2048 verifies via parallel" {
    const bytes = @embedFile("corpus/rsa_pss/sha384_valid_2048.bin");
    const parsed = FuzzInput.parse(bytes) orelse return error.MalformedSeed;
    try testing.expectEqual(@as(u8, 1), parsed.hash_id);

    var alloc_buf: [16 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&alloc_buf);
    const alloc = fba.allocator();

    const in = parallel.SignatureVerifyInput{
        .algorithm = .rsa_pss_rsae_sha384,
        .public_key_der = parsed.spki,
        .signed_data = parsed.msg,
        .signature = parsed.sig,
    };
    const r = parallel.verifyRsaPssWithHash(Sha384, in, alloc);
    try testing.expect(r.valid);
}
