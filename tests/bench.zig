// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! PERF-011: Minimal benchmark harness for TLS 1.3 handshake performance.
//!
//! Run with: zig build bench -Doptimize=ReleaseFast
//!
//! This benchmark measures key schedule derivation, transcript hashing,
//! and AEAD operations. Expand with full handshake benchmarks as needed.

const std = @import("std");
const ks = @import("quic_tls");
const record = @import("record");

const Sha256 = std.crypto.hash.sha2.Sha256;

/// Simple timer-based benchmark runner.
fn benchmarkFn(comptime name: []const u8, comptime iterations: u32, func: anytype) void {
    var timer = std.time.Timer.start() catch {
        std.debug.print("[bench] {s}: timer unavailable, skipping\n", .{name});
        return;
    };
    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        func();
    }
    const elapsed_ns = timer.read();
    const per_op_ns = elapsed_ns / iterations;
    std.debug.print("[bench] {s}: {d} iterations, {d}ns total, {d}ns/op\n", .{
        name,
        iterations,
        elapsed_ns,
        per_op_ns,
    });
}

/// Benchmark: HKDF-Extract + HKDF-Expand-Label (key derivation hot path).
fn benchKeyDerivation() void {
    const ikm = [_]u8{0xAB} ** 32;
    const salt = [_]u8{0x00} ** 32;
    const secret = ks.extractHash(.sha256, &salt, &ikm);
    var out: [32]u8 = undefined;
    // expandLabelHash may fail only on fixed-buffer overflow which cannot happen
    // at 32 bytes output.
    ks.expandLabelHash(.sha256, &secret, "derived", &[_]u8{}, &out) catch {};
    std.mem.doNotOptimizeAway(&out);
}

/// Benchmark: SHA-256 transcript hash update + finalize.
fn benchTranscriptHash() void {
    var hasher = Sha256.init(.{});
    // Simulate a realistic handshake message (~300 bytes)
    const msg = [_]u8{0x42} ** 300;
    hasher.update(&msg);
    var digest: [Sha256.digest_length]u8 = undefined;
    // Clone before finalize to simulate non-consuming snapshot
    var tmp = hasher;
    tmp.final(&digest);
    std.mem.doNotOptimizeAway(&digest);
}

/// Benchmark: AEAD seal operation (AES-128-GCM).
fn benchAeadSeal() void {
    const key = [_]u8{0x01} ** 16;
    const iv = [_]u8{0x02} ** 12;
    var cipher = record.AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null) catch return;
    var plaintext = [_]u8{0x03} ** 128;
    var out: [128 + 16]u8 = undefined; // plaintext + tag
    const aad = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x90 }; // TLS record header
    cipher.sealBuf(&out, 0, &aad, &plaintext) catch return;
    std.mem.doNotOptimizeAway(&out);
}

pub fn main() void {
    std.debug.print("=== TLS 1.3 Performance Benchmarks ===\n", .{});
    std.debug.print("Build mode: {s}\n\n", .{@tagName(@import("builtin").mode)});

    benchmarkFn("key_derivation (HKDF-Extract+Expand)", 10_000, benchKeyDerivation);
    benchmarkFn("transcript_hash (SHA-256 update+finalize)", 10_000, benchTranscriptHash);
    benchmarkFn("aead_seal (AES-128-GCM 128B)", 10_000, benchAeadSeal);

    std.debug.print("\n=== Benchmark Complete ===\n", .{});
}
