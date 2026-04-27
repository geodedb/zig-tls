// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! PERF-011 / PERF-029: Performance benchmark harness for TLS 1.3 operations.
//!
//! Run with: zig build bench -Doptimize=ReleaseFast
//!
//! Benchmarks cover the hot paths in a TLS 1.3 handshake:
//! - Key schedule derivation (HKDF)
//! - Transcript hashing (SHA-256)
//! - AEAD seal and open (AES-128-GCM, ChaCha20-Poly1305)
//! - X.509 certificate DER parsing (parseCert)
//! - Signature verification (Ed25519, ECDSA-P256)
//! - ClientHello wire-format parsing (parseClientHello)
//! - Server flight handshake message encoding

const std = @import("std");
const ks = @import("quic_tls");
const record = @import("record");
const x509 = @import("x509");
const sig = @import("sig");
const tls13_full = @import("tls13_full");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Ed25519 = std.crypto.sign.Ed25519;

/// Monotonic-nanosecond wall reader. Zig 0.16 removed `std.time.Timer` and
/// `std.time.Instant` in favor of `std.Io.Clock`, which requires an `Io`
/// instance. For a standalone benchmark we go one layer lower and read
/// `CLOCK_MONOTONIC` directly via `std.posix.system.clock_gettime`, which
/// is what the new `Io.Threaded` backend ultimately calls on POSIX anyway.
fn nowMonotonicNs() ?u64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.system.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts) != 0) return null;
    const sec_ns = @as(u64, @intCast(ts.sec)) * std.time.ns_per_s;
    return sec_ns + @as(u64, @intCast(ts.nsec));
}

/// PERF-223: Warmup iterations executed before timing begins. The first few
/// calls pay cold-cache/branch-predictor costs that distort the reported
/// mean and percentiles; discarding them stabilizes readings across runs.
const warmup_iters: u32 = 3;

/// PERF-223: Maximum per-sample buffer size for p50/p95 computation. Benches
/// with higher iteration counts still run all iterations; only the first
/// `max_samples` are retained for percentile reporting. Keeps stack usage
/// bounded while preserving statistical validity for iteration counts
/// <= 10_000 (which is the maximum currently used by any bench in main()).
const max_samples: usize = 10_000;

/// Compiler memory barrier. Zig 0.16 removed both `@fence` and
/// `std.atomic.fence`; inline asm with a memory clobber is the remaining
/// portable way to prevent the optimizer from reordering benchmarked work
/// across the timer reads. Without this the compiler is free to hoist
/// `func()` above the `t0` read or sink it below `t1`, producing near-zero
/// sample times. A full hardware barrier is not required on x86-64 (TSO),
/// but we still want the compiler barrier on every architecture.
inline fn perfFence() void {
    asm volatile ("" ::: .{ .memory = true });
}

/// PERF-258: collected benchmark results — populated by `benchmarkFn` and
/// either rendered to stdout (default) or serialized to JSON / compared
/// against a committed baseline by `main`. The static array avoids any
/// allocator dependency in the hot path; 64 slots is comfortably above
/// every current bench (~25) plus the PERF-256 size sweep.
const BenchSample = struct {
    name: []const u8,
    iterations: u32,
    sampled: usize,
    elapsed_ns: u64,
    mean_ns: u64,
    p50_ns: u64,
    p95_ns: u64,
    /// Optional throughput in GB/s (PERF-256). Only the AEAD size-sweep
    /// benches set this; nullable to keep the schema uniform.
    throughput_gbps: ?f64 = null,
    /// Optional payload size in bytes (PERF-256). Set alongside
    /// `throughput_gbps` for AEAD size-sweep benches.
    payload_bytes: ?usize = null,
};

var bench_samples: [64]BenchSample = undefined;
var bench_sample_count: usize = 0;

fn recordSample(s: BenchSample) void {
    if (bench_sample_count >= bench_samples.len) return;
    bench_samples[bench_sample_count] = s;
    bench_sample_count += 1;
}

/// PERF-223: Per-iteration timer-based benchmark runner with warmup, memory
/// fences, and p50/p95 reporting.
///
/// Each iteration is timed individually so percentiles are meaningful. The
/// first `warmup_iters` samples are discarded. Samples are sorted and p50
/// (median) and p95 are reported alongside mean/total. A `seq_cst` fence
/// surrounds each timer read to prevent reordering.
fn benchmarkFn(comptime name: []const u8, comptime iterations: u32, func: anytype) void {
    // Warmup: pay cold-cache costs without recording samples.
    {
        var w: u32 = 0;
        while (w < warmup_iters) : (w += 1) func();
    }

    const sample_count: usize = @min(@as(usize, iterations), max_samples);
    var samples: [max_samples]u64 = undefined;

    const start_ns = nowMonotonicNs() orelse {
        std.debug.print("[bench] {s}: timer unavailable, skipping\n", .{name});
        return;
    };

    var i: u32 = 0;
    var recorded: usize = 0;
    while (i < iterations) : (i += 1) {
        if (recorded < sample_count) {
            perfFence();
            const t0 = nowMonotonicNs() orelse {
                std.debug.print("[bench] {s}: timer unavailable mid-run, skipping\n", .{name});
                return;
            };
            perfFence();
            func();
            perfFence();
            const t1 = nowMonotonicNs() orelse {
                std.debug.print("[bench] {s}: timer unavailable mid-run, skipping\n", .{name});
                return;
            };
            perfFence();
            samples[recorded] = if (t1 >= t0) (t1 - t0) else 0;
            recorded += 1;
        } else {
            func();
        }
    }

    const end_ns = nowMonotonicNs() orelse {
        std.debug.print("[bench] {s}: timer unavailable mid-run, skipping\n", .{name});
        return;
    };
    const elapsed_ns = end_ns - start_ns;
    const per_op_ns = elapsed_ns / iterations;

    // Sort recorded samples for percentile extraction.
    std.mem.sort(u64, samples[0..recorded], {}, std.sort.asc(u64));
    const p50: u64 = if (recorded == 0) 0 else samples[recorded / 2];
    const p95: u64 = if (recorded == 0) 0 else blk: {
        const idx = (recorded * 95) / 100;
        break :blk samples[if (idx >= recorded) recorded - 1 else idx];
    };

    std.debug.print(
        "[bench] {s}: {d} iters (warmup {d}, sampled {d}), {d}ns total, mean {d}ns/op, p50 {d}ns, p95 {d}ns\n",
        .{ name, iterations, warmup_iters, recorded, elapsed_ns, per_op_ns, p50, p95 },
    );

    recordSample(.{
        .name = name,
        .iterations = iterations,
        .sampled = recorded,
        .elapsed_ns = elapsed_ns,
        .mean_ns = per_op_ns,
        .p50_ns = p50,
        .p95_ns = p95,
    });
}

/// PERF-258 / PERF-256: like `benchmarkFn` but tags the sample with the
/// payload size and computes derived GB/s throughput. Used by the AEAD
/// size-sweep benchmarks introduced for PERF-256.
fn benchmarkThroughputFn(
    comptime name: []const u8,
    comptime iterations: u32,
    payload_bytes: usize,
    func: anytype,
) void {
    const before = bench_sample_count;
    benchmarkFn(name, iterations, func);
    if (bench_sample_count <= before) return;
    var s = &bench_samples[bench_sample_count - 1];
    s.payload_bytes = payload_bytes;
    if (s.mean_ns > 0) {
        const bytes_per_sec = @as(f64, @floatFromInt(payload_bytes)) /
            (@as(f64, @floatFromInt(s.mean_ns)) / 1_000_000_000.0);
        s.throughput_gbps = bytes_per_sec / 1_000_000_000.0;
        std.debug.print(
            "[bench]   ({s}: {d} bytes/op, {d:.3} GB/s)\n",
            .{ name, payload_bytes, s.throughput_gbps.? },
        );
    }
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

// ============================================================================
// PERF-029: Additional critical benchmarks
// ============================================================================

/// Benchmark: AEAD open/decrypt operation (AES-128-GCM).
///
/// PERF-029: Measures the decrypt path alongside the existing seal benchmark.
/// Uses pre-sealed ciphertext to isolate decryption cost.
fn benchAeadOpen() void {
    const key = [_]u8{0x01} ** 16;
    const iv = [_]u8{0x02} ** 12;

    // Pre-seal a ciphertext that we will repeatedly decrypt
    var seal_cipher = record.AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null) catch return;
    var plaintext = [_]u8{0x03} ** 128;
    var ciphertext: [128 + 16]u8 = undefined;
    const aad = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x90 };
    seal_cipher.sealBuf(&ciphertext, 0, &aad, &plaintext) catch return;

    // Now benchmark the open path
    var open_cipher = record.AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null) catch return;
    var decrypted: [128]u8 = undefined;
    open_cipher.openBuf(&decrypted, 0, &aad, &ciphertext) catch return;
    std.mem.doNotOptimizeAway(&decrypted);
}

/// Benchmark: AEAD open/decrypt operation (ChaCha20-Poly1305).
///
/// PERF-029: ChaCha20-Poly1305 is preferred on platforms without AES-NI
/// hardware acceleration. Benchmarking both ciphers reveals platform-
/// dependent performance characteristics.
fn benchAeadOpenChacha() void {
    const key = [_]u8{0x01} ** 32;
    const iv = [_]u8{0x02} ** 12;

    var seal_cipher = record.AeadCipher.init(.TLS_CHACHA20_POLY1305_SHA256, &key, &iv, null) catch return;
    var plaintext = [_]u8{0x03} ** 128;
    var ciphertext: [128 + 16]u8 = undefined;
    const aad = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x90 };
    seal_cipher.sealBuf(&ciphertext, 0, &aad, &plaintext) catch return;

    var open_cipher = record.AeadCipher.init(.TLS_CHACHA20_POLY1305_SHA256, &key, &iv, null) catch return;
    var decrypted: [128]u8 = undefined;
    open_cipher.openBuf(&decrypted, 0, &aad, &ciphertext) catch return;
    std.mem.doNotOptimizeAway(&decrypted);
}

/// Benchmark: X.509 certificate parsing (parseCert).
///
/// PERF-029: Measures the cost of parsing a DER-encoded leaf certificate,
/// which is a hot path during certificate chain validation.
fn benchCertParse() void {
    const cert_der = @embedFile("test_certs/leaf_cert.der");
    const alloc = std.heap.page_allocator;
    const cert = x509.parseCert(alloc, cert_der) catch return;
    cert.deinit(alloc);
    std.mem.doNotOptimizeAway(&cert);
}

/// Benchmark: Ed25519 signature verification.
///
/// PERF-029: Measures raw Ed25519 verify cost using a deterministic keypair.
/// This is the core operation in CertificateVerify processing for Ed25519 certs.
fn benchEd25519Verify() void {
    // Use a deterministic seed for reproducible benchmarking
    const seed: [32]u8 = [_]u8{0x42} ** 32;
    const kp = Ed25519.KeyPair.generateDeterministic(seed) catch return;

    // Build a realistic-length message (TLS CertificateVerify signed content ~130 bytes)
    // 64 spaces + context string + 0x00 separator + 32-byte transcript hash
    const msg = comptime blk: {
        var buf: [130]u8 = undefined;
        var pos: usize = 0;
        // 64 spaces (TLS 1.3 context padding)
        for (0..64) |j| {
            buf[j] = 0x20;
        }
        pos = 64;
        // context string "TLS 1.3, server CertificateVerify"
        const ctx = "TLS 1.3, server CertificateVerify";
        for (ctx, 0..) |c, j| buf[pos + j] = c;
        pos += ctx.len;
        // 0x00 separator
        buf[pos] = 0x00;
        pos += 1;
        // 32-byte transcript hash
        for (0..32) |j| buf[pos + j] = 0xAA;
        pos += 32;
        break :blk buf[0..pos].*;
    };
    const message: []const u8 = &msg;
    const signature = kp.sign(message, null) catch return;

    // Benchmark the verify operation
    signature.verify(message, kp.public_key) catch {};
    std.mem.doNotOptimizeAway(&signature);
}

/// Benchmark: ECDSA-P256/SHA-256 signature verification.
///
/// PERF-029: Measures ECDSA verify cost which is the most common signature
/// algorithm for certificate chain validation (ecdsa_secp256r1_sha256).
fn benchEcdsaP256Verify() void {
    const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P256, Sha256);

    // Deterministic seed for reproducible key pair
    const seed: [32]u8 = [_]u8{0x37} ** 32;
    const secret_key = Ecdsa.SecretKey.fromBytes(seed) catch return;
    const key_pair = Ecdsa.KeyPair.fromSecretKey(secret_key) catch return;

    // Simulated TBSCertificate content (~256 bytes, typical cert body size)
    const message: []const u8 = &([_]u8{0xBB} ** 256);
    const signature = key_pair.sign(message, null) catch return;

    signature.verify(message, key_pair.public_key) catch {};
    std.mem.doNotOptimizeAway(&signature);
}

/// Benchmark: ClientHello parsing (parseClientHello).
///
/// PERF-029: Measures parsing of a realistic ClientHello message with
/// standard extensions (supported_versions, key_share, cipher_suites,
/// signature_algorithms, ALPN, supported_groups).
fn benchClientHelloParse() void {
    // Realistic ClientHello with TLS 1.3 extensions:
    // - legacy_version: 0x0303
    // - random: 32 bytes
    // - session_id: empty
    // - cipher_suites: TLS_AES_128_GCM_SHA256
    // - compression: null
    // - extensions: supported_versions (TLS 1.3), key_share (X25519),
    //   signature_algorithms (ecdsa_secp256r1_sha256), supported_groups (x25519)
    const client_hello_bytes = comptime blk: {
        var buf: [256]u8 = undefined;
        var pos: usize = 0;
        // legacy_version
        buf[pos] = 0x03;
        buf[pos + 1] = 0x03;
        pos += 2;
        // random (32 bytes)
        for (0..32) |j| buf[pos + j] = @intCast(j);
        pos += 32;
        // session_id length = 0
        buf[pos] = 0x00;
        pos += 1;
        // cipher_suites: length=2, TLS_AES_128_GCM_SHA256
        buf[pos] = 0x00;
        buf[pos + 1] = 0x02;
        buf[pos + 2] = 0x13;
        buf[pos + 3] = 0x01;
        pos += 4;
        // compression_methods: length=1, null
        buf[pos] = 0x01;
        buf[pos + 1] = 0x00;
        pos += 2;
        // extensions
        const ext_start = pos;
        pos += 2; // placeholder for extensions length
        // supported_versions: type=0x002b, length=3, list_len=2, 0x0304
        const sv = [_]u8{ 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04 };
        for (sv, 0..) |b, j| buf[pos + j] = b;
        pos += sv.len;
        // supported_groups: type=0x000a, length=4, list_len=2, x25519=0x001d
        const sg = [_]u8{ 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d };
        for (sg, 0..) |b, j| buf[pos + j] = b;
        pos += sg.len;
        // signature_algorithms: type=0x000d, length=4, list_len=2, ecdsa_secp256r1_sha256=0x0403
        const sa = [_]u8{ 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03 };
        for (sa, 0..) |b, j| buf[pos + j] = b;
        pos += sa.len;
        // key_share: type=0x0033
        const ks_hdr = [_]u8{ 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20 };
        for (ks_hdr, 0..) |b, j| buf[pos + j] = b;
        pos += ks_hdr.len;
        // key_share data: 32 bytes of X25519 pubkey
        for (0..32) |j| buf[pos + j] = @intCast((j + 0x80) & 0xff);
        pos += 32;
        // Fill in extensions length
        const ext_len: u16 = @intCast(pos - ext_start - 2);
        buf[ext_start] = @intCast(ext_len >> 8);
        buf[ext_start + 1] = @intCast(ext_len & 0xff);
        break :blk buf[0..pos].*;
    };
    const alloc = std.heap.page_allocator;
    const ch = tls13_full.parseClientHello(alloc, &client_hello_bytes) catch return;
    // Free allocated fields
    if (ch.cipher_suites.len != 0) alloc.free(ch.cipher_suites);
    if (ch.supported_groups) |groups| if (groups.len != 0) alloc.free(groups);
    if (ch.signature_algorithms) |algs| if (algs.len != 0) alloc.free(algs);
    if (ch.alpn_list) |list| if (list.len != 0) alloc.free(list);
    if (ch.pre_shared_key) |psk| {
        if (psk.identities.len != 0) alloc.free(psk.identities);
        if (psk.binders.len != 0) alloc.free(psk.binders);
    }
    std.mem.doNotOptimizeAway(&ch);
}

/// Benchmark: Certificate chain validation (parseCert + chain walk).
///
/// PERF-029: Measures the cost of parsing and validating a 2-cert chain
/// (leaf + root), which is the typical hot path for server certificate
/// verification during the TLS handshake.
fn benchCertChainValidation() void {
    const leaf_der = @embedFile("test_certs/leaf_cert.der");
    const root_der = @embedFile("test_certs/root_cert.der");
    const alloc = std.heap.page_allocator;
    // Parse both certs (simulates the chain validation parse phase)
    const leaf = x509.parseCert(alloc, leaf_der) catch return;
    defer leaf.deinit(alloc);
    const root = x509.parseCert(alloc, root_der) catch return;
    defer root.deinit(alloc);
    std.mem.doNotOptimizeAway(&leaf);
    std.mem.doNotOptimizeAway(&root);
}

/// Benchmark: Server flight handshake message encoding.
///
/// PERF-029: Measures the cost of encoding a full server flight into a
/// contiguous buffer. Each message gets a 4-byte handshake header (1-byte
/// type + 3-byte big-endian length) followed by the body. This mirrors
/// encodeHandshakeBuf from messages.zig. Uses realistic body sizes:
///   ServerHello:          ~70 bytes
///   EncryptedExtensions:  ~40 bytes
///   Certificate:          ~800 bytes (single leaf cert)
///   CertificateVerify:    ~80 bytes (signature)
///   Finished:             ~32 bytes (verify_data)
fn benchServerFlightEncode() void {
    var buf: [2048]u8 = undefined;
    var total: usize = 0;

    // Handshake type codes from RFC 8446 §4
    const messages = [_]struct { hs_type: u8, size: usize }{
        .{ .hs_type = 2, .size = 70 }, // server_hello
        .{ .hs_type = 8, .size = 40 }, // encrypted_extensions
        .{ .hs_type = 11, .size = 800 }, // certificate
        .{ .hs_type = 15, .size = 80 }, // certificate_verify
        .{ .hs_type = 20, .size = 32 }, // finished
    };

    for (messages) |m| {
        if (total + 4 + m.size > buf.len) return;
        // Handshake header: 1-byte type + 3-byte big-endian length
        buf[total] = m.hs_type;
        buf[total + 1] = @intCast((m.size >> 16) & 0xFF);
        buf[total + 2] = @intCast((m.size >> 8) & 0xFF);
        buf[total + 3] = @intCast(m.size & 0xFF);
        // Fill body with pattern to prevent dead-code elimination
        @memset(buf[total + 4 ..][0..m.size], 0x42);
        total += 4 + m.size;
    }
    std.mem.doNotOptimizeAway(&buf);
    std.mem.doNotOptimizeAway(&total);
}

// ============================================================================
// PERF-213 / PERF-221 / PERF-222: Deep-chain NameConstraints accumulation.
//
// x509.runChainChecks() walks every certificate in the chain and, for each
// position, re-accumulates permitted/excluded DNS constraint slices from all
// issuers above it. Pre-fix: two ArrayLists per cert (O(N) allocs total,
// O(N^2) append-ops across the chain). Post-fix: a single pair of
// ArrayLists reused across positions with clearRetainingCapacity() and a
// single ensureTotalCapacity() pre-pass. These benches exercise the same
// allocation/append/compare shape so wall-time deltas reflect the win.
// ============================================================================

fn benchNameConstraintsDepth(alloc: std.mem.Allocator, depth: usize) void {
    const permitted_pool = [_][]const u8{
        ".example.com",
        ".foo.example.com",
        ".bar.example.com",
        ".baz.example.com",
    };
    const excluded_pool = [_][]const u8{
        ".forbidden.example.com",
        ".blocked.example.com",
        ".denied.example.com",
        ".nogo.example.com",
    };
    const leaf_sans = [_][]const u8{ "www.example.com", "api.example.com" };

    // Mirror of x509.zig:1676-1722: outer loop over every cert in the chain,
    // inner loop over every issuer above it.
    var cert_idx: usize = 0;
    while (cert_idx < depth) : (cert_idx += 1) {
        var accumulated_permitted = std.ArrayList([]const u8).initCapacity(alloc, 4) catch return;
        defer accumulated_permitted.deinit(alloc);
        var accumulated_excluded = std.ArrayList([]const u8).initCapacity(alloc, 4) catch return;
        defer accumulated_excluded.deinit(alloc);

        var issuer_idx = cert_idx + 1;
        while (issuer_idx < depth) : (issuer_idx += 1) {
            for (permitted_pool) |p| accumulated_permitted.append(alloc, p) catch return;
            for (excluded_pool) |e| accumulated_excluded.append(alloc, e) catch return;
        }

        if (accumulated_permitted.items.len > 0 or accumulated_excluded.items.len > 0) {
            const constraints = x509.NameConstraints{
                .permitted_dns = accumulated_permitted.items,
                .excluded_dns = accumulated_excluded.items,
            };
            for (leaf_sans) |dns_name| {
                const ok = x509.checkNameConstraints(dns_name, constraints);
                std.mem.doNotOptimizeAway(&ok);
            }
        }
    }
}

fn benchNameConstraintsDepth5() void {
    benchNameConstraintsDepth(std.heap.page_allocator, 5);
}

fn benchNameConstraintsDepth10() void {
    benchNameConstraintsDepth(std.heap.page_allocator, 10);
}

// ============================================================================
// PERF-256: AEAD throughput size-sweep benchmarks.
//
// Measures AEAD seal/open at realistic record sizes {128, 1024, 4096, 16384}
// for AES-128-GCM and ChaCha20-Poly1305. The 16 KB measurement is the SLO
// gate (AES-128-GCM ≥ 3 GB/s with `-Dcpu=native`).
// ============================================================================

fn aeadSealAes(comptime size: usize) fn () void {
    return struct {
        fn run() void {
            const key = [_]u8{0x01} ** 16;
            const iv = [_]u8{0x02} ** 12;
            var cipher = record.AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null) catch return;
            var plaintext = [_]u8{0x03} ** size;
            var out: [size + 16]u8 = undefined;
            const aad = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x90 };
            cipher.sealBuf(&out, 0, &aad, &plaintext) catch return;
            std.mem.doNotOptimizeAway(&out);
        }
    }.run;
}

fn aeadOpenAes(comptime size: usize) fn () void {
    return struct {
        fn run() void {
            const key = [_]u8{0x01} ** 16;
            const iv = [_]u8{0x02} ** 12;
            var seal_cipher = record.AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null) catch return;
            var plaintext = [_]u8{0x03} ** size;
            var ciphertext: [size + 16]u8 = undefined;
            const aad = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x90 };
            seal_cipher.sealBuf(&ciphertext, 0, &aad, &plaintext) catch return;
            var open_cipher = record.AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null) catch return;
            var decrypted: [size]u8 = undefined;
            open_cipher.openBuf(&decrypted, 0, &aad, &ciphertext) catch return;
            std.mem.doNotOptimizeAway(&decrypted);
        }
    }.run;
}

fn aeadSealChacha(comptime size: usize) fn () void {
    return struct {
        fn run() void {
            const key = [_]u8{0x01} ** 32;
            const iv = [_]u8{0x02} ** 12;
            var cipher = record.AeadCipher.init(.TLS_CHACHA20_POLY1305_SHA256, &key, &iv, null) catch return;
            var plaintext = [_]u8{0x03} ** size;
            var out: [size + 16]u8 = undefined;
            const aad = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x90 };
            cipher.sealBuf(&out, 0, &aad, &plaintext) catch return;
            std.mem.doNotOptimizeAway(&out);
        }
    }.run;
}

// ============================================================================
// PERF-258: JSON emission, baseline comparison, and CLI argument handling.
// ============================================================================

const tolerance_pct: f64 = 0.10;

const BaselineEntry = struct {
    name: []const u8,
    mean_ns: u64,
};

fn appendFmt(out: *std.ArrayList(u8), gpa: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    const tmp = try std.fmt.allocPrint(gpa, fmt, args);
    defer gpa.free(tmp);
    try out.appendSlice(gpa, tmp);
}

fn renderJsonResults(gpa: std.mem.Allocator) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, "{\n");
    try out.appendSlice(gpa, "  \"version\": \"1\",\n");
    try appendFmt(&out, gpa, "  \"build_mode\": \"{s}\",\n", .{@tagName(@import("builtin").mode)});
    try out.appendSlice(gpa, "  \"tolerance_pct\": 0.10,\n");
    try out.appendSlice(gpa, "  \"results\": [\n");
    var i: usize = 0;
    while (i < bench_sample_count) : (i += 1) {
        const s = bench_samples[i];
        try out.appendSlice(gpa, "    {\n");
        try appendFmt(&out, gpa, "      \"name\": \"{s}\",\n", .{s.name});
        try appendFmt(&out, gpa, "      \"iterations\": {d},\n", .{s.iterations});
        try appendFmt(&out, gpa, "      \"sampled\": {d},\n", .{s.sampled});
        try appendFmt(&out, gpa, "      \"elapsed_ns\": {d},\n", .{s.elapsed_ns});
        try appendFmt(&out, gpa, "      \"mean_ns\": {d},\n", .{s.mean_ns});
        try appendFmt(&out, gpa, "      \"p50_ns\": {d},\n", .{s.p50_ns});
        try appendFmt(&out, gpa, "      \"p95_ns\": {d}", .{s.p95_ns});
        if (s.throughput_gbps) |gb| {
            try appendFmt(&out, gpa, ",\n      \"throughput_gbps\": {d:.6}", .{gb});
        }
        if (s.payload_bytes) |pb| {
            try appendFmt(&out, gpa, ",\n      \"payload_bytes\": {d}", .{pb});
        }
        try out.appendSlice(gpa, "\n    }");
        if (i + 1 < bench_sample_count) try out.appendSlice(gpa, ",");
        try out.appendSlice(gpa, "\n");
    }
    try out.appendSlice(gpa, "  ]\n}\n");
    return try out.toOwnedSlice(gpa);
}

/// Minimal scanner that extracts (name, mean_ns) pairs from a baseline JSON
/// produced by `writeJsonResults`. Keeps the bench self-contained — no
/// `std.json` dependency, and no allocator beyond a fixed scratch arena.
fn parseBaseline(alloc: std.mem.Allocator, content: []const u8, out: []BaselineEntry) !usize {
    var count: usize = 0;
    var pos: usize = 0;
    while (pos < content.len) {
        const name_marker = "\"name\":";
        const name_start = std.mem.indexOfPos(u8, content, pos, name_marker) orelse break;
        const q1 = std.mem.indexOfScalarPos(u8, content, name_start + name_marker.len, '"') orelse break;
        const q2 = std.mem.indexOfScalarPos(u8, content, q1 + 1, '"') orelse break;
        const name_slice = content[q1 + 1 .. q2];

        const mean_marker = "\"mean_ns\":";
        const mean_start = std.mem.indexOfPos(u8, content, q2, mean_marker) orelse break;
        var num_pos = mean_start + mean_marker.len;
        while (num_pos < content.len and (content[num_pos] == ' ' or content[num_pos] == '\t')) : (num_pos += 1) {}
        var num_end = num_pos;
        while (num_end < content.len and content[num_end] >= '0' and content[num_end] <= '9') : (num_end += 1) {}
        if (num_end == num_pos) break;
        const mean_ns = try std.fmt.parseInt(u64, content[num_pos..num_end], 10);

        if (count >= out.len) return count;
        out[count] = .{
            .name = try alloc.dupe(u8, name_slice),
            .mean_ns = mean_ns,
        };
        count += 1;
        pos = num_end;
    }
    return count;
}

/// Compare current `bench_samples` against the baseline at `path`. Returns
/// `true` iff every paired sample is within `tolerance_pct` of its baseline
/// mean. Emits a per-row report on stdout regardless. Names that exist only
/// in the baseline are flagged as missing; samples without a matching
/// baseline entry are flagged as unknown but do not fail the gate.
fn compareAgainstBaseline(io: std.Io, gpa: std.mem.Allocator, path: []const u8) !bool {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const alloc = arena.allocator();

    const buf = try std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .limited(1 * 1024 * 1024));

    var entries: [64]BaselineEntry = undefined;
    const n = try parseBaseline(alloc, buf, &entries);

    std.debug.print("\n=== Baseline comparison (tolerance ±{d:.0}%) vs {s} ===\n", .{ tolerance_pct * 100, path });

    var ok = true;
    var matched = [_]bool{false} ** 64;
    for (bench_samples[0..bench_sample_count]) |s| {
        var found_idx: ?usize = null;
        var j: usize = 0;
        while (j < n) : (j += 1) {
            if (std.mem.eql(u8, entries[j].name, s.name)) {
                found_idx = j;
                break;
            }
        }
        if (found_idx) |idx| {
            matched[idx] = true;
            const baseline_mean = entries[idx].mean_ns;
            if (baseline_mean == 0) continue;
            const ratio = @as(f64, @floatFromInt(s.mean_ns)) / @as(f64, @floatFromInt(baseline_mean));
            const delta_pct = (ratio - 1.0) * 100.0;
            const status: []const u8 = if (ratio > 1.0 + tolerance_pct)
                "REGRESSION"
            else if (ratio < 1.0 - tolerance_pct)
                "IMPROVED"
            else
                "OK";
            std.debug.print("  {s:<48} {s:<10} mean={d}ns baseline={d}ns Δ={d:.2}%\n", .{ s.name, status, s.mean_ns, baseline_mean, delta_pct });
            if (ratio > 1.0 + tolerance_pct) ok = false;
        } else {
            std.debug.print("  {s:<48} UNKNOWN    mean={d}ns (no baseline entry)\n", .{ s.name, s.mean_ns });
        }
    }
    var k: usize = 0;
    while (k < n) : (k += 1) {
        if (!matched[k]) {
            std.debug.print("  {s:<48} MISSING    (baseline entry, no current sample)\n", .{entries[k].name});
            ok = false;
        }
    }
    std.debug.print("=== {s} ===\n", .{if (ok) "Within tolerance" else "Regression detected"});
    return ok;
}

fn runAllBenches() void {
    // Existing benchmarks (PERF-011)
    benchmarkFn("key_derivation (HKDF-Extract+Expand)", 10_000, benchKeyDerivation);
    benchmarkFn("transcript_hash (SHA-256 update+finalize)", 10_000, benchTranscriptHash);
    benchmarkFn("aead_seal (AES-128-GCM 128B)", 10_000, benchAeadSeal);

    // PERF-029: AEAD decrypt
    benchmarkFn("aead_open (AES-128-GCM 128B)", 10_000, benchAeadOpen);
    benchmarkFn("aead_open (ChaCha20-Poly1305 128B)", 10_000, benchAeadOpenChacha);

    // PERF-029: Certificate validation
    benchmarkFn("cert_parse (X.509 leaf DER)", 10_000, benchCertParse);
    benchmarkFn("cert_chain_parse (leaf+root DER)", 10_000, benchCertChainValidation);

    // PERF-029: Signature verification
    benchmarkFn("ed25519_verify (CertificateVerify)", 1_000, benchEd25519Verify);
    benchmarkFn("ecdsa_p256_verify (cert chain sig)", 1_000, benchEcdsaP256Verify);

    // PERF-029: ClientHello parsing
    benchmarkFn("client_hello_parse (realistic CH)", 1_000, benchClientHelloParse);

    // PERF-029: Server flight encoding
    benchmarkFn("server_flight_encode (5 msgs ~1022B)", 10_000, benchServerFlightEncode);

    // PERF-213 / PERF-221 / PERF-222: Deep-chain NameConstraints accumulation.
    benchmarkFn("name_constraints_accumulate (chain depth 5)", 1_000, benchNameConstraintsDepth5);
    benchmarkFn("name_constraints_accumulate (chain depth 10)", 1_000, benchNameConstraintsDepth10);

    // PERF-256: AEAD throughput size sweep.
    benchmarkThroughputFn("aead_seal_aes128 (1024B)", 5_000, 1024, aeadSealAes(1024));
    benchmarkThroughputFn("aead_seal_aes128 (4096B)", 2_000, 4096, aeadSealAes(4096));
    benchmarkThroughputFn("aead_seal_aes128 (16384B)", 1_000, 16384, aeadSealAes(16384));
    benchmarkThroughputFn("aead_open_aes128 (1024B)", 5_000, 1024, aeadOpenAes(1024));
    benchmarkThroughputFn("aead_open_aes128 (4096B)", 2_000, 4096, aeadOpenAes(4096));
    benchmarkThroughputFn("aead_open_aes128 (16384B)", 1_000, 16384, aeadOpenAes(16384));
    benchmarkThroughputFn("aead_seal_chacha20 (1024B)", 5_000, 1024, aeadSealChacha(1024));
    benchmarkThroughputFn("aead_seal_chacha20 (16384B)", 1_000, 16384, aeadSealChacha(16384));
}

pub fn main(init: std.process.Init) !void {
    std.debug.print("=== TLS 1.3 Performance Benchmarks ===\n", .{});
    std.debug.print("Build mode: {s}\n\n", .{@tagName(@import("builtin").mode)});

    const gpa = init.gpa;
    const io = init.io;

    // PERF-258: parse CLI args. The bench is normally launched by
    // `zig build bench`; arguments are forwarded through the `b.args`
    // hook (`-Dargs="..."`) or by direct execution.
    var emit_json: ?[]const u8 = null;
    var check_baseline: ?[]const u8 = null;
    {
        var it = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
        defer it.deinit();
        _ = it.next(); // skip program name
        while (it.next()) |a| {
            if (std.mem.eql(u8, a, "--emit-json")) {
                const next = it.next() orelse {
                    std.debug.print("--emit-json requires a path argument\n", .{});
                    std.process.exit(2);
                };
                emit_json = try gpa.dupe(u8, next);
            } else if (std.mem.eql(u8, a, "--check-baseline")) {
                const next = it.next() orelse {
                    std.debug.print("--check-baseline requires a path argument\n", .{});
                    std.process.exit(2);
                };
                check_baseline = try gpa.dupe(u8, next);
            } else if (std.mem.eql(u8, a, "--help")) {
                std.debug.print(
                    \\Usage: bench [--emit-json PATH] [--check-baseline PATH]
                    \\
                    \\PERF-258: Optional JSON output and baseline regression detection.
                    \\Default behavior (no flags) prints human-readable bench rows.
                    \\
                , .{});
                std.process.exit(0);
            }
        }
    }
    defer if (emit_json) |p| gpa.free(p);
    defer if (check_baseline) |p| gpa.free(p);

    runAllBenches();

    if (emit_json) |path| {
        const blob = try renderJsonResults(gpa);
        defer gpa.free(blob);
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = blob });
        std.debug.print("\n[bench] wrote JSON results to {s}\n", .{path});
    }

    if (check_baseline) |path| {
        const ok = compareAgainstBaseline(io, gpa, path) catch |err| {
            std.debug.print("[bench] failed to compare baseline at {s}: {any}\n", .{ path, err });
            std.process.exit(2);
        };
        if (!ok) std.process.exit(1);
    }

    std.debug.print("\n=== Benchmark Complete ===\n", .{});
}
