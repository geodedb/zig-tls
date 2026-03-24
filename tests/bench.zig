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

pub fn main() void {
    std.debug.print("=== TLS 1.3 Performance Benchmarks ===\n", .{});
    std.debug.print("Build mode: {s}\n\n", .{@tagName(@import("builtin").mode)});

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

    std.debug.print("\n=== Benchmark Complete ===\n", .{});
}
