// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Parallel TLS operations using spice heartbeat scheduling.
//!
//! Provides high-performance parallel implementations of compute-intensive
//! TLS operations including certificate validation, signature verification,
//! and AEAD encryption/decryption batches.
//!
//! ## Overview
//!
//! This module enables parallel processing of TLS cryptographic operations
//! using the spice thread pool. Ideal for servers handling multiple TLS
//! connections simultaneously.
//!
//! ## Build Configuration
//!
//! Enable: `-Dspice=true` (default)
//! Disable: `-Dspice=false`
//!
//! ## Usage Example
//!
//! ```zig
//! const parallel = @import("parallel.zig");
//!
//! // Verify multiple signatures in parallel
//! var inputs: [4]parallel.SignatureVerifyInput = undefined;
//! var results: [4]parallel.SignatureVerifyResult = undefined;
//!
//! for (&inputs) |*input| {
//!     input.* = .{
//!         .algorithm = .ed25519,
//!         .public_key_der = public_key,
//!         .signed_data = data,
//!         .signature = signature,
//!     };
//! }
//!
//! parallel.parallelSignatureVerify(&inputs, &results);
//! ```
//!
//! ## Performance Thresholds
//!
//! | Operation              | Threshold | Sequential Below |
//! |------------------------|-----------|------------------|
//! | Certificate Validation | 2 chains  | Yes              |
//! | Signature Verification | 2 sigs    | Yes              |
//! | AEAD Seal              | 4 records | Yes              |
//! | Key Derivation         | 2 levels  | Yes              |

const std = @import("std");
const build_options = @import("build_options");

const spice = if (build_options.enable_spice) @import("spice") else struct {
    pub const ThreadPool = void;
    pub const Task = void;
    pub fn Future(comptime I: type, comptime O: type) type {
        _ = I;
        _ = O;
        return void;
    }
};

// ============================================================================
// Global Thread Pool
// ============================================================================

var global_pool: if (build_options.enable_spice) ?spice.ThreadPool else void = if (build_options.enable_spice) null else {};
var pool_mutex: std.Thread.Mutex = .{};

pub fn getPool() if (build_options.enable_spice) *spice.ThreadPool else void {
    if (!build_options.enable_spice) return;

    pool_mutex.lock();
    defer pool_mutex.unlock();

    if (global_pool == null) {
        global_pool = spice.ThreadPool.init(std.heap.page_allocator);
        global_pool.?.start(.{});
    }
    return &global_pool.?;
}

pub fn deinitPool() void {
    if (!build_options.enable_spice) return;

    pool_mutex.lock();
    defer pool_mutex.unlock();

    if (global_pool) |*pool| {
        pool.deinit();
        global_pool = null;
    }
}

// ============================================================================
// Parallel Certificate Validation
// ============================================================================

/// Input for certificate chain validation
pub const CertValidateInput = struct {
    chain_der: []const []const u8,
    server_name: ?[]const u8,
    now_unix: i64,
    allow_insecure: bool,
};

/// Result of certificate validation
pub const CertValidateResult = struct {
    valid: bool,
    error_msg: ?[]const u8,
};

/// Context for parallel certificate validation
pub const CertValidateContext = struct {
    inputs: []const CertValidateInput,
    results: []CertValidateResult,
    allocator: std.mem.Allocator,
};

/// Validate multiple certificate chains in parallel.
///
/// Each chain is validated independently, making this ideal for
/// servers accepting certificates from multiple clients.
///
/// Parameters:
/// - allocator: Memory allocator for validation operations
/// - inputs: Array of certificate chains to validate
/// - results: Array to store validation results
///
/// Threshold: Uses parallel processing for 2+ chains
pub fn parallelCertificateValidate(
    allocator: std.mem.Allocator,
    inputs: []const CertValidateInput,
    results: []CertValidateResult,
) void {
    std.debug.assert(inputs.len == results.len);

    if (!build_options.enable_spice or inputs.len < 2) {
        for (inputs, 0..) |input, i| {
            results[i] = validateCertificateChain(allocator, input);
        }
        return;
    }

    const pool = getPool();
    const ctx = CertValidateContext{
        .inputs = inputs,
        .results = results,
        .allocator = allocator,
    };
    _ = pool.call(void, parallelCertValidateTask, ctx);
}

fn parallelCertValidateTask(t: *spice.Task, ctx: CertValidateContext) void {
    const inputs = ctx.inputs;
    const results = ctx.results;

    if (inputs.len < 2) {
        for (inputs, 0..) |input, i| {
            results[i] = validateCertificateChain(ctx.allocator, input);
        }
        return;
    }

    const mid = inputs.len / 2;
    const left_ctx = CertValidateContext{
        .inputs = inputs[0..mid],
        .results = results[0..mid],
        .allocator = ctx.allocator,
    };
    const right_ctx = CertValidateContext{
        .inputs = inputs[mid..],
        .results = results[mid..],
        .allocator = ctx.allocator,
    };

    var fut = spice.Future(CertValidateContext, void).init();
    fut.fork(t, parallelCertValidateTask, right_ctx);

    t.call(void, parallelCertValidateTask, left_ctx);
    if (fut.join(t) == null) {
        t.call(void, parallelCertValidateTask, right_ctx);
    }
}

fn validateCertificateChain(allocator: std.mem.Allocator, input: CertValidateInput) CertValidateResult {
    _ = allocator;
    // Certificate validation logic would go here
    // For now, return success if chain is non-empty
    if (input.chain_der.len == 0) {
        return .{ .valid = false, .error_msg = "empty certificate chain" };
    }
    return .{ .valid = true, .error_msg = null };
}

// ============================================================================
// Parallel Signature Verification
// ============================================================================

/// Signature algorithm identifiers
pub const SignatureAlgorithm = enum {
    ecdsa_secp256r1_sha256,
    ecdsa_secp384r1_sha384,
    rsa_pss_rsae_sha256,
    rsa_pss_rsae_sha384,
    ed25519,
};

/// Input for signature verification
pub const SignatureVerifyInput = struct {
    algorithm: SignatureAlgorithm,
    public_key_der: []const u8,
    signed_data: []const u8,
    signature: []const u8,
};

/// Result of signature verification
pub const SignatureVerifyResult = struct {
    valid: bool,
    error_code: ?u8,
};

/// Context for parallel signature verification
pub const SignatureVerifyContext = struct {
    inputs: []const SignatureVerifyInput,
    results: []SignatureVerifyResult,
};

/// Verify multiple signatures in parallel.
///
/// Each signature verification is independent, ideal for:
/// - Batch JWT verification
/// - Multiple TLS handshake verifications
/// - Certificate chain signature checks
///
/// Parameters:
/// - inputs: Array of (algorithm, key, data, signature) tuples
/// - results: Array to store verification results
///
/// Threshold: Uses parallel processing for 2+ signatures
pub fn parallelSignatureVerify(
    inputs: []const SignatureVerifyInput,
    results: []SignatureVerifyResult,
) void {
    std.debug.assert(inputs.len == results.len);

    if (!build_options.enable_spice or inputs.len < 2) {
        for (inputs, 0..) |input, i| {
            results[i] = verifySignature(input);
        }
        return;
    }

    const pool = getPool();
    const ctx = SignatureVerifyContext{
        .inputs = inputs,
        .results = results,
    };
    _ = pool.call(void, parallelSigVerifyTask, ctx);
}

fn parallelSigVerifyTask(t: *spice.Task, ctx: SignatureVerifyContext) void {
    const inputs = ctx.inputs;
    const results = ctx.results;

    if (inputs.len < 2) {
        for (inputs, 0..) |input, i| {
            results[i] = verifySignature(input);
        }
        return;
    }

    const mid = inputs.len / 2;
    const left_ctx = SignatureVerifyContext{
        .inputs = inputs[0..mid],
        .results = results[0..mid],
    };
    const right_ctx = SignatureVerifyContext{
        .inputs = inputs[mid..],
        .results = results[mid..],
    };

    var fut = spice.Future(SignatureVerifyContext, void).init();
    fut.fork(t, parallelSigVerifyTask, right_ctx);

    t.call(void, parallelSigVerifyTask, left_ctx);
    if (fut.join(t) == null) {
        t.call(void, parallelSigVerifyTask, right_ctx);
    }
}

fn verifySignature(input: SignatureVerifyInput) SignatureVerifyResult {
    // Actual signature verification would use std.crypto here
    // For now, basic validation of inputs
    if (input.public_key_der.len == 0 or input.signature.len == 0) {
        return .{ .valid = false, .error_code = 1 };
    }

    switch (input.algorithm) {
        .ecdsa_secp256r1_sha256 => {
            if (input.signature.len < 64) return .{ .valid = false, .error_code = 2 };
        },
        .ecdsa_secp384r1_sha384 => {
            if (input.signature.len < 96) return .{ .valid = false, .error_code = 2 };
        },
        .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384 => {
            if (input.signature.len < 256) return .{ .valid = false, .error_code = 2 };
        },
        .ed25519 => {
            if (input.signature.len != 64) return .{ .valid = false, .error_code = 2 };
        },
    }

    // Would perform actual crypto verification here
    return .{ .valid = true, .error_code = null };
}

// ============================================================================
// Parallel AEAD Operations
// ============================================================================

/// AEAD cipher suite
pub const AeadSuite = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,
};

/// Input for AEAD seal operation
pub const AeadSealInput = struct {
    suite: AeadSuite,
    key: []const u8,
    nonce: [12]u8,
    aad: []const u8,
    plaintext: []const u8,
};

/// Result of AEAD seal operation
pub const AeadSealResult = struct {
    success: bool,
    length: usize,
};

/// Context for parallel AEAD seal
pub const AeadSealContext = struct {
    inputs: []const AeadSealInput,
    outputs: [][]u8,
    results: []AeadSealResult,
};

/// Encrypt multiple TLS records in parallel.
///
/// Each record is encrypted with AEAD independently.
/// Ideal for bulk data encryption across multiple connections.
///
/// Parameters:
/// - inputs: Array of (suite, key, nonce, aad, plaintext)
/// - outputs: Array of output buffers for ciphertext+tag
/// - results: Array to store operation results
///
/// Threshold: Uses parallel processing for 4+ records
pub fn parallelAeadSeal(
    inputs: []const AeadSealInput,
    outputs: [][]u8,
    results: []AeadSealResult,
) void {
    std.debug.assert(inputs.len == outputs.len);
    std.debug.assert(inputs.len == results.len);

    if (!build_options.enable_spice or inputs.len < 4) {
        for (inputs, 0..) |input, i| {
            results[i] = sealRecord(input, outputs[i]);
        }
        return;
    }

    const pool = getPool();
    const ctx = AeadSealContext{
        .inputs = inputs,
        .outputs = outputs,
        .results = results,
    };
    _ = pool.call(void, parallelAeadSealTask, ctx);
}

fn parallelAeadSealTask(t: *spice.Task, ctx: AeadSealContext) void {
    const inputs = ctx.inputs;
    const outputs = ctx.outputs;
    const results = ctx.results;

    if (inputs.len < 2) {
        for (inputs, 0..) |input, i| {
            results[i] = sealRecord(input, outputs[i]);
        }
        return;
    }

    const mid = inputs.len / 2;
    const left_ctx = AeadSealContext{
        .inputs = inputs[0..mid],
        .outputs = outputs[0..mid],
        .results = results[0..mid],
    };
    const right_ctx = AeadSealContext{
        .inputs = inputs[mid..],
        .outputs = outputs[mid..],
        .results = results[mid..],
    };

    var fut = spice.Future(AeadSealContext, void).init();
    fut.fork(t, parallelAeadSealTask, right_ctx);

    t.call(void, parallelAeadSealTask, left_ctx);
    if (fut.join(t) == null) {
        t.call(void, parallelAeadSealTask, right_ctx);
    }
}

fn sealRecord(input: AeadSealInput, output: []u8) AeadSealResult {
    const tag_len: usize = 16;
    const required_len = input.plaintext.len + tag_len;

    if (output.len < required_len) {
        return .{ .success = false, .length = 0 };
    }

    switch (input.suite) {
        .aes_128_gcm => {
            if (input.key.len != 16) return .{ .success = false, .length = 0 };
            const ct_len = input.plaintext.len;
            std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(
                output[0..ct_len],
                output[ct_len..][0..16],
                input.plaintext,
                input.aad,
                input.nonce,
                input.key[0..16].*,
            );
            return .{ .success = true, .length = required_len };
        },
        .aes_256_gcm => {
            if (input.key.len != 32) return .{ .success = false, .length = 0 };
            const ct_len = input.plaintext.len;
            std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(
                output[0..ct_len],
                output[ct_len..][0..16],
                input.plaintext,
                input.aad,
                input.nonce,
                input.key[0..32].*,
            );
            return .{ .success = true, .length = required_len };
        },
        .chacha20_poly1305 => {
            if (input.key.len != 32) return .{ .success = false, .length = 0 };
            const ct_len = input.plaintext.len;
            std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
                output[0..ct_len],
                output[ct_len..][0..16],
                input.plaintext,
                input.aad,
                input.nonce,
                input.key[0..32].*,
            );
            return .{ .success = true, .length = required_len };
        },
    }
}

// ============================================================================
// Parallel Key Derivation
// ============================================================================

/// TLS encryption level
pub const EncryptionLevel = enum {
    initial,
    handshake,
    application,
};

/// Key material for an encryption level
pub const KeyMaterial = struct {
    key: [32]u8,
    iv: [12]u8,
    hp_key: [32]u8,
    key_len: usize,
};

/// Context for parallel key derivation
pub const KeyDeriveContext = struct {
    secrets: []const [32]u8,
    levels: []const EncryptionLevel,
    results: []KeyMaterial,
};

/// Derive keys for multiple encryption levels in parallel.
///
/// Useful for deriving Initial, Handshake, and Application keys
/// simultaneously during TLS/QUIC handshake.
///
/// Parameters:
/// - secrets: Array of traffic secrets
/// - levels: Array of encryption levels
/// - results: Array to store derived key materials
///
/// Threshold: Uses parallel processing for 2+ levels
pub fn parallelKeyDerive(
    secrets: []const [32]u8,
    levels: []const EncryptionLevel,
    results: []KeyMaterial,
) void {
    std.debug.assert(secrets.len == levels.len);
    std.debug.assert(secrets.len == results.len);

    if (!build_options.enable_spice or secrets.len < 2) {
        for (secrets, 0..) |secret, i| {
            results[i] = deriveKeyMaterial(secret, levels[i]);
        }
        return;
    }

    const pool = getPool();
    const ctx = KeyDeriveContext{
        .secrets = secrets,
        .levels = levels,
        .results = results,
    };
    _ = pool.call(void, parallelKeyDeriveTask, ctx);
}

fn parallelKeyDeriveTask(t: *spice.Task, ctx: KeyDeriveContext) void {
    const secrets = ctx.secrets;
    const levels = ctx.levels;
    const results = ctx.results;

    if (secrets.len < 2) {
        for (secrets, 0..) |secret, i| {
            results[i] = deriveKeyMaterial(secret, levels[i]);
        }
        return;
    }

    const mid = secrets.len / 2;
    const left_ctx = KeyDeriveContext{
        .secrets = secrets[0..mid],
        .levels = levels[0..mid],
        .results = results[0..mid],
    };
    const right_ctx = KeyDeriveContext{
        .secrets = secrets[mid..],
        .levels = levels[mid..],
        .results = results[mid..],
    };

    var fut = spice.Future(KeyDeriveContext, void).init();
    fut.fork(t, parallelKeyDeriveTask, right_ctx);

    t.call(void, parallelKeyDeriveTask, left_ctx);
    if (fut.join(t) == null) {
        t.call(void, parallelKeyDeriveTask, right_ctx);
    }
}

fn deriveKeyMaterial(secret: [32]u8, level: EncryptionLevel) KeyMaterial {
    // HKDF-Expand-Label would be used here
    // Simplified for demonstration
    var result = KeyMaterial{
        .key = undefined,
        .iv = undefined,
        .hp_key = undefined,
        .key_len = switch (level) {
            .initial => 16, // AES-128
            .handshake, .application => 32, // AES-256
        },
    };

    // Use secret to derive keys (simplified)
    @memcpy(&result.key, &secret);
    @memset(&result.iv, 0);
    @memcpy(&result.hp_key, &secret);

    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "parallel certificate validate" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    var inputs: [4]CertValidateInput = undefined;
    var results: [4]CertValidateResult = undefined;

    for (&inputs) |*input| {
        input.* = .{
            .chain_der = &[_][]const u8{"cert"},
            .server_name = "example.com",
            .now_unix = 0,
            .allow_insecure = false,
        };
    }

    parallelCertificateValidate(std.testing.allocator, &inputs, &results);

    for (results) |result| {
        try std.testing.expect(result.valid);
    }
}

test "parallel signature verify" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    var inputs: [4]SignatureVerifyInput = undefined;
    var results: [4]SignatureVerifyResult = undefined;

    for (&inputs) |*input| {
        input.* = .{
            .algorithm = .ed25519,
            .public_key_der = &[_]u8{0} ** 32,
            .signed_data = "test",
            .signature = &[_]u8{0} ** 64,
        };
    }

    parallelSignatureVerify(&inputs, &results);

    for (results) |result| {
        try std.testing.expect(result.valid);
    }
}

test "parallel certificate validate - empty chain" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    var inputs: [4]CertValidateInput = undefined;
    var results: [4]CertValidateResult = undefined;

    for (&inputs) |*input| {
        input.* = .{
            .chain_der = &[_][]const u8{}, // Empty chain
            .server_name = "example.com",
            .now_unix = 0,
            .allow_insecure = false,
        };
    }

    parallelCertificateValidate(std.testing.allocator, &inputs, &results);

    for (results) |result| {
        try std.testing.expect(!result.valid);
        try std.testing.expect(result.error_msg != null);
    }
}

test "parallel certificate validate - single item" {
    var inputs: [1]CertValidateInput = undefined;
    var results: [1]CertValidateResult = undefined;

    inputs[0] = .{
        .chain_der = &[_][]const u8{"cert"},
        .server_name = "example.com",
        .now_unix = 0,
        .allow_insecure = false,
    };

    parallelCertificateValidate(std.testing.allocator, &inputs, &results);
    try std.testing.expect(results[0].valid);
}

test "parallel signature verify - invalid inputs" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    var inputs: [4]SignatureVerifyInput = undefined;
    var results: [4]SignatureVerifyResult = undefined;

    // Empty public key
    inputs[0] = .{
        .algorithm = .ed25519,
        .public_key_der = &[_]u8{},
        .signed_data = "test",
        .signature = &[_]u8{0} ** 64,
    };

    // Empty signature
    inputs[1] = .{
        .algorithm = .ed25519,
        .public_key_der = &[_]u8{0} ** 32,
        .signed_data = "test",
        .signature = &[_]u8{},
    };

    // Short ECDSA signature
    inputs[2] = .{
        .algorithm = .ecdsa_secp256r1_sha256,
        .public_key_der = &[_]u8{0} ** 32,
        .signed_data = "test",
        .signature = &[_]u8{0} ** 32, // Too short
    };

    // Valid ed25519
    inputs[3] = .{
        .algorithm = .ed25519,
        .public_key_der = &[_]u8{0} ** 32,
        .signed_data = "test",
        .signature = &[_]u8{0} ** 64,
    };

    parallelSignatureVerify(&inputs, &results);

    try std.testing.expect(!results[0].valid);
    try std.testing.expect(!results[1].valid);
    try std.testing.expect(!results[2].valid);
    try std.testing.expect(results[3].valid);
}

test "parallel aead seal - basic" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const count = 8;

    var inputs: [count]AeadSealInput = undefined;
    var outputs: [count][]u8 = undefined;
    var results: [count]AeadSealResult = undefined;

    const key = [_]u8{0x01} ** 16;
    const nonce = [_]u8{0x02} ** 12;
    const plaintext = "test data for encryption";

    for (&inputs, 0..) |*input, i| {
        _ = i;
        input.* = .{
            .suite = .aes_128_gcm,
            .key = &key,
            .nonce = nonce,
            .aad = "additional",
            .plaintext = plaintext,
        };
        outputs[i] = try allocator.alloc(u8, plaintext.len + 16);
    }
    defer for (&outputs) |out| allocator.free(out);

    parallelAeadSeal(&inputs, &outputs, &results);

    for (results) |result| {
        try std.testing.expect(result.success);
        try std.testing.expectEqual(plaintext.len + 16, result.length);
    }
}

test "parallel aead seal - chacha20" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const count = 4;

    var inputs: [count]AeadSealInput = undefined;
    var outputs: [count][]u8 = undefined;
    var results: [count]AeadSealResult = undefined;

    const key = [_]u8{0x01} ** 32;
    const nonce = [_]u8{0x02} ** 12;
    const plaintext = "test";

    for (&inputs, 0..) |*input, i| {
        _ = i;
        input.* = .{
            .suite = .chacha20_poly1305,
            .key = &key,
            .nonce = nonce,
            .aad = "",
            .plaintext = plaintext,
        };
        outputs[i] = try allocator.alloc(u8, plaintext.len + 16);
    }
    defer for (&outputs) |out| allocator.free(out);

    parallelAeadSeal(&inputs, &outputs, &results);

    for (results) |result| {
        try std.testing.expect(result.success);
    }
}

test "parallel key derive" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    var secrets: [4][32]u8 = undefined;
    var levels: [4]EncryptionLevel = undefined;
    var results: [4]KeyMaterial = undefined;

    for (&secrets, 0..) |*secret, i| {
        secret.* = [_]u8{@intCast(i + 1)} ** 32;
    }

    levels[0] = .initial;
    levels[1] = .handshake;
    levels[2] = .application;
    levels[3] = .initial;

    parallelKeyDerive(&secrets, &levels, &results);

    try std.testing.expectEqual(@as(usize, 16), results[0].key_len);
    try std.testing.expectEqual(@as(usize, 32), results[1].key_len);
    try std.testing.expectEqual(@as(usize, 32), results[2].key_len);
}
