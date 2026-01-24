// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
//
//! AEAD Encryption Example
//!
//! Demonstrates authenticated encryption with associated data (AEAD) operations
//! as used in TLS 1.3 record protection and QUIC packet protection.
//! Covers all three TLS 1.3 cipher suites:
//! - AES-128-GCM (RFC 5116)
//! - AES-256-GCM (RFC 5116)
//! - ChaCha20-Poly1305 (RFC 8439)
//!
//! ## RFC References
//! - RFC 8446 Section 5.2: Record Payload Protection
//! - RFC 8446 Section 5.3: Per-Record Nonce
//! - RFC 8446 Section 5.5: Limits on Key Usage
//! - RFC 9001 Section 5.3: QUIC Packet Protection

const std = @import("std");
const ztls = @import("ztls");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== AEAD Encryption Examples (TLS 1.3 / QUIC) ===\n\n", .{});

    // =========================================================================
    // Example 1: AES-128-GCM Encryption/Decryption
    // =========================================================================
    std.debug.print("1. AES-128-GCM Seal/Open (RFC 5116)\n", .{});
    std.debug.print("   TLS_AES_128_GCM_SHA256 cipher suite\n\n", .{});

    {
        // RFC 8446: 128-bit key, 96-bit nonce
        const key_128: [16]u8 = [_]u8{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        };
        const iv: [12]u8 = [_]u8{
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
            0xa8, 0xa9, 0xaa, 0xab,
        };

        var cipher = try ztls.record.AeadCipher.init(
            .TLS_AES_128_GCM_SHA256,
            &key_128,
            &iv,
            null, // No custom usage limits
        );
        defer cipher.wipe();

        const plaintext = "Hello, TLS 1.3 AEAD!";
        const aad = "additional authenticated data";
        const seq_num: u64 = 0; // Sequence number for nonce derivation

        // Encrypt (seal)
        const ciphertext = try cipher.seal(allocator, seq_num, aad, plaintext);
        defer allocator.free(ciphertext);

        std.debug.print("   Plaintext:   '{s}'\n", .{plaintext});
        std.debug.print("   Ciphertext:  {} bytes (includes 16-byte tag)\n", .{ciphertext.len});
        std.debug.print("   First bytes: ", .{});
        for (ciphertext[0..@min(16, ciphertext.len)]) |b| std.debug.print("{x:0>2}", .{b});
        std.debug.print("...\n", .{});

        // Decrypt (open)
        const recovered = try cipher.open(allocator, seq_num, aad, ciphertext);
        defer allocator.free(recovered);

        std.debug.print("   Decrypted:   '{s}'\n", .{recovered});
        std.debug.print("   Match: {}\n\n", .{std.mem.eql(u8, plaintext, recovered)});
    }

    // =========================================================================
    // Example 2: AES-256-GCM Encryption
    // =========================================================================
    std.debug.print("2. AES-256-GCM Seal/Open\n", .{});
    std.debug.print("   TLS_AES_256_GCM_SHA384 cipher suite\n\n", .{});

    {
        // RFC 8446: 256-bit key for AES-256
        const key_256: [32]u8 = [_]u8{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        };
        const iv: [12]u8 = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb };

        var cipher = try ztls.record.AeadCipher.init(
            .TLS_AES_256_GCM_SHA384,
            &key_256,
            &iv,
            null,
        );
        defer cipher.wipe();

        const plaintext = "Secure message with AES-256-GCM";
        const aad = "header data";

        const ciphertext = try cipher.seal(allocator, 42, aad, plaintext);
        defer allocator.free(ciphertext);

        const recovered = try cipher.open(allocator, 42, aad, ciphertext);
        defer allocator.free(recovered);

        std.debug.print("   Plaintext:  '{s}'\n", .{plaintext});
        std.debug.print("   Decrypted:  '{s}'\n", .{recovered});
        std.debug.print("   Key size:   256 bits\n\n", .{});
    }

    // =========================================================================
    // Example 3: ChaCha20-Poly1305 Encryption
    // =========================================================================
    std.debug.print("3. ChaCha20-Poly1305 Seal/Open (RFC 8439)\n", .{});
    std.debug.print("   TLS_CHACHA20_POLY1305_SHA256 cipher suite\n\n", .{});

    {
        // ChaCha20-Poly1305 uses 256-bit keys
        const key_chacha: [32]u8 = [_]u8{
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
            0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
            0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
            0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
        };
        const iv: [12]u8 = [_]u8{ 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb };

        var cipher = try ztls.record.AeadCipher.init(
            .TLS_CHACHA20_POLY1305_SHA256,
            &key_chacha,
            &iv,
            null,
        );
        defer cipher.wipe();

        const plaintext = "ChaCha20-Poly1305 is great for mobile!";
        const aad = "mobile header";

        const ciphertext = try cipher.seal(allocator, 100, aad, plaintext);
        defer allocator.free(ciphertext);

        const recovered = try cipher.open(allocator, 100, aad, ciphertext);
        defer allocator.free(recovered);

        std.debug.print("   Plaintext:  '{s}'\n", .{plaintext});
        std.debug.print("   Decrypted:  '{s}'\n", .{recovered});
        std.debug.print("   Note: ChaCha20-Poly1305 is often faster on ARM/mobile\n\n", .{});
    }

    // =========================================================================
    // Example 4: Nonce Derivation (XOR method)
    // =========================================================================
    std.debug.print("4. Per-Record Nonce Derivation (RFC 8446 Section 5.3)\n", .{});
    std.debug.print("   nonce = base_iv XOR padded_sequence_number\n\n", .{});

    {
        const base_iv: [12]u8 = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
        var nonce: [12]u8 = undefined;

        // Derive nonce for sequence number 1
        try ztls.record.xorNonce(&nonce, &base_iv, 1);

        std.debug.print("   Base IV:       ", .{});
        for (base_iv) |b| std.debug.print("{x:0>2}", .{b});
        std.debug.print("\n", .{});

        std.debug.print("   Sequence:      1\n", .{});

        std.debug.print("   Derived Nonce: ", .{});
        for (nonce) |b| std.debug.print("{x:0>2}", .{b});
        std.debug.print("\n\n", .{});

        // Different sequence numbers produce different nonces
        try ztls.record.xorNonce(&nonce, &base_iv, 12345);
        std.debug.print("   Nonce (seq=12345): ", .{});
        for (nonce) |b| std.debug.print("{x:0>2}", .{b});
        std.debug.print("\n\n", .{});
    }

    // =========================================================================
    // Example 5: Authentication Failure Detection
    // =========================================================================
    std.debug.print("5. Authentication Failure Detection\n", .{});
    std.debug.print("   Tampered ciphertext is rejected\n\n", .{});

    {
        const key: [16]u8 = [_]u8{0x11} ** 16;
        const iv: [12]u8 = [_]u8{0x22} ** 12;

        var cipher = try ztls.record.AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, null);
        defer cipher.wipe();

        const plaintext = "Authentic message";
        const aad = "header";

        const ciphertext = try cipher.seal(allocator, 0, aad, plaintext);
        defer allocator.free(ciphertext);

        // Tamper with ciphertext
        var tampered = try allocator.alloc(u8, ciphertext.len);
        defer allocator.free(tampered);
        @memcpy(tampered, ciphertext);
        tampered[0] ^= 0xFF; // Flip bits

        // Attempt decryption - should fail
        const result = cipher.open(allocator, 0, aad, tampered);
        if (result) |data| {
            allocator.free(data);
            std.debug.print("   ERROR: Tampered data was accepted!\n\n", .{});
        } else |err| {
            std.debug.print("   Original ciphertext: OK\n", .{});
            std.debug.print("   Tampered ciphertext: Rejected ({any})\n", .{err});
            std.debug.print("   AEAD correctly detected tampering\n\n", .{});
        }
    }

    // =========================================================================
    // Example 6: AEAD Usage Limits (RFC 8446 Section 5.5)
    // =========================================================================
    std.debug.print("6. AEAD Usage Limits (RFC 8446 Section 5.5)\n", .{});
    std.debug.print("   Key rotation required before limits exceeded\n\n", .{});

    {
        // Set very low limits for demonstration
        const limits = ztls.record.AeadUsageLimits{
            .confidentiality = 3, // Only 3 encryptions allowed
            .integrity = 5, // Only 5 auth failures before key considered compromised
        };

        const key: [16]u8 = [_]u8{0x33} ** 16;
        const iv: [12]u8 = [_]u8{0x44} ** 12;

        var cipher = try ztls.record.AeadCipher.init(.TLS_AES_128_GCM_SHA256, &key, &iv, limits);
        defer cipher.wipe();

        std.debug.print("   Confidentiality limit: {} encryptions\n", .{limits.confidentiality});
        std.debug.print("   Integrity limit: {} auth failures\n\n", .{limits.integrity});

        const plaintext = "test";
        var seq: u64 = 0;

        // Encrypt up to the limit
        while (seq < 3) : (seq += 1) {
            const ct = try cipher.seal(allocator, seq, "", plaintext);
            allocator.free(ct);
            std.debug.print("   Encryption {}: OK\n", .{seq + 1});
        }

        // Next encryption should fail
        const result = cipher.seal(allocator, seq, "", plaintext);
        if (result) |ct| {
            allocator.free(ct);
            std.debug.print("   Encryption 4: Unexpectedly succeeded\n", .{});
        } else |err| {
            std.debug.print("   Encryption 4: Blocked ({any})\n", .{err});
            std.debug.print("   Key must be rotated before continuing\n", .{});
        }
    }

    std.debug.print("\n=== AEAD Examples Complete ===\n", .{});
}
