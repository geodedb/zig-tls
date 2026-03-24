// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
//
//! Basic TLS 1.3 Client Example
//!
//! Demonstrates how to initialize a TLS 1.3 client context for QUIC integration.
//! This example shows the fundamental setup required to:
//! - Configure cipher suites and key exchange groups
//! - Set up ALPN negotiation for HTTP/3
//! - Define callbacks for secret installation
//! - Process CRYPTO frame data
//!
//! ## RFC References
//! - RFC 8446: TLS 1.3 core protocol
//! - RFC 9001: Using TLS to Secure QUIC
//! - RFC 7301: Application-Layer Protocol Negotiation (ALPN)

const std = @import("std");
const ztls = @import("ztls");

/// Example QUIC connection state (simplified for demonstration).
/// In a real implementation, this would contain full connection state.
const QuicConnection = struct {
    // Encryption keys for each level
    initial_keys_installed: bool = false,
    handshake_keys_installed: bool = false,
    application_keys_installed: bool = false,

    // CRYPTO frame buffers (simulated)
    outgoing_crypto: std.ArrayList(u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) QuicConnection {
        return .{
            .outgoing_crypto = std.ArrayList(u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *QuicConnection) void {
        self.outgoing_crypto.deinit();
    }

    /// Install traffic secrets at the specified encryption level.
    /// RFC 9001 Section 5.1: Packet protection keys are derived from traffic secrets.
    pub fn installKeys(self: *QuicConnection, level: ztls.EncryptionLevel, secret: []const u8) void {
        _ = secret; // In real code: derive AEAD keys via HKDF-Expand-Label
        switch (level) {
            .Initial => self.initial_keys_installed = true,
            .Handshake => self.handshake_keys_installed = true,
            .Application => self.application_keys_installed = true,
        }
        std.debug.print("Installed keys at level: {}\n", .{level});
    }
};

/// Callback: Called when new traffic secrets become available.
/// RFC 9001 Section 5: QUIC uses these secrets to derive packet protection keys.
fn onSecretAvailable(ctx: *ztls.Context, level: ztls.EncryptionLevel, secret: []const u8) anyerror!void {
    // Access user data from context (would be set during init in real code)
    _ = ctx;
    std.debug.print("Secret available at level {}: {} bytes\n", .{ level, secret.len });

    // In real implementation:
    // 1. Derive packet protection keys using HKDF-Expand-Label
    // 2. Install keys in QUIC packet protection layer
    // 3. Enable encryption/decryption at this level
}

/// Callback: Called when handshake completes successfully.
fn onHandshakeComplete(ctx: *ztls.Context) anyerror!void {
    _ = ctx;
    std.debug.print("TLS handshake completed successfully!\n", .{});
    // Now safe to send/receive application data
}

/// Callback: Called when peer's Finished message is verified.
fn onPeerFinished(ctx: *ztls.Context) anyerror!void {
    _ = ctx;
    std.debug.print("Peer Finished message verified\n", .{});
}

/// Callback: Called when handshake metadata (ALPN, transport params) is available.
fn onHandshakeMetadata(ctx: *ztls.Context, meta: ztls.HandshakeMetadata) anyerror!void {
    _ = ctx;
    if (meta.alpn) |alpn| {
        std.debug.print("Negotiated ALPN: {s}\n", .{alpn});
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Simulated QUIC connection
    var quic_conn = QuicConnection.init(allocator);
    defer quic_conn.deinit();

    // Example QUIC transport parameters (would be encoded by QUIC layer)
    const transport_params = [_]u8{
        // max_idle_timeout (0x01): 30000ms
        0x01, 0x02, 0x75, 0x30,
        // initial_max_data (0x04): 1MB
        0x04, 0x04, 0x80, 0x10,
        0x00, 0x00,
    };

    // Configure TLS 1.3 client
    // RFC 8446 Section 4.1.2: ClientHello configuration
    const config = ztls.Config{
        .allocator = allocator,
        .role = .Client,

        // Cipher suite preferences (RFC 8446 Section B.4)
        .supported_cipher_suites = &.{
            .TLS_AES_128_GCM_SHA256, // Most common for QUIC
            .TLS_AES_256_GCM_SHA384, // Higher security
            .TLS_CHACHA20_POLY1305_SHA256, // Good for mobile
        },

        // Key exchange groups (RFC 8446 Section 4.2.7)
        .supported_groups = &.{
            .x25519, // Recommended, fast
        },

        // Signature algorithms (RFC 8446 Section 4.2.3)
        .supported_signature_schemes = &.{
            .ed25519, // Modern, fast
            .ecdsa_secp256r1_sha256, // Widely supported
            .rsa_pss_rsae_sha256, // RSA fallback
        },

        // ALPN protocols (RFC 7301)
        .alpn_protocols = &.{"h3"}, // HTTP/3 for QUIC

        // QUIC transport parameters (RFC 9001 Section 8.2)
        .quic_transport_parameters = &transport_params,

        // Server name for SNI and certificate validation
        .server_name = "example.com",
    };

    // Set up callbacks for QUIC integration
    const callbacks = ztls.Callbacks{
        .on_secret_available = onSecretAvailable,
        .on_handshake_complete = onHandshakeComplete,
        .on_peer_finished = onPeerFinished,
        .on_handshake_metadata = onHandshakeMetadata,
    };

    // Initialize TLS context
    var ctx = try ztls.Context.init(config, callbacks);
    defer ctx.deinit();

    std.debug.print("TLS 1.3 client context initialized\n", .{});
    std.debug.print("  Role: Client\n", .{});
    std.debug.print("  Cipher suites: {} configured\n", .{config.supported_cipher_suites.len});
    std.debug.print("  ALPN: h3\n", .{});

    // In a real application, you would now:
    //
    // 1. Generate ClientHello:
    //    const client_hello = ctx.generateClientHello();
    //
    // 2. Send ClientHello via QUIC CRYPTO frame:
    //    try quic_conn.sendCryptoFrame(.Initial, client_hello);
    //
    // 3. Receive ServerHello from QUIC CRYPTO frame:
    //    try ctx.processCrypto(.Initial, server_hello_data);
    //
    // 4. Process encrypted handshake messages:
    //    try ctx.processCrypto(.Handshake, encrypted_extensions);
    //    try ctx.processCrypto(.Handshake, certificate);
    //    try ctx.processCrypto(.Handshake, certificate_verify);
    //    try ctx.processCrypto(.Handshake, finished);
    //
    // 5. Send client Finished:
    //    const client_finished = ctx.generateFinished();
    //    try quic_conn.sendCryptoFrame(.Handshake, client_finished);
    //
    // 6. Handshake complete - application data can flow

    std.debug.print("\nClient example completed. In production, integrate with QUIC transport.\n", .{});
}
