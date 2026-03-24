// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros
//
//! Basic TLS 1.3 Server Example
//!
//! Demonstrates how to initialize a TLS 1.3 server context for QUIC integration.
//! Shows server-specific configuration including:
//! - Certificate and private key setup
//! - Server-side ALPN selection
//! - Processing client handshake messages
//!
//! ## RFC References
//! - RFC 8446 Section 4.1.3: ServerHello
//! - RFC 8446 Section 4.4.2: Certificate message
//! - RFC 8446 Section 4.4.3: CertificateVerify
//! - RFC 9001: QUIC-TLS integration

const std = @import("std");
const ztls = @import("ztls");

/// Callback: Called when new traffic secrets become available.
fn onSecretAvailable(ctx: *ztls.Context, level: ztls.EncryptionLevel, secret: []const u8) anyerror!void {
    _ = ctx;
    std.debug.print("[Server] Secret available at level {}: {} bytes\n", .{ level, secret.len });
}

/// Callback: Called when handshake completes successfully.
fn onHandshakeComplete(ctx: *ztls.Context) anyerror!void {
    _ = ctx;
    std.debug.print("[Server] TLS handshake completed!\n", .{});
}

/// Callback: Called when client's Finished message is verified.
fn onPeerFinished(ctx: *ztls.Context) anyerror!void {
    _ = ctx;
    std.debug.print("[Server] Client Finished verified\n", .{});
}

/// Callback: Fetch certificate chain for server authentication.
/// RFC 8446 Section 4.4.2: Certificate message structure.
fn fetchCertificateChain(ctx: *ztls.Context) anyerror![]const u8 {
    _ = ctx;
    // In real implementation: return DER-encoded certificate chain
    // The first certificate should be the leaf (server identity)
    return &[_]u8{};
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Example: In production, load from files
    // const cert_der = try std.fs.cwd().readFileAlloc(allocator, "server.crt.der", 64 * 1024);
    // defer allocator.free(cert_der);
    // const key_der = try std.fs.cwd().readFileAlloc(allocator, "server.key.der", 8 * 1024);
    // defer allocator.free(key_der);

    // Placeholder certificate/key for demonstration
    // In production: use real DER-encoded X.509 certificate and PKCS#8 private key
    const demo_cert: ?[]const u8 = null;
    const demo_key: ?[]const u8 = null;

    // Example QUIC transport parameters for server
    const transport_params = [_]u8{
        // original_destination_connection_id would be set by QUIC
        // max_idle_timeout (0x01): 30000ms
        0x01, 0x02, 0x75, 0x30,
        // initial_max_data (0x04): 10MB
        0x04, 0x04, 0x80, 0xA0,
        0x00, 0x00,
        // initial_max_stream_data_bidi_local (0x05): 256KB
        0x05, 0x04,
        0x80, 0x04, 0x00, 0x00,
    };

    // Configure TLS 1.3 server
    // RFC 8446 Section 4.1.3: ServerHello and server configuration
    const config = ztls.Config{
        .allocator = allocator,
        .role = .Server,

        // Cipher suites the server accepts (in preference order)
        .supported_cipher_suites = &.{
            .TLS_AES_128_GCM_SHA256,
            .TLS_AES_256_GCM_SHA384,
            .TLS_CHACHA20_POLY1305_SHA256,
        },

        // Key exchange groups supported
        .supported_groups = &.{.x25519},

        // Signature algorithms for CertificateVerify
        .supported_signature_schemes = &.{
            .ed25519,
            .ecdsa_secp256r1_sha256,
        },

        // ALPN protocols server supports
        // Server selects first match from client's list
        .alpn_protocols = &.{
            "h3", // HTTP/3
            "h3-29", // Draft version fallback
        },

        // QUIC transport parameters (RFC 9001 Section 8.2)
        .quic_transport_parameters = &transport_params,

        // Server certificate (DER-encoded X.509)
        .server_cert_der = demo_cert,

        // Server private key (DER-encoded PKCS#8)
        .server_key_der = demo_key,

        // Enable 0-RTT early data (optional, requires PSK support)
        .enable_early_data = false,
    };

    // Set up callbacks
    const callbacks = ztls.Callbacks{
        .on_secret_available = onSecretAvailable,
        .on_handshake_complete = onHandshakeComplete,
        .on_peer_finished = onPeerFinished,
        .fetch_certificate_chain = fetchCertificateChain,
    };

    // Initialize TLS server context
    var ctx = try ztls.Context.init(config, callbacks);
    defer ctx.deinit();

    std.debug.print("TLS 1.3 server context initialized\n", .{});
    std.debug.print("  Role: Server\n", .{});
    std.debug.print("  Cipher suites: {} configured\n", .{config.supported_cipher_suites.len});
    std.debug.print("  ALPN: h3, h3-29\n", .{});

    // Server handshake flow:
    //
    // 1. Receive ClientHello via QUIC CRYPTO frame:
    //    try ctx.processCrypto(.Initial, client_hello_data);
    //
    // 2. After processing ClientHello, TLS generates:
    //    - ServerHello (sent at Initial level)
    //    - EncryptedExtensions (sent at Handshake level)
    //    - Certificate (sent at Handshake level)
    //    - CertificateVerify (sent at Handshake level)
    //    - Finished (sent at Handshake level)
    //
    // 3. Retrieve outgoing data:
    //    while (ctx.getOutgoingCrypto()) |frame| {
    //        try quic_conn.sendCryptoFrame(frame.level, frame.data);
    //    }
    //
    // 4. Receive client Finished:
    //    try ctx.processCrypto(.Handshake, client_finished_data);
    //
    // 5. Handshake complete - application data can flow

    std.debug.print("\nServer example completed. In production, integrate with QUIC transport.\n", .{});
}
