# Engine to Context Migration Guide

> **Status:** Engine is marked **LEGACY** in `src/tls13/engine.zig`. New code should use Context.
> **Last updated:** 2026-03-24

## Overview

The `Engine` struct was the original TLS 1.3 handshake driver, designed for testing with simplified message formats. The `Context` struct is the production replacement, providing full RFC 8446 compliance, callback-based QUIC integration, and features like mTLS, OCSP stapling, and SCT validation.

This guide covers how to migrate from Engine to Context.

## API Mapping

| Engine | Context | Notes |
|--------|---------|-------|
| `Engine.init(allocator, role)` | `Context.init(config, callbacks)` | Context uses Config struct instead of individual setters |
| `Engine.deinit()` | `Context.deinit()` | Same lifecycle semantics |
| `Engine.onCryptoRecv(data)` | `Context.processCrypto(level, data)` | Context requires encryption level |
| `Engine.flushCrypto(allocator)` | Read from `Context.streams` outbound buffers | Context does not copy; caller reads outbound directly |
| `Engine.handshakeComplete()` | `Context.handshakeComplete()` | Same semantics |
| `Engine.setServerName(name)` | `config.server_name = name` | Set at construction via Config |
| `Engine.setServerCertificate(cert, key, alg)` | `config.server_cert_der = cert; config.server_key_der = key` | Algorithm inferred from key type |
| `Engine.setAllowInsecure(true)` | `config.allow_insecure = true` | Same behavior; panics in release |
| `Engine.setTransportParameters(tp)` | `config.quic_transport_parameters = tp` | Or call `Context.setTransportParameters()` |
| `engine.peer_tp` (direct field access) | `Callbacks.on_handshake_metadata` | Peer transport params delivered via callback |
| `engine.alpn` (direct field access) | `Callbacks.on_handshake_metadata` | Negotiated ALPN delivered via callback |
| `engine.tickets` (TicketStore) | `Callbacks.on_session_ticket` | Tickets delivered via callback (WIP) |
| `engine.peer_finished_cb` | `Callbacks.on_peer_finished` | Same concept, different registration |

## Key Behavioral Differences

### 1. Configuration Model

Engine uses a mutable-state model where you set fields after construction:

```zig
// Engine (old)
var engine = Engine.init(allocator, .Client);
try engine.setServerName("example.com");
engine.setAllowInsecure(true);
```

Context uses an immutable Config struct at construction:

```zig
// Context (new)
const config = Config{
    .allocator = allocator,
    .role = .Client,
    .server_name = "example.com",
    .allow_insecure = true,  // Debug only!
};
var ctx = try Context.init(config, callbacks);
```

### 2. Callback-Based Architecture

Engine requires polling for results. Context pushes events via callbacks:

```zig
// Engine (old) - polling
try engine.onCryptoRecv(data);
const crypto_out = try engine.flushCrypto(allocator);
// ... manually check engine.handshakeComplete(), engine.peer_tp, etc.

// Context (new) - event-driven
const callbacks = Callbacks{
    .on_secret_available = mySecretHandler,       // Traffic secrets
    .on_handshake_metadata = myMetadataHandler,   // ALPN + transport params
    .on_peer_finished = myFinishedHandler,         // Peer Finished verified
    .on_handshake_complete = myCompleteHandler,    // Handshake done
};
var ctx = try Context.init(config, callbacks);
try ctx.processCrypto(.Initial, data);
// Results delivered via callbacks automatically
```

### 3. Encryption Levels

Engine does not track encryption levels (all data goes through a single `onCryptoRecv` / `flushCrypto` pair). Context explicitly tracks QUIC encryption levels:

```zig
// Context processes data at specific encryption levels
try ctx.processCrypto(.Initial, initial_crypto_data);
try ctx.processCrypto(.Handshake, handshake_crypto_data);
```

### 4. Error Handling

Engine uses boolean flags (`peer_cert_ok`, `handshake_failed`) and some errors are swallowed silently. Context returns errors from `processCrypto` and propagates errors through callbacks.

### 5. Message Format

Engine supports both "minimal" (testing) and "standard" (real TLS) message formats. Context auto-detects the format but is designed primarily for standard RFC 8446 messages.

## What's Only in Engine

These features exist only in Engine and have no direct Context equivalent:

- **NewSessionTicket with full PSK derivation**: Engine processes NewSessionTicket messages and derives resumption PSK internally via `TicketStore`. Context has partial support (`on_session_ticket` callback is defined but not fully wired).

- **Minimal message format**: Engine supports a simplified message encoding used by early tests. Context focuses on standard RFC 8446 encoding.

- **Direct field access**: Engine exposes internal state fields directly (`peer_tp`, `alpn`, `leaf_spki`, etc.). Context encapsulates state and delivers it via callbacks.

## What's Only in Context

These features exist only in Context:

- **Callback-based API**: Event-driven integration with QUIC stack via `Callbacks`.
- **mTLS support**: Full mutual TLS with `request_client_cert`, `client_cert_der`, `client_key_der` configuration.
- **OCSP stapling validation**: `require_ocsp` in Config, with OCSP response parsing.
- **SCT validation**: `require_scts` and `on_sct_list` callback for Certificate Transparency.
- **HelloRetryRequest (HRR)**: Full server-side HRR with cookie generation and client-side HRR handling.
- **0-RTT anti-replay**: Lazy-allocated `AntiReplayWindow` with `zero_rtt_limits` configuration.
- **PSK/resumption support**: External PSK and ticket-based resumption via Config fields.
- **QUIC transport parameter validation**: Per-role validation rejecting invalid transport parameters.
- **Encryption level tracking**: Per-level CRYPTO buffers for proper QUIC integration.

## Migration Checklist

1. Replace `Engine.init(allocator, role)` with `Config` struct + `Context.init(config, callbacks)`.
2. Implement `Callbacks` for events you previously polled:
   - `on_secret_available` for traffic secret installation
   - `on_handshake_metadata` for ALPN and transport parameters
   - `on_handshake_complete` for handshake completion
3. Replace `engine.onCryptoRecv(data)` with `ctx.processCrypto(level, data)`, passing the correct encryption level.
4. Replace `engine.flushCrypto(allocator)` with reading from Context's outbound CRYPTO buffers.
5. Move `setServerName`, `setServerCertificate`, `setAllowInsecure` calls into Config fields.
6. Replace direct field access (`engine.peer_tp`, `engine.alpn`) with callback-based delivery.
7. Add mTLS, OCSP, SCT configuration if needed (new capabilities).
8. Update error handling: Context returns errors from `processCrypto` instead of setting boolean flags.

## Recommendation

Use Context for all new code. Engine remains available for existing tests that rely on its simplified interface, but should not be used for production QUIC integration.
