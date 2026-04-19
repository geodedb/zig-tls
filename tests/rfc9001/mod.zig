//! RFC 9001: QUIC-TLS Test Suite
//!
//! This module organizes tests for QUIC's use of TLS 1.3 per RFC 9001.
//!
//! ## Test Organization
//!
//! Tests are organized by RFC 9001 section:
//! - §4: Carrying TLS Messages in QUIC (CRYPTO frames)
//! - §5: Packet Protection (AEAD, header protection)
//! - §5.1: Packet Protection Keys (initial secrets, handshake keys, application keys)
//! - §5.2: Initial Secrets (special handling for Initial packets)
//! - §5.3: AEAD Usage (limits, key updates)
//! - §5.4: Header Protection
//! - §8: QUIC-Specific Adjustments to TLS
//! - §8.2: QUIC Transport Parameters Extension
//! - Appendix A: Sample Packet Protection
//!
//! ## Usage
//!
//! Run all RFC 9001 tests:
//! ```bash
//! zig build test-rfc9001
//! ```
//!
//! Run specific section tests:
//! ```bash
//! zig test tests/rfc9001/appendix_a_initial_secrets.zig
//! ```
//!
//! ## Key Differences from RFC 8446
//!
//! RFC 9001 specifies QUIC-specific TLS behavior:
//! 1. **No TLS record layer**: TLS messages carried in CRYPTO frames
//! 2. **Initial secrets**: Derived from connection ID, not handshake
//! 3. **Packet protection**: Uses TLS traffic secrets but QUIC framing
//! 4. **Header protection**: Additional encryption for packet headers
//! 5. **Transport parameters**: Mandatory extension (0x0039) in EncryptedExtensions
//! 6. **Version-specific salts**: QUIC v1 and v2 use different initial salts

const std = @import("std");

// Re-export test modules for discovery
pub const section_4_crypto_frames = @import("section_4_crypto_frames.zig");
pub const section_8_2_transport_params = @import("section_8_2_transport_params.zig");
pub const appendix_a_initial_secrets = @import("appendix_a_initial_secrets.zig");
pub const section_5_packet_protection = @import("section_5_packet_protection.zig");
pub const section_5_4_header_protection = @import("section_5_4_header_protection.zig");
pub const section_5_5_retry_integrity = @import("section_5_5_retry_integrity.zig");

test {
    std.testing.refAllDecls(@This());
}
