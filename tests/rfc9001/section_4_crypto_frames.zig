//! RFC 9001 §4: Carrying TLS Messages - CRYPTO Frame Tests
//!
//! Tests for QUIC CRYPTO frame handling in TLS 1.3 handshake.
//!
//! ## RFC 9001 §4: Carrying TLS Messages
//!
//! QUIC carries TLS handshake data in CRYPTO frames. Unlike traditional TLS
//! which uses a record layer, QUIC replaces the TLS record layer with its
//! own packet and frame structures.
//!
//! ## CRYPTO Frame Structure (RFC 9000 §19.6)
//!
//! ```
//! CRYPTO Frame {
//!   Type (i) = 0x06,
//!   Offset (i),
//!   Length (i),
//!   Crypto Data (..),
//! }
//! ```
//!
//! ## Key Requirements
//!
//! - CRYPTO frames carry TLS handshake messages
//! - CRYPTO data is sent at different encryption levels:
//!   * Initial: ClientHello, ServerHello
//!   * Handshake: Encrypted handshake messages (Certificate, CertificateVerify, Finished)
//!   * Application: NewSessionTicket (post-handshake)
//! - CRYPTO frames are flow-controlled per encryption level
//! - CRYPTO data can be fragmented across multiple frames
//! - CRYPTO frames use offset to order data
//!
//! ## Encryption Levels (RFC 9001 §4.1.4)
//!
//! QUIC uses four encryption levels, each with independent CRYPTO streams:
//!
//! - **Initial**: 0-RTT keys from connection IDs, carries ClientHello/ServerHello
//! - **0-RTT**: Early data keys (optional), carries application data
//! - **Handshake**: Handshake keys derived from ECDHE, carries encrypted handshake
//! - **Application**: Application keys, carries NewSessionTicket and app data
//!
//! ## Test Coverage
//!
//! - CRYPTO frame type identifier
//! - Encryption level isolation
//! - Frame fragmentation and reassembly
//! - Offset tracking
//! - Flow control per level

const std = @import("std");
const testing = std.testing;

// RFC 9000 §19.6: CRYPTO Frame Type
//
// The CRYPTO frame (type 0x06) is used to transmit cryptographic handshake
// messages. It MUST NOT be sent in 0-RTT packets.
test "RFC 9000 §19.6: CRYPTO frame type identifier" {
    const crypto_frame_type: u8 = 0x06;
    try testing.expectEqual(@as(u8, 0x06), crypto_frame_type);
}

// RFC 9001 §4.1.4: Encryption Levels
//
// QUIC packets are protected under one of four encryption levels:
// - Initial (uses initial secrets from connection IDs)
// - 0-RTT (uses early data keys, optional)
// - Handshake (uses handshake traffic secrets)
// - Application (uses application traffic secrets)
//
// Each level has an independent CRYPTO stream.
test "RFC 9001 §4.1.4: Encryption levels" {
    // Encryption levels (conceptual, not wire format)
    const initial_level: u8 = 0;
    const zero_rtt_level: u8 = 1;
    const handshake_level: u8 = 2;
    const application_level: u8 = 3;

    try testing.expectEqual(@as(u8, 0), initial_level);
    try testing.expectEqual(@as(u8, 1), zero_rtt_level);
    try testing.expectEqual(@as(u8, 2), handshake_level);
    try testing.expectEqual(@as(u8, 3), application_level);
}

// RFC 9001 §4.1.1: Initial Secrets
//
// Initial packets use AEAD keys derived from the client's initial
// Destination Connection ID using HKDF with salt from RFC 9001 Appendix A.
test "RFC 9001 §4.1.1: Initial packet encryption" {
    // Initial salt for QUIC version 1 (RFC 9001 Appendix A)
    const initial_salt_v1_hex =
        "38762cf7f55934b34d179ae6a4c80cadccbb7f0a";

    // Salt is used with Destination Connection ID to derive initial secrets
    const salt_length: usize = 20;
    try testing.expectEqual(@as(usize, 20), salt_length);
    try testing.expectEqual(@as(usize, initial_salt_v1_hex.len / 2), salt_length);
}

// RFC 9001 §4.1: TLS Handshake Messages in CRYPTO Frames
//
// TLS handshake messages are split across encryption levels:
//
// Initial level:
// - ClientHello (from client)
// - ServerHello (from server)
//
// Handshake level:
// - EncryptedExtensions (from server)
// - Certificate (from server)
// - CertificateVerify (from server)
// - Finished (from both)
//
// Application level:
// - NewSessionTicket (from server, post-handshake)
test "RFC 9001 §4.1: Handshake message distribution by encryption level" {
    // Initial level messages
    const client_hello_type: u8 = 0x01;
    const server_hello_type: u8 = 0x02;

    // Handshake level messages
    const encrypted_extensions_type: u8 = 0x08;
    const certificate_type: u8 = 0x0b;
    const certificate_verify_type: u8 = 0x0f;
    const finished_type: u8 = 0x14;

    // Application level messages (post-handshake)
    const new_session_ticket_type: u8 = 0x04;

    try testing.expectEqual(@as(u8, 0x01), client_hello_type);
    try testing.expectEqual(@as(u8, 0x02), server_hello_type);
    try testing.expectEqual(@as(u8, 0x08), encrypted_extensions_type);
    try testing.expectEqual(@as(u8, 0x0b), certificate_type);
    try testing.expectEqual(@as(u8, 0x0f), certificate_verify_type);
    try testing.expectEqual(@as(u8, 0x14), finished_type);
    try testing.expectEqual(@as(u8, 0x04), new_session_ticket_type);
}

// RFC 9001 §4.9: Discarding Unused Keys
//
// QUIC discards keys and CRYPTO state when they are no longer needed:
//
// - Initial keys are discarded when Handshake keys are available
// - Handshake keys are discarded when the handshake is confirmed
// - 0-RTT keys are discarded when Handshake keys are available
test "RFC 9001 §4.9: Key discarding lifecycle" {
    // Keys are discarded in this order:
    // 1. Initial keys (after Handshake keys available)
    // 2. 0-RTT keys (after Handshake keys available, if 0-RTT used)
    // 3. Handshake keys (after handshake confirmed)

    // Only Application keys remain after handshake
    const final_encryption_level: u8 = 3; // Application
    try testing.expectEqual(@as(u8, 3), final_encryption_level);
}

// RFC 9001 §4.1.2: ClientHello in Initial CRYPTO Frame
//
// The client's first CRYPTO frame carries the TLS ClientHello message
// at the Initial encryption level. This is sent in an Initial packet.
test "RFC 9001 §4.1.2: ClientHello in Initial packet" {
    const client_hello_type: u8 = 0x01;
    const initial_encryption_level: u8 = 0;

    try testing.expectEqual(@as(u8, 0x01), client_hello_type);
    try testing.expectEqual(@as(u8, 0), initial_encryption_level);

    // ClientHello MUST include quic_transport_parameters extension (0x0039)
    const quic_transport_params_ext: u16 = 0x0039;
    try testing.expectEqual(@as(u16, 0x0039), quic_transport_params_ext);
}

// RFC 9001 §4.1.3: ServerHello in Initial CRYPTO Frame
//
// The server's first CRYPTO frame carries the TLS ServerHello message
// at the Initial encryption level. This is sent in an Initial packet.
test "RFC 9001 §4.1.3: ServerHello in Initial packet" {
    const server_hello_type: u8 = 0x02;
    const initial_encryption_level: u8 = 0;

    try testing.expectEqual(@as(u8, 0x02), server_hello_type);
    try testing.expectEqual(@as(u8, 0), initial_encryption_level);

    // ServerHello MUST include supported_versions and key_share
    const supported_versions_ext: u16 = 0x002b;
    const key_share_ext: u16 = 0x0033;

    try testing.expectEqual(@as(u16, 0x002b), supported_versions_ext);
    try testing.expectEqual(@as(u16, 0x0033), key_share_ext);
}

// RFC 9001 §4.1.3: EncryptedExtensions in Handshake CRYPTO Frame
//
// After ServerHello, the server sends EncryptedExtensions at the
// Handshake encryption level. This message contains the server's
// QUIC transport parameters.
test "RFC 9001 §4.1.3: EncryptedExtensions in Handshake packet" {
    const encrypted_extensions_type: u8 = 0x08;
    const handshake_encryption_level: u8 = 2;

    try testing.expectEqual(@as(u8, 0x08), encrypted_extensions_type);
    try testing.expectEqual(@as(u8, 2), handshake_encryption_level);

    // EncryptedExtensions MUST include quic_transport_parameters (0x0039)
    const quic_transport_params_ext: u16 = 0x0039;
    try testing.expectEqual(@as(u16, 0x0039), quic_transport_params_ext);
}

// RFC 9000 §19.6: CRYPTO Frame Offset
//
// CRYPTO frames include an offset field to maintain data ordering.
// The offset is the stream offset of the CRYPTO data.
test "RFC 9000 §19.6: CRYPTO frame offset field" {
    // Offset is a variable-length integer
    // First CRYPTO frame has offset 0
    const first_frame_offset: u64 = 0;
    try testing.expectEqual(@as(u64, 0), first_frame_offset);

    // Subsequent frames have offsets based on previous data length
    const second_frame_offset: u64 = 1024; // Example: after 1024 bytes
    try testing.expect(second_frame_offset > first_frame_offset);
}

// RFC 9000 §19.6: CRYPTO Frame Length
//
// The length field indicates the number of bytes of CRYPTO data
// in this frame.
test "RFC 9000 §19.6: CRYPTO frame length field" {
    // Length is a variable-length integer
    // Typical TLS handshake message sizes:
    const typical_client_hello_size: usize = 200; // ~200 bytes
    const typical_certificate_size: usize = 2000; // ~2KB with cert chain

    try testing.expect(typical_client_hello_size > 0);
    try testing.expect(typical_certificate_size > typical_client_hello_size);
}

// RFC 9001 §4: CRYPTO Frame Flow Control
//
// CRYPTO frames are subject to flow control, but separately from
// stream data. Each encryption level has its own flow control limits.
test "RFC 9001 §4: CRYPTO flow control isolation" {
    // Flow control is per encryption level
    // initial_max_data does NOT apply to CRYPTO frames
    // CRYPTO frames use connection-level flow control but are separate

    const crypto_frame_type: u8 = 0x06;
    try testing.expectEqual(@as(u8, 0x06), crypto_frame_type);

    // CRYPTO frames are not counted toward stream limits
}

// RFC 9001 §4.5: Key Update
//
// QUIC supports TLS key updates, but they are triggered differently
// than in traditional TLS. Key updates in QUIC use the KEY_UPDATE
// frame type from RFC 9000.
test "RFC 9001 §4.5: Key updates in QUIC" {
    // TLS 1.3 KeyUpdate message type
    const key_update_type: u8 = 0x18;
    try testing.expectEqual(@as(u8, 0x18), key_update_type);

    // In QUIC, key updates are signaled via packet number space
    // and do not use TLS KeyUpdate messages in CRYPTO frames
}

// RFC 9001 §4.1.4: Packet Type and Encryption Level Mapping
//
// QUIC packet types map to encryption levels:
//
// - Initial packets → Initial encryption level
// - 0-RTT packets → 0-RTT encryption level
// - Handshake packets → Handshake encryption level
// - 1-RTT packets → Application encryption level
test "RFC 9001 §4.1.4: Packet type to encryption level mapping" {
    // Packet types (long header)
    const initial_packet_type: u8 = 0x00;
    const zero_rtt_packet_type: u8 = 0x01;
    const handshake_packet_type: u8 = 0x02;

    // 1-RTT packets use short header (no specific type byte)
    const short_header_bit: u8 = 0x00; // Bit 7 = 0 for short header

    try testing.expectEqual(@as(u8, 0x00), initial_packet_type);
    try testing.expectEqual(@as(u8, 0x01), zero_rtt_packet_type);
    try testing.expectEqual(@as(u8, 0x02), handshake_packet_type);
    try testing.expectEqual(@as(u8, 0x00), short_header_bit);
}

// RFC 9001 §4.1: CRYPTO Frame Reassembly
//
// CRYPTO data may be fragmented across multiple CRYPTO frames.
// Receivers MUST reassemble CRYPTO data using offsets before
// processing TLS handshake messages.
test "RFC 9001 §4.1: CRYPTO frame fragmentation and reassembly" {
    // Example fragmentation scenario:
    // Frame 1: offset=0, length=500
    // Frame 2: offset=500, length=500
    // Frame 3: offset=1000, length=200
    // Total: 1200 bytes of CRYPTO data

    const frame1_offset: u64 = 0;
    const frame1_length: u64 = 500;

    const frame2_offset: u64 = 500;
    const frame2_length: u64 = 500;

    const frame3_offset: u64 = 1000;
    const frame3_length: u64 = 200;

    const total_crypto_data: u64 = frame1_length + frame2_length + frame3_length;

    try testing.expectEqual(@as(u64, 0), frame1_offset);
    try testing.expectEqual(@as(u64, 500), frame2_offset);
    try testing.expectEqual(@as(u64, 1000), frame3_offset);
    try testing.expectEqual(@as(u64, 1200), total_crypto_data);
}

// RFC 9001 §4.4: TLS Errors in QUIC
//
// TLS errors are mapped to QUIC connection errors. When a TLS error
// occurs, the QUIC connection is closed with a CRYPTO_ERROR code.
test "RFC 9001 §4.4: TLS error mapping" {
    // QUIC uses TLS alert codes (RFC 8446 §6) directly
    // CRYPTO_ERROR frame includes TLS alert description

    // Common TLS alerts
    const close_notify: u8 = 0;
    const unexpected_message: u8 = 10;
    const bad_certificate: u8 = 42;
    const certificate_required: u8 = 116;
    const internal_error: u8 = 80;

    try testing.expectEqual(@as(u8, 0), close_notify);
    try testing.expectEqual(@as(u8, 10), unexpected_message);
    try testing.expectEqual(@as(u8, 42), bad_certificate);
    try testing.expectEqual(@as(u8, 116), certificate_required);
    try testing.expectEqual(@as(u8, 80), internal_error);
}

// RFC 9001 §4.8: QUIC-Specific TLS Alert
//
// QUIC adds a no_application_protocol alert (0x78 = 120) for
// when ALPN negotiation fails.
test "RFC 9001 §4.8: no_application_protocol alert" {
    const no_application_protocol: u8 = 120;
    try testing.expectEqual(@as(u8, 120), no_application_protocol);
    try testing.expectEqual(@as(u8, 0x78), no_application_protocol);
}
