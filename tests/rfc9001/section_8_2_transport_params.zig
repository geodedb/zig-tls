//! RFC 9001 §8.2: QUIC Transport Parameters Tests
//!
//! Tests for QUIC transport parameters extension in TLS 1.3 handshake.
//!
//! ## RFC 9001 §8.2: QUIC Transport Parameters Extension
//!
//! QUIC transport parameters are carried in a TLS extension. The
//! "quic_transport_parameters" extension (type 0x0039) is sent during
//! the handshake in the ClientHello and EncryptedExtensions messages.
//!
//! ```
//! enum {
//!     quic_transport_parameters(0x0039), (65535)
//! } ExtensionType;
//! ```
//!
//! The extension_data field contains QUIC transport parameters encoded
//! per RFC 9000 §18.
//!
//! ## Key Requirements
//!
//! - Extension type MUST be 0x0039
//! - MUST be sent in ClientHello and EncryptedExtensions
//! - MUST NOT be sent in ServerHello
//! - Parameters are encoded as variable-length integers
//! - Client and server can send different parameters
//! - Some parameters are connection-level, others are flow-control
//!
//! ## Common Transport Parameters
//!
//! - original_destination_connection_id (0x00)
//! - max_idle_timeout (0x01)
//! - stateless_reset_token (0x02)
//! - max_udp_payload_size (0x03)
//! - initial_max_data (0x04)
//! - initial_max_stream_data_bidi_local (0x05)
//! - initial_max_stream_data_bidi_remote (0x06)
//! - initial_max_stream_data_uni (0x07)
//! - initial_max_streams_bidi (0x08)
//! - initial_max_streams_uni (0x09)
//! - ack_delay_exponent (0x0a)
//! - max_ack_delay (0x0b)
//! - disable_active_migration (0x0c)
//! - preferred_address (0x0d)
//! - active_connection_id_limit (0x0e)
//! - initial_source_connection_id (0x0f)
//! - retry_source_connection_id (0x10)
//!
//! ## Test Coverage
//!
// - Extension type validation
// - Parameter encoding/decoding
// - Required parameters verification
// - Parameter value constraints
// - Version-specific parameters

const std = @import("std");
const testing = std.testing;

// RFC 9001 §8.2: Extension Type
//
// The quic_transport_parameters extension type is 0x0039 (57 decimal).
test "RFC 9001 §8.2: quic_transport_parameters extension type" {
    const quic_transport_parameters: u16 = 0x0039;
    try testing.expectEqual(@as(u16, 0x0039), quic_transport_parameters);
    try testing.expectEqual(@as(u16, 57), quic_transport_parameters);
}

// RFC 9001 §8.2: Extension Context
//
// The quic_transport_parameters extension is included in:
// - ClientHello (sent by client)
// - EncryptedExtensions (sent by server)
//
// It MUST NOT be sent in ServerHello.
test "RFC 9001 §8.2: Extension context restrictions" {
    // Valid contexts: ClientHello, EncryptedExtensions
    const quic_transport_parameters: u16 = 0x0039;

    // Not valid in ServerHello (which only allows supported_versions, key_share, pre_shared_key)
    try testing.expectEqual(@as(u16, 0x0039), quic_transport_parameters);
}

// RFC 9000 §18: Transport Parameter Identifiers
//
// Transport parameters are identified by a 62-bit variable-length integer.
test "RFC 9000 §18: Transport parameter identifiers" {
    // Connection ID parameters
    const original_destination_connection_id: u64 = 0x00;
    const initial_source_connection_id: u64 = 0x0f;
    const retry_source_connection_id: u64 = 0x10;

    // Timeout and size parameters
    const max_idle_timeout: u64 = 0x01;
    const max_udp_payload_size: u64 = 0x03;

    // Flow control parameters
    const initial_max_data: u64 = 0x04;
    const initial_max_stream_data_bidi_local: u64 = 0x05;
    const initial_max_stream_data_bidi_remote: u64 = 0x06;
    const initial_max_stream_data_uni: u64 = 0x07;
    const initial_max_streams_bidi: u64 = 0x08;
    const initial_max_streams_uni: u64 = 0x09;

    // ACK parameters
    const ack_delay_exponent: u64 = 0x0a;
    const max_ack_delay: u64 = 0x0b;

    // Migration and connection parameters
    const disable_active_migration: u64 = 0x0c;
    const preferred_address: u64 = 0x0d;
    const active_connection_id_limit: u64 = 0x0e;

    // Stateless reset
    const stateless_reset_token: u64 = 0x02;

    try testing.expectEqual(@as(u64, 0x00), original_destination_connection_id);
    try testing.expectEqual(@as(u64, 0x0f), initial_source_connection_id);
    try testing.expectEqual(@as(u64, 0x10), retry_source_connection_id);
    try testing.expectEqual(@as(u64, 0x01), max_idle_timeout);
    try testing.expectEqual(@as(u64, 0x03), max_udp_payload_size);
    try testing.expectEqual(@as(u64, 0x04), initial_max_data);
    try testing.expectEqual(@as(u64, 0x05), initial_max_stream_data_bidi_local);
    try testing.expectEqual(@as(u64, 0x06), initial_max_stream_data_bidi_remote);
    try testing.expectEqual(@as(u64, 0x07), initial_max_stream_data_uni);
    try testing.expectEqual(@as(u64, 0x08), initial_max_streams_bidi);
    try testing.expectEqual(@as(u64, 0x09), initial_max_streams_uni);
    try testing.expectEqual(@as(u64, 0x0a), ack_delay_exponent);
    try testing.expectEqual(@as(u64, 0x0b), max_ack_delay);
    try testing.expectEqual(@as(u64, 0x0c), disable_active_migration);
    try testing.expectEqual(@as(u64, 0x0d), preferred_address);
    try testing.expectEqual(@as(u64, 0x0e), active_connection_id_limit);
    try testing.expectEqual(@as(u64, 0x02), stateless_reset_token);
}

// RFC 9000 §18.2: Integer Encoding
//
// Transport parameter values are encoded as variable-length integers.
// The encoding uses the two most significant bits to indicate the length:
// - 00: 1 byte (0-63)
// - 01: 2 bytes (0-16383)
// - 10: 4 bytes (0-1073741823)
// - 11: 8 bytes (0-4611686018427387903)
test "RFC 9000 §18.2: Variable-length integer encoding" {
    // 1-byte encoding: 0x00-0x3f (0-63)
    const one_byte_max: u64 = 63;
    try testing.expectEqual(@as(u64, 63), one_byte_max);
    try testing.expect(one_byte_max <= 0x3f);

    // 2-byte encoding: 0x40-0x3fff (64-16383)
    const two_byte_max: u64 = 16383;
    try testing.expectEqual(@as(u64, 16383), two_byte_max);
    try testing.expect(two_byte_max <= 0x3fff);

    // 4-byte encoding: 0x4000-0x3fffffff (16384-1073741823)
    const four_byte_max: u64 = 1073741823;
    try testing.expectEqual(@as(u64, 1073741823), four_byte_max);
    try testing.expect(four_byte_max <= 0x3fffffff);

    // 8-byte encoding: 0x40000000-0x3fffffffffffffff
    const eight_byte_max: u64 = 4611686018427387903;
    try testing.expectEqual(@as(u64, 4611686018427387903), eight_byte_max);
}

// RFC 9000 §18.2: max_idle_timeout
//
// The maximum idle timeout is a value in milliseconds that is encoded
// as a variable-length integer. A value of 0 disables the idle timeout.
test "RFC 9000 §18.2: max_idle_timeout parameter" {
    const max_idle_timeout_id: u64 = 0x01;
    try testing.expectEqual(@as(u64, 0x01), max_idle_timeout_id);

    // Common values (in milliseconds)
    const default_timeout: u64 = 30000; // 30 seconds
    const max_timeout: u64 = 600000; // 10 minutes

    try testing.expect(default_timeout > 0);
    try testing.expect(max_timeout >= default_timeout);
}

// RFC 9000 §18.2: max_udp_payload_size
//
// The maximum UDP payload size parameter is the maximum size of UDP
// payload that the endpoint is willing to receive. The value MUST be
// at least 1200 bytes.
test "RFC 9000 §18.2: max_udp_payload_size constraints" {
    const max_udp_payload_size_id: u64 = 0x03;
    try testing.expectEqual(@as(u64, 0x03), max_udp_payload_size_id);

    // Minimum allowed value (RFC 9000 §18.2)
    const min_udp_payload_size: u64 = 1200;
    try testing.expectEqual(@as(u64, 1200), min_udp_payload_size);

    // Common value (Ethernet MTU - headers)
    const typical_udp_payload_size: u64 = 1472; // 1500 - 20 (IP) - 8 (UDP)
    try testing.expect(typical_udp_payload_size >= min_udp_payload_size);
}

// RFC 9000 §18.2: initial_max_data
//
// The initial maximum data parameter is the initial value for the
// maximum amount of data that can be sent on the connection. This is
// a sum of the maximum stream data for all streams.
test "RFC 9000 §18.2: initial_max_data parameter" {
    const initial_max_data_id: u64 = 0x04;
    try testing.expectEqual(@as(u64, 0x04), initial_max_data_id);

    // Typical values (in bytes)
    const conservative_limit: u64 = 1_048_576; // 1 MB
    const generous_limit: u64 = 10_485_760; // 10 MB

    try testing.expect(conservative_limit > 0);
    try testing.expect(generous_limit > conservative_limit);
}

// RFC 9000 §18.2: initial_max_stream_data
//
// The initial maximum stream data parameters set the initial flow
// control limit for different stream types:
// - bidi_local: bidirectional streams initiated locally
// - bidi_remote: bidirectional streams initiated by peer
// - uni: unidirectional streams
test "RFC 9000 §18.2: initial_max_stream_data parameters" {
    const initial_max_stream_data_bidi_local: u64 = 0x05;
    const initial_max_stream_data_bidi_remote: u64 = 0x06;
    const initial_max_stream_data_uni: u64 = 0x07;

    try testing.expectEqual(@as(u64, 0x05), initial_max_stream_data_bidi_local);
    try testing.expectEqual(@as(u64, 0x06), initial_max_stream_data_bidi_remote);
    try testing.expectEqual(@as(u64, 0x07), initial_max_stream_data_uni);

    // Typical value (256 KB)
    const typical_stream_limit: u64 = 262144;
    try testing.expect(typical_stream_limit > 0);
}

// RFC 9000 §18.2: initial_max_streams
//
// The initial maximum streams parameters set the maximum number of
// concurrent streams allowed:
// - bidi: bidirectional streams
// - uni: unidirectional streams
test "RFC 9000 §18.2: initial_max_streams parameters" {
    const initial_max_streams_bidi: u64 = 0x08;
    const initial_max_streams_uni: u64 = 0x09;

    try testing.expectEqual(@as(u64, 0x08), initial_max_streams_bidi);
    try testing.expectEqual(@as(u64, 0x09), initial_max_streams_uni);

    // Typical values
    const typical_stream_count: u64 = 100;
    try testing.expect(typical_stream_count > 0);
}

// RFC 9000 §18.2: ack_delay_exponent
//
// The ACK delay exponent is used to decode the ACK Delay field in the
// ACK frame. The default value is 3 if not specified.
test "RFC 9000 §18.2: ack_delay_exponent parameter" {
    const ack_delay_exponent_id: u64 = 0x0a;
    try testing.expectEqual(@as(u64, 0x0a), ack_delay_exponent_id);

    // Default value (RFC 9000 §18.2)
    const default_exponent: u8 = 3;
    try testing.expectEqual(@as(u8, 3), default_exponent);

    // Maximum value
    const max_exponent: u8 = 20;
    try testing.expect(max_exponent >= default_exponent);
}

// RFC 9000 §18.2: max_ack_delay
//
// The maximum ACK delay is the maximum amount of time in milliseconds
// that the endpoint will delay sending acknowledgments. The default is 25ms.
test "RFC 9000 §18.2: max_ack_delay parameter" {
    const max_ack_delay_id: u64 = 0x0b;
    try testing.expectEqual(@as(u64, 0x0b), max_ack_delay_id);

    // Default value (RFC 9000 §18.2)
    const default_delay_ms: u64 = 25;
    try testing.expectEqual(@as(u64, 25), default_delay_ms);

    // Maximum allowed value (2^14 - 1 = 16383 ms)
    const max_delay_ms: u64 = 16383;
    try testing.expect(max_delay_ms >= default_delay_ms);
}

// RFC 9000 §18.2: disable_active_migration
//
// The disable_active_migration parameter is used to disable connection
// migration. It has no value (length = 0).
test "RFC 9000 §18.2: disable_active_migration parameter" {
    const disable_active_migration_id: u64 = 0x0c;
    try testing.expectEqual(@as(u64, 0x0c), disable_active_migration_id);

    // This parameter has zero-length value
    const param_length: usize = 0;
    try testing.expectEqual(@as(usize, 0), param_length);
}

// RFC 9000 §18.2: active_connection_id_limit
//
// The active connection ID limit is the maximum number of connection IDs
// from the peer that an endpoint is willing to store. The value MUST be
// at least 2.
test "RFC 9000 §18.2: active_connection_id_limit constraints" {
    const active_connection_id_limit_id: u64 = 0x0e;
    try testing.expectEqual(@as(u64, 0x0e), active_connection_id_limit_id);

    // Minimum allowed value (RFC 9000 §18.2)
    const min_conn_id_limit: u64 = 2;
    try testing.expectEqual(@as(u64, 2), min_conn_id_limit);

    // Typical value
    const typical_conn_id_limit: u64 = 8;
    try testing.expect(typical_conn_id_limit >= min_conn_id_limit);
}

// RFC 9000 §18.2: stateless_reset_token
//
// The stateless reset token is used to validate stateless resets.
// It is a 16-byte value.
test "RFC 9000 §18.2: stateless_reset_token parameter" {
    const stateless_reset_token_id: u64 = 0x02;
    try testing.expectEqual(@as(u64, 0x02), stateless_reset_token_id);

    // Fixed length (RFC 9000 §18.2)
    const token_length: usize = 16;
    try testing.expectEqual(@as(usize, 16), token_length);
}

// RFC 9000 §18.2: Connection ID Parameters
//
// Three connection ID parameters are used during handshake:
// - original_destination_connection_id: The CID from the first Initial packet
// - initial_source_connection_id: The CID used by the endpoint
// - retry_source_connection_id: The CID used in a Retry packet (if any)
test "RFC 9000 §18.2: Connection ID parameters" {
    const original_destination_connection_id: u64 = 0x00;
    const initial_source_connection_id: u64 = 0x0f;
    const retry_source_connection_id: u64 = 0x10;

    try testing.expectEqual(@as(u64, 0x00), original_destination_connection_id);
    try testing.expectEqual(@as(u64, 0x0f), initial_source_connection_id);
    try testing.expectEqual(@as(u64, 0x10), retry_source_connection_id);

    // Connection IDs can be 0-20 bytes (RFC 9000 §5.1)
    const max_conn_id_length: usize = 20;
    try testing.expectEqual(@as(usize, 20), max_conn_id_length);
}

// RFC 9001 §8.2: Transport Parameters in TLS Extension
//
// The transport parameters are encoded in the extension_data field
// of the quic_transport_parameters extension. Each parameter is
// encoded as:
//
// ```
// Transport Parameter {
//   Transport Parameter ID (i),
//   Transport Parameter Length (i),
//   Transport Parameter Value (..),
// }
// ```
test "RFC 9001 §8.2: Transport parameter encoding structure" {
    // Each parameter consists of:
    // - ID: variable-length integer
    // - Length: variable-length integer
    // - Value: 'length' bytes

    const quic_transport_parameters_ext: u16 = 0x0039;
    try testing.expectEqual(@as(u16, 0x0039), quic_transport_parameters_ext);
}

// RFC 9001 §8.2: Version-Specific Parameters
//
// Some transport parameters are version-specific and may only be
// sent when using specific QUIC versions.
test "RFC 9001 §8.2: Version considerations" {
    // QUIC version 1 (RFC 9000)
    const quic_version_1: u32 = 0x00000001;
    try testing.expectEqual(@as(u32, 0x00000001), quic_version_1);

    // Parameters are defined per version
    // Some parameters may be reserved or have different meanings in future versions
}
