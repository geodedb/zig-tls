//! QUIC transport parameters encoding and decoding.
//!
//! Implements QUIC transport parameter exchange as specified in RFC 9000 §18
//! (Transport Parameters) and RFC 9001 §8.2 (QUIC Transport Parameters Extension).
//!
//! ## Purpose
//!
//! This module provides types and functions for encoding and decoding QUIC
//! transport parameters, which are exchanged during the TLS 1.3 handshake via
//! the `quic_transport_parameters` extension (extension type 0x0039, formerly 0xffa5).
//!
//! Transport parameters allow QUIC endpoints to communicate protocol settings
//! and capabilities that affect connection behavior, such as:
//! - Flow control limits (max_data, max_stream_data)
//! - Stream concurrency limits (max_streams_bidi, max_streams_uni)
//! - Connection ID constraints (active_connection_id_limit)
//! - Timeout values (max_idle_timeout, max_ack_delay)
//! - Migration settings (disable_active_migration, preferred_address)
//!
//! ## Integration with TLS 1.3
//!
//! RFC 9001 §8.2 specifies that transport parameters are carried in TLS
//! EncryptedExtensions (server) and ClientHello (client) messages:
//!
//! - **Client → Server**: Transport parameters appear in ClientHello extensions
//! - **Server → Client**: Transport parameters appear in EncryptedExtensions
//!
//! The TLS extension uses type 0x0039 (`quic_transport_parameters`) and contains
//! the variable-length encoded transport parameter list.
//!
//! ## Wire Format (RFC 9000 §18)
//!
//! Transport parameters are encoded as a sequence of:
//! ```
//! Transport Parameter {
//!   Transport Parameter ID (i),    // Variable-length integer
//!   Transport Parameter Length (i), // Variable-length integer
//!   Transport Parameter Value (..),
//! }
//! ```
//!
//! Each parameter is self-describing with an ID and length, allowing unknown
//! parameters to be safely ignored (forward compatibility).
//!
//! ## Required vs. Optional Parameters
//!
//! RFC 9000 §18.2 defines:
//! - **Required parameters**: Endpoints MUST send certain parameters (e.g.,
//!   `initial_source_connection_id` for both client and server)
//! - **Optional parameters**: May be omitted if default behavior is acceptable
//! - **Server-only parameters**: `stateless_reset_token`, `preferred_address`,
//!   `original_destination_connection_id`, `retry_source_connection_id`
//!
//! Missing required parameters or invalid values result in a TRANSPORT_PARAMETER_ERROR.
//!
//! ## Placeholder Implementation
//!
//! This is a minimal placeholder implementation for TLS integration testing.
//! In a production QUIC stack, this module would be replaced with the actual
//! transport layer's parameter encoding/decoding logic.
//!
//! See also:
//! - RFC 9000 §7.4 (Cryptographic and Transport Handshake)
//! - RFC 9000 §18 (Transport Parameters)
//! - RFC 9001 §8.2 (QUIC Transport Parameters Extension)

const std = @import("std");

/// QUIC transport parameter identifiers.
///
/// RFC 9000 §18.2 defines the transport parameter registry. Each parameter
/// is identified by a variable-length integer and has specific encoding rules.
///
/// Parameter ID allocation:
/// - 0x00-0x3f: Standards Track parameters (IETF Review required)
/// - 0x40-0x7fff: Standards Track (Specification Required)
/// - 0x8000-0x3fff_ffff: Private Use
/// - 0x4000_0000+: Reserved
///
/// Endpoints MUST ignore parameters with unknown IDs (forward compatibility).
pub const ParameterId = enum(u64) {
    /// Original Destination Connection ID (server-only, variable length).
    /// RFC 9000 §18.2: Used to validate that the client's Initial packet
    /// was correctly routed through load balancers or NATs.
    original_destination_connection_id = 0x00,

    /// Maximum idle timeout in milliseconds (variable-length integer).
    /// RFC 9000 §18.2: Connection is silently closed if no packets are
    /// received for this duration. Value of 0 disables idle timeout.
    max_idle_timeout = 0x01,

    /// Stateless Reset Token (server-only, 16 bytes).
    /// RFC 9000 §18.2: Used to validate Stateless Reset packets when
    /// endpoint loses connection state.
    stateless_reset_token = 0x02,

    /// Maximum UDP payload size in bytes (variable-length integer).
    /// RFC 9000 §18.2: MUST be >= 1200 bytes (QUIC minimum packet size).
    /// Signals the maximum UDP payload the endpoint is willing to receive.
    max_udp_payload_size = 0x03,

    /// Initial maximum data in bytes (variable-length integer).
    /// RFC 9000 §18.2: Connection-level flow control limit.
    /// Maximum total bytes peer may send across all streams.
    initial_max_data = 0x04,

    /// Initial max stream data for locally-initiated bidirectional streams.
    /// RFC 9000 §18.2: Per-stream flow control limit (variable-length integer).
    initial_max_stream_data_bidi_local = 0x05,

    /// Initial max stream data for remotely-initiated bidirectional streams.
    /// RFC 9000 §18.2: Per-stream flow control limit (variable-length integer).
    initial_max_stream_data_bidi_remote = 0x06,

    /// Initial max stream data for unidirectional streams.
    /// RFC 9000 §18.2: Per-stream flow control limit (variable-length integer).
    initial_max_stream_data_uni = 0x07,

    /// Maximum concurrent bidirectional streams (variable-length integer).
    /// RFC 9000 §18.2: Limits number of peer-initiated bidirectional streams.
    initial_max_streams_bidi = 0x08,

    /// Maximum concurrent unidirectional streams (variable-length integer).
    /// RFC 9000 §18.2: Limits number of peer-initiated unidirectional streams.
    initial_max_streams_uni = 0x09,

    /// ACK delay exponent for ACK frame encoding (variable-length integer).
    /// RFC 9000 §18.2: Default is 3. Value MUST be <= 20.
    /// Ack Delay field in ACK frames is scaled by 2^exponent microseconds.
    ack_delay_exponent = 0x0a,

    /// Maximum ACK delay in milliseconds (variable-length integer).
    /// RFC 9000 §18.2: Default is 25ms. Value MUST be < 2^14.
    /// Used for calculating PTO (Probe Timeout).
    max_ack_delay = 0x0b,

    /// Disable active connection migration (zero-length value).
    /// RFC 9000 §18.2: If present, peer MUST NOT send from a new address.
    disable_active_migration = 0x0c,

    /// Preferred address for connection migration (server-only).
    /// RFC 9000 §18.2: Contains IPv4/IPv6 addresses, CID, and stateless reset token.
    preferred_address = 0x0d,

    /// Maximum number of active Connection IDs (variable-length integer).
    /// RFC 9000 §18.2: Default is 2. Value MUST be >= 2.
    /// Limits number of connection IDs endpoint will maintain.
    active_connection_id_limit = 0x0e,

    /// Initial Source Connection ID (variable length).
    /// RFC 9000 §18.2: MUST match the Source CID from the Initial packet.
    /// Required parameter for both endpoints.
    initial_source_connection_id = 0x0f,

    /// Retry Source Connection ID (server-only, variable length).
    /// RFC 9000 §18.2: MUST be sent by server if Retry packet was sent.
    /// Used to validate that Retry was not forged.
    retry_source_connection_id = 0x10,

    /// Unknown parameter IDs are allowed (forward compatibility).
    /// RFC 9000 §7.4: Endpoints MUST ignore unknown transport parameters.
    _,
};

/// QUIC transport parameters structure.
///
/// This is a placeholder implementation that stores raw encoded transport
/// parameters. In a production QUIC stack, this would be replaced with a
/// fully parsed structure containing all parameter values.
///
/// RFC 9000 §18 specifies the encoding format and validation rules for
/// each transport parameter.
pub const TransportParameters = struct {
    /// Raw encoded transport parameters in wire format.
    ///
    /// Contains the variable-length encoded sequence of transport parameters
    /// as defined by RFC 9000 §18. This data is embedded in the TLS
    /// quic_transport_parameters extension (RFC 9001 §8.2).
    raw: []const u8,

    /// Create transport parameters from pre-encoded raw bytes.
    ///
    /// This constructor does not validate the encoding. Use `decode()` if
    /// validation is required.
    ///
    /// Parameters:
    /// - `raw`: Wire-format transport parameters (RFC 9000 §18 encoding)
    ///
    /// Returns:
    /// TransportParameters wrapping the raw data.
    pub fn init(raw: []const u8) TransportParameters {
        return .{ .raw = raw };
    }

    /// Encode transport parameters to wire format.
    ///
    /// RFC 9000 §18: Each parameter is encoded as:
    /// ```
    /// Parameter ID (variable-length integer)
    /// Parameter Length (variable-length integer)
    /// Parameter Value (length bytes)
    /// ```
    ///
    /// In a real implementation, this would:
    /// 1. Encode each configured parameter using variable-length integer encoding
    /// 2. Include mandatory parameters (initial_source_connection_id, etc.)
    /// 3. Validate parameter values against RFC 9000 §18.2 constraints
    /// 4. Return the concatenated encoded parameter list
    ///
    /// Parameters:
    /// - `allocator`: Memory allocator for output buffer
    ///
    /// Returns:
    /// Encoded transport parameters suitable for TLS extension payload.
    ///
    /// Errors:
    /// - `OutOfMemory`: Allocation failure
    ///
    /// **Placeholder**: Currently returns empty parameters.
    pub fn encode(allocator: std.mem.Allocator) ![]u8 {
        _ = allocator;
        // TODO: Real implementation would encode configured parameters here
        // Example encoding for max_idle_timeout=30000ms (0x7530):
        // 0x01 (max_idle_timeout ID)
        // 0x02 (length: 2 bytes)
        // 0x75 0x30 (value: 30000 in variable-length encoding)
        return &.{};
    }

    /// Decode transport parameters from wire format.
    ///
    /// RFC 9000 §18: Parse the variable-length encoded parameter list and
    /// validate:
    /// - Parameter IDs are valid
    /// - Parameter lengths match value sizes
    /// - Required parameters are present
    /// - Values satisfy RFC 9000 §18.2 constraints
    ///
    /// In a real implementation, this would:
    /// 1. Parse variable-length integers for ID and length
    /// 2. Extract parameter values
    /// 3. Validate required parameters (initial_source_connection_id)
    /// 4. Check server-only parameters appear only from server
    /// 5. Verify value constraints (e.g., max_udp_payload_size >= 1200)
    /// 6. Return structured TransportParameters
    ///
    /// Parameters:
    /// - `data`: Wire-format transport parameters from TLS extension
    ///
    /// Returns:
    /// Decoded transport parameters.
    ///
    /// Errors:
    /// - `InvalidEncoding`: Malformed variable-length integers
    /// - `InvalidParameter`: Parameter value violates RFC 9000 constraints
    /// - `MissingParameter`: Required parameter absent
    ///
    /// **Placeholder**: Currently performs no validation.
    pub fn decode(data: []const u8) !TransportParameters {
        // TODO: Real implementation would parse and validate here
        // Should detect:
        // - Truncated parameters (length extends beyond buffer)
        // - Duplicate parameters (most parameters MUST NOT appear twice)
        // - Invalid server-only parameters from client
        // - Missing mandatory parameters
        return TransportParameters{ .raw = data };
    }
};

test "transport parameters placeholder" {
    const params = TransportParameters.init(&.{});
    try std.testing.expect(params.raw.len == 0);
}
