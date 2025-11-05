//! Placeholder QUIC transport parameters module
//!
//! This module provides types and functions for QUIC transport parameters
//! as specified in RFC 9000 §7.4. These parameters are exchanged during the
//! TLS handshake via the quic_transport_parameters extension (0x39).
//!
//! In a real QUIC implementation, this would be replaced with the actual
//! transport parameter encoding/decoding logic from the QUIC stack.

const std = @import("std");

/// QUIC transport parameter IDs (RFC 9000 §18.2)
pub const ParameterId = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    _,
};

/// Placeholder transport parameters structure
pub const TransportParameters = struct {
    /// Raw encoded transport parameters
    raw: []const u8,

    /// Create transport parameters from raw bytes
    pub fn init(raw: []const u8) TransportParameters {
        return .{ .raw = raw };
    }

    /// Encode transport parameters to wire format
    /// In a real implementation, this would encode the parameters according to RFC 9000 §18
    pub fn encode(allocator: std.mem.Allocator) ![]u8 {
        _ = allocator;
        // Return empty parameters for now
        return &.{};
    }

    /// Decode transport parameters from wire format
    /// In a real implementation, this would parse the parameters according to RFC 9000 §18
    pub fn decode(data: []const u8) !TransportParameters {
        return TransportParameters{ .raw = data };
    }
};

test "transport parameters placeholder" {
    const params = TransportParameters.init(&.{});
    try std.testing.expect(params.raw.len == 0);
}
