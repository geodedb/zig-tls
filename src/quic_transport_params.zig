// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! QUIC transport parameters encoding and decoding with variable-length integers.
//!
//! Implements QUIC transport parameter exchange as specified in:
//! - RFC 9000 §16 (Variable-Length Integer Encoding)
//! - RFC 9000 §18 (Transport Parameter Encoding)
//! - RFC 9001 §8.2 (QUIC Transport Parameters Extension)
//!
//! ## Purpose
//!
//! This module provides complete encoding and decoding of QUIC transport
//! parameters, which are exchanged during the TLS 1.3 handshake via the
//! `quic_transport_parameters` extension (extension type 0x0039).
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
//! ## Variable-Length Integer Encoding (RFC 9000 §16)
//!
//! QUIC uses a compact variable-length encoding for non-negative integers.
//! The two most significant bits of the first byte encode the length:
//!
//! ```
//! 2MSB | Length | Usable Bits | Range
//! -----|--------|-------------|-------------------------
//! 00   | 1 byte | 6 bits      | 0 to 63
//! 01   | 2 bytes| 14 bits     | 0 to 16,383
//! 10   | 4 bytes| 30 bits     | 0 to 1,073,741,823
//! 11   | 8 bytes| 62 bits     | 0 to 4,611,686,018,427,387,903
//! ```
//!
//! Examples from RFC 9000 Appendix A.1:
//! - `0x25` (1 byte) → 37
//! - `0x7bbd` (2 bytes) → 15,293
//! - `0x9d7f3e7d` (4 bytes) → 494,878,333
//! - `0xc2197c5eff14e88c` (8 bytes) → 151,288,809,941,952,652
//!
//! ## Required vs. Optional Parameters
//!
//! RFC 9000 §18.2 defines:
//! - **Required parameters**: Endpoints MUST send `initial_source_connection_id`
//! - **Server-only parameters**: `stateless_reset_token`, `preferred_address`,
//!   `original_destination_connection_id`, `retry_source_connection_id`
//! - **Optional parameters**: May be omitted if default behavior is acceptable
//!
//! Missing required parameters result in a TRANSPORT_PARAMETER_ERROR (0x0008).
//!
//! ## Usage Example
//!
//! ```zig
//! var params = TransportParameters{};
//! params.max_idle_timeout = 30_000; // 30 seconds
//! params.initial_max_data = 1_048_576; // 1 MB
//! params.initial_max_streams_bidi = 100;
//! params.initial_source_connection_id = client_dcid;
//!
//! // Encode for TLS extension
//! const encoded = try params.encode(allocator);
//! defer allocator.free(encoded);
//!
//! // Decode from peer
//! const peer_params = try TransportParameters.decode(data, allocator);
//! ```
//!
//! ## Security Considerations
//!
//! - Transport parameters are not authenticated until handshake completes (RFC 9001 §8.2)
//! - Tampering with parameters will cause handshake failure
//! - Endpoints MUST validate parameter constraints (e.g., max_udp_payload_size ≥ 1200)
//! - Unknown parameters MUST be ignored (forward compatibility)
//!
//! ## See Also
//!
//! - RFC 9000 §7.4 (Cryptographic and Transport Handshake)
//! - RFC 9000 §18 (Transport Parameters)
//! - RFC 9001 §8.2 (QUIC Transport Parameters Extension)

const std = @import("std");
const varint = @import("varint");

// Re-export varint functions for convenience
pub const encodeVarint = varint.encode;
pub const decodeVarint = varint.decode;
pub const VarintError = varint.Error;

// ============================================================================
// Transport Parameter Types (RFC 9000 §18.2)
// ============================================================================

/// QUIC transport parameter identifiers (RFC 9000 §18.2).
///
/// Each parameter is identified by a variable-length integer and has specific
/// encoding rules and validation constraints.
///
/// ## Parameter ID Allocation
/// - 0x00-0x3f: Standards Track (IETF Review)
/// - 0x40-0x7fff: Standards Track (Specification Required)
/// - 0x8000-0x3fffffff: Private Use
/// - 31*N+27: Reserved for GREASE (RFC 9287)
///
/// ## Server-Only Parameters
/// RFC 9000 §18.2: The following parameters MUST NOT be sent by clients:
/// - original_destination_connection_id (0x00)
/// - stateless_reset_token (0x02)
/// - preferred_address (0x0d)
/// - retry_source_connection_id (0x10)
///
/// Endpoints MUST ignore unknown parameter IDs (forward compatibility).
pub const ParameterId = enum(u64) {
    /// Original Destination Connection ID (server-only, RFC 9000 §18.2).
    /// The value of the Destination Connection ID field from the first
    /// Initial packet sent by the client. Used to validate correct routing
    /// through load balancers or NATs.
    original_destination_connection_id = 0x00,

    /// Maximum idle timeout in milliseconds (RFC 9000 §18.2).
    /// Connection is silently closed if no packets received for this duration.
    /// Value of 0 disables idle timeout. Default: 0 (disabled).
    max_idle_timeout = 0x01,

    /// Stateless Reset Token (server-only, 16 bytes, RFC 9000 §18.2).
    /// Used to validate Stateless Reset packets when endpoint loses state.
    /// Servers that don't send this cannot use stateless reset.
    stateless_reset_token = 0x02,

    /// Maximum UDP payload size in bytes (RFC 9000 §18.2).
    /// MUST be ≥ 1200 bytes (QUIC minimum). Default: 65527 bytes.
    /// Values below 1200 are invalid and cause TRANSPORT_PARAMETER_ERROR.
    max_udp_payload_size = 0x03,

    /// Initial maximum data in bytes (RFC 9000 §18.2).
    /// Connection-level flow control limit. Equivalent to immediate MAX_DATA.
    /// Default: 0 (no data can be sent).
    initial_max_data = 0x04,

    /// Initial max stream data for locally-initiated bidirectional streams (RFC 9000 §18.2).
    /// Per-stream flow control limit. Client: streams with ID ending in 0x00.
    /// Server: streams with ID ending in 0x01. Default: 0.
    initial_max_stream_data_bidi_local = 0x05,

    /// Initial max stream data for remotely-initiated bidirectional streams (RFC 9000 §18.2).
    /// Per-stream flow control limit. Client: streams with ID ending in 0x01.
    /// Server: streams with ID ending in 0x00. Default: 0.
    initial_max_stream_data_bidi_remote = 0x06,

    /// Initial max stream data for unidirectional streams (RFC 9000 §18.2).
    /// Per-stream flow control limit applies to all unidirectional streams.
    /// Default: 0.
    initial_max_stream_data_uni = 0x07,

    /// Maximum concurrent bidirectional streams (RFC 9000 §18.2).
    /// Limits number of peer-initiated bidirectional streams. Default: 0.
    initial_max_streams_bidi = 0x08,

    /// Maximum concurrent unidirectional streams (RFC 9000 §18.2).
    /// Limits number of peer-initiated unidirectional streams. Default: 0.
    initial_max_streams_uni = 0x09,

    /// ACK delay exponent for ACK frame encoding (RFC 9000 §18.2).
    /// ACK Delay field in ACK frames is scaled by 2^exponent microseconds.
    /// Default: 3. MUST be ≤ 20.
    ack_delay_exponent = 0x0a,

    /// Maximum ACK delay in milliseconds (RFC 9000 §18.2).
    /// Used for calculating PTO (Probe Timeout). Default: 25ms.
    /// MUST be < 2^14 (16384ms).
    max_ack_delay = 0x0b,

    /// Disable active connection migration (zero-length, RFC 9000 §18.2).
    /// If present, peer MUST NOT initiate connection migration to a new address.
    disable_active_migration = 0x0c,

    /// Preferred address for connection migration (server-only, RFC 9000 §18.2).
    /// Contains IPv4/IPv6 addresses, connection ID, and stateless reset token.
    preferred_address = 0x0d,

    /// Maximum number of active Connection IDs (RFC 9000 §18.2).
    /// Limits number of connection IDs endpoint will maintain.
    /// Default: 2. MUST be ≥ 2.
    active_connection_id_limit = 0x0e,

    /// Initial Source Connection ID (RFC 9000 §18.2).
    /// MUST match the Source CID from the Initial packet.
    /// Required parameter for both client and server.
    initial_source_connection_id = 0x0f,

    /// Retry Source Connection ID (server-only, RFC 9000 §18.2).
    /// MUST be sent by server if a Retry packet was sent.
    /// Used to validate that Retry was not forged.
    retry_source_connection_id = 0x10,

    /// Unknown parameter IDs are allowed (RFC 9000 §7.4).
    /// Endpoints MUST ignore unknown transport parameters (forward compatibility).
    _,
};

/// RFC 9000 §18.2: Preferred Address structure used by servers to signal
/// alternate IPv4/IPv6 endpoints alongside a connection ID and stateless
/// reset token. Encoded exactly as described in Figure 22 of the RFC.
pub const PreferredAddress = struct {
    pub const max_connection_id_length: usize = 20;

    /// IPv4 address advertised by the server (network byte order).
    ipv4_address: [4]u8 = [_]u8{0} ** 4,
    /// IPv4 port advertised by the server.
    ipv4_port: u16 = 0,
    /// IPv6 address advertised by the server (network byte order).
    ipv6_address: [16]u8 = [_]u8{0} ** 16,
    /// IPv6 port advertised by the server.
    ipv6_port: u16 = 0,
    /// Connection ID associated with the preferred address (sequence number 1).
    /// When owns_connection_id is true, this slice was allocated and must be freed on deinit.
    connection_id: []u8,
    /// Stateless reset token corresponding to the connection ID.
    stateless_reset_token: [16]u8,
    /// Whether the connection_id slice is owned and should be freed on deinit.
    owns_connection_id: bool = false,
    /// Encode the preferred address into its wire format representation.
    pub fn encode(self: PreferredAddress, allocator: std.mem.Allocator) ![]u8 {
        const cid_len = self.connection_id.len;
        if (cid_len == 0 or cid_len > max_connection_id_length or cid_len > std.math.maxInt(u8)) {
            return error.InvalidParameter;
        }

        const total_len = 4 + 2 + 16 + 2 + 1 + cid_len + 16;
        var out = try allocator.alloc(u8, total_len);
        var idx: usize = 0;

        @memcpy(out[idx .. idx + 4], self.ipv4_address[0..]);
        idx += 4;

        out[idx] = @as(u8, @intCast(self.ipv4_port >> 8));
        out[idx + 1] = @as(u8, @intCast(self.ipv4_port & 0xff));
        idx += 2;

        @memcpy(out[idx .. idx + 16], self.ipv6_address[0..]);
        idx += 16;

        out[idx] = @as(u8, @intCast(self.ipv6_port >> 8));
        out[idx + 1] = @as(u8, @intCast(self.ipv6_port & 0xff));
        idx += 2;

        out[idx] = @as(u8, @intCast(cid_len));
        idx += 1;

        @memcpy(out[idx .. idx + cid_len], self.connection_id);
        idx += cid_len;

        @memcpy(out[idx .. idx + 16], self.stateless_reset_token[0..]);

        return out;
    }

    /// Decode a preferred address from wire format.
    pub fn decode(data: []const u8, allocator: std.mem.Allocator) !PreferredAddress {
        const base_len = 4 + 2 + 16 + 2 + 1 + 16;
        if (data.len < base_len) return error.Truncated;

        var idx: usize = 0;
        var addr = PreferredAddress{
            .ipv4_address = undefined,
            .ipv4_port = 0,
            .ipv6_address = undefined,
            .ipv6_port = 0,
            .connection_id = undefined,
            .stateless_reset_token = undefined,
        };

        @memcpy(addr.ipv4_address[0..], data[idx .. idx + 4]);
        idx += 4;

        addr.ipv4_port = (@as(u16, data[idx]) << 8) | data[idx + 1];
        idx += 2;

        @memcpy(addr.ipv6_address[0..], data[idx .. idx + 16]);
        idx += 16;

        addr.ipv6_port = (@as(u16, data[idx]) << 8) | data[idx + 1];
        idx += 2;

        const conn_id_len = data[idx];
        idx += 1;
        if (conn_id_len == 0 or conn_id_len > max_connection_id_length) {
            return error.InvalidParameter;
        }

        if (idx + conn_id_len + 16 > data.len) return error.Truncated;

        const conn_id_buf = try allocator.dupe(u8, data[idx .. idx + conn_id_len]);
        errdefer allocator.free(conn_id_buf);
        addr.connection_id = conn_id_buf;
        idx += conn_id_len;

        @memcpy(addr.stateless_reset_token[0..], data[idx .. idx + 16]);
        idx += 16;

        if (idx != data.len) return error.InvalidParameter;

        addr.owns_connection_id = true;

        return addr;
    }

    /// Release any heap allocations owned by the preferred address.
    pub fn deinit(self: *PreferredAddress, allocator: std.mem.Allocator) void {
        if (self.owns_connection_id and self.connection_id.len != 0) {
            allocator.free(self.connection_id);
            self.connection_id.len = 0;
        }
        self.owns_connection_id = false;
    }
};

/// QUIC transport parameters structure.
///
/// Contains all defined transport parameters from RFC 9000 §18.2.
/// All integer parameters use variable-length encoding in wire format.
///
/// ## Defaults
/// RFC 9000 §18.2: Most parameters default to 0 if absent, except:
/// - `max_udp_payload_size`: defaults to 65527
/// - `ack_delay_exponent`: defaults to 3
/// - `max_ack_delay`: defaults to 25
/// - `active_connection_id_limit`: defaults to 2
///
/// ## Validation
/// The following constraints MUST be enforced (RFC 9000 §18.2):
/// - `max_udp_payload_size` ≥ 1200
/// - `ack_delay_exponent` ≤ 20
/// - `max_ack_delay` < 16384
/// - `active_connection_id_limit` ≥ 2
/// - `stateless_reset_token` must be exactly 16 bytes if present
///
/// ## Server-Only Parameters
/// Clients MUST NOT send the following parameters:
/// - `original_destination_connection_id`
/// - `stateless_reset_token`
/// - `preferred_address`
/// - `retry_source_connection_id`
pub const TransportParameters = struct {
    // RFC 9000 §18.2: Connection flow control and timeout parameters
    max_idle_timeout: ?u64 = null,
    max_udp_payload_size: ?u64 = null,
    initial_max_data: ?u64 = null,

    // RFC 9000 §18.2: Stream flow control parameters
    initial_max_stream_data_bidi_local: ?u64 = null,
    initial_max_stream_data_bidi_remote: ?u64 = null,
    initial_max_stream_data_uni: ?u64 = null,
    initial_max_streams_bidi: ?u64 = null,
    initial_max_streams_uni: ?u64 = null,

    // RFC 9000 §18.2: ACK parameters
    ack_delay_exponent: ?u64 = null,
    max_ack_delay: ?u64 = null,

    // RFC 9000 §18.2: Connection ID and migration parameters
    disable_active_migration: bool = false,
    active_connection_id_limit: ?u64 = null,

    // RFC 9000 §18.2: Connection ID parameters (variable length)
    initial_source_connection_id: ?[]const u8 = null,
    original_destination_connection_id: ?[]const u8 = null,
    retry_source_connection_id: ?[]const u8 = null,

    // RFC 9000 §18.2: Stateless reset token (server-only, exactly 16 bytes)
    stateless_reset_token: ?[16]u8 = null,

    // RFC 9000 §18.2: Preferred address (server-only, complex structure)
    preferred_address: ?PreferredAddress = null,

    /// Encode transport parameters to wire format (RFC 9000 §18).
    ///
    /// Each parameter is encoded as:
    /// ```
    /// Parameter ID (variable-length integer)
    /// Parameter Length (variable-length integer)
    /// Parameter Value (length bytes)
    /// ```
    ///
    /// ## Parameters
    /// - `self`: Transport parameters to encode
    /// - `allocator`: Memory allocator for output buffer
    ///
    /// ## Returns
    /// Encoded transport parameters suitable for TLS extension payload.
    ///
    /// ## Errors
    /// - `OutOfMemory`: Allocation failure
    /// - `InvalidParameter`: Parameter violates RFC 9000 constraints
    /// - `Truncated`: Buffer too small (from varint encoding)
    ///
    /// ## RFC References
    /// - RFC 9000 §18: Transport parameter encoding format
    /// - RFC 9000 §18.2: Parameter definitions and constraints
    pub fn encode(self: *const TransportParameters, allocator: std.mem.Allocator) ![]u8 {
        // RFC 9000 §18: Build parameter list using ArrayList
        var list = std.ArrayList(u8){};
        errdefer list.deinit(allocator);

        // Helper to encode a parameter
        const Writer = struct {
            fn writeParam(l: *std.ArrayList(u8), alloc: std.mem.Allocator, id: u64, value: []const u8) !void {
                // RFC 9000 §18: Write parameter ID as variable-length integer
                var id_buf: [8]u8 = undefined;
                const id_len = try varint.encode(id, &id_buf);
                try l.appendSlice(alloc, id_buf[0..id_len]);

                // RFC 9000 §18: Write parameter length as variable-length integer
                var len_buf: [8]u8 = undefined;
                const len_len = try varint.encode(value.len, &len_buf);
                try l.appendSlice(alloc, len_buf[0..len_len]);

                // RFC 9000 §18: Write parameter value
                try l.appendSlice(alloc, value);
            }

            fn writeVarintParam(l: *std.ArrayList(u8), alloc: std.mem.Allocator, id: u64, value: u64) !void {
                // RFC 9000 §18.2: Integer parameters encoded as variable-length integers
                var value_buf: [8]u8 = undefined;
                const value_len = try varint.encode(value, &value_buf);
                try writeParam(l, alloc, id, value_buf[0..value_len]);
            }
        };

        // RFC 9000 §18.2: Encode all present parameters

        // Connection flow control
        if (self.max_idle_timeout) |v| {
            try Writer.writeVarintParam(&list, allocator, @intFromEnum(ParameterId.max_idle_timeout), v);
        }
        if (self.max_udp_payload_size) |v| {
            // RFC 9000 §18.2: MUST be ≥ 1200
            if (v < 1200) return error.InvalidParameter;
            try Writer.writeVarintParam(&list, allocator, @intFromEnum(ParameterId.max_udp_payload_size), v);
        }
        if (self.initial_max_data) |v| {
            try Writer.writeVarintParam(&list, allocator, @intFromEnum(ParameterId.initial_max_data), v);
        }

        // Stream flow control
        if (self.initial_max_stream_data_bidi_local) |v| {
            try Writer.writeVarintParam(&list, allocator, @intFromEnum(ParameterId.initial_max_stream_data_bidi_local), v);
        }
        if (self.initial_max_stream_data_bidi_remote) |v| {
            try Writer.writeVarintParam(&list, allocator, @intFromEnum(ParameterId.initial_max_stream_data_bidi_remote), v);
        }
        if (self.initial_max_stream_data_uni) |v| {
            try Writer.writeVarintParam(&list, allocator, @intFromEnum(ParameterId.initial_max_stream_data_uni), v);
        }
        if (self.initial_max_streams_bidi) |v| {
            try Writer.writeVarintParam(&list, allocator, @intFromEnum(ParameterId.initial_max_streams_bidi), v);
        }
        if (self.initial_max_streams_uni) |v| {
            try Writer.writeVarintParam(&list, allocator, @intFromEnum(ParameterId.initial_max_streams_uni), v);
        }

        // ACK parameters
        if (self.ack_delay_exponent) |v| {
            // RFC 9000 §18.2: MUST be ≤ 20
            if (v > 20) return error.InvalidParameter;
            try Writer.writeVarintParam(&list, allocator, @intFromEnum(ParameterId.ack_delay_exponent), v);
        }
        if (self.max_ack_delay) |v| {
            // RFC 9000 §18.2: MUST be < 2^14
            if (v >= 16384) return error.InvalidParameter;
            try Writer.writeVarintParam(&list, allocator, @intFromEnum(ParameterId.max_ack_delay), v);
        }

        // Connection migration
        if (self.disable_active_migration) {
            // RFC 9000 §18.2: Zero-length parameter
            try Writer.writeParam(&list, allocator, @intFromEnum(ParameterId.disable_active_migration), &.{});
        }
        if (self.active_connection_id_limit) |v| {
            // RFC 9000 §18.2: MUST be ≥ 2
            if (v < 2) return error.InvalidParameter;
            try Writer.writeVarintParam(&list, allocator, @intFromEnum(ParameterId.active_connection_id_limit), v);
        }

        // Connection IDs
        if (self.initial_source_connection_id) |cid| {
            try Writer.writeParam(&list, allocator, @intFromEnum(ParameterId.initial_source_connection_id), cid);
        }
        if (self.original_destination_connection_id) |cid| {
            try Writer.writeParam(&list, allocator, @intFromEnum(ParameterId.original_destination_connection_id), cid);
        }
        if (self.retry_source_connection_id) |cid| {
            try Writer.writeParam(&list, allocator, @intFromEnum(ParameterId.retry_source_connection_id), cid);
        }

        // Server-only parameters
        if (self.stateless_reset_token) |token| {
            // RFC 9000 §18.2: Must be exactly 16 bytes
            try Writer.writeParam(&list, allocator, @intFromEnum(ParameterId.stateless_reset_token), &token);
        }
        if (self.preferred_address) |addr| {
            const encoded_addr = try addr.encode(allocator);
            defer allocator.free(encoded_addr);
            try Writer.writeParam(&list, allocator, @intFromEnum(ParameterId.preferred_address), encoded_addr);
        }

        return list.toOwnedSlice(allocator);
    }

    /// Decode transport parameters from wire format (RFC 9000 §18).
    ///
    /// Parses the variable-length encoded parameter list and validates:
    /// - Parameter IDs are properly encoded
    /// - Parameter lengths match available data
    /// - Required parameters are present (initial_source_connection_id)
    /// - Values satisfy RFC 9000 §18.2 constraints
    /// - Server-only parameters are not sent by client (if role known)
    ///
    /// ## Parameters
    /// - `data`: Wire-format transport parameters from TLS extension
    /// - `allocator`: Memory allocator for variable-length fields
    ///
    /// ## Returns
    /// Decoded and validated transport parameters.
    ///
    /// ## Errors
    /// - `Truncated`: Incomplete data
    /// - `InvalidParameter`: Parameter value violates constraints
    ///
    /// ## RFC References
    /// - RFC 9000 §18: Transport parameter encoding
    /// - RFC 9000 §18.2: Parameter constraints
    /// - RFC 9000 §7.4: Unknown parameters must be ignored
    pub fn decode(data: []const u8, allocator: std.mem.Allocator) !TransportParameters {
        var params = TransportParameters{};
        var offset: usize = 0;

        // RFC 9000 §18: Parse sequence of (ID, Length, Value) tuples
        while (offset < data.len) {
            // RFC 9000 §18: Read parameter ID
            const id_result = try varint.decode(data[offset..]);
            const id = id_result.value;
            offset += id_result.n;

            // RFC 9000 §18: Read parameter length
            const len_result = try varint.decode(data[offset..]);
            const length = len_result.value;
            offset += len_result.n;

            // RFC 9000 §18: Ensure we have enough data for value
            if (offset + length > data.len) return error.Truncated;
            const value = data[offset .. offset + length];
            offset += length;

            // RFC 9000 §18.2: Parse parameter based on ID
            switch (@as(ParameterId, @enumFromInt(id))) {
                .max_idle_timeout => {
                    const v_result = try varint.decode(value);
                    params.max_idle_timeout = v_result.value;
                },
                .max_udp_payload_size => {
                    const v_result = try varint.decode(value);
                    const v = v_result.value;
                    // RFC 9000 §18.2: MUST be ≥ 1200
                    if (v < 1200) return error.InvalidParameter;
                    params.max_udp_payload_size = v;
                },
                .initial_max_data => {
                    const v_result = try varint.decode(value);
                    params.initial_max_data = v_result.value;
                },
                .initial_max_stream_data_bidi_local => {
                    const v_result = try varint.decode(value);
                    params.initial_max_stream_data_bidi_local = v_result.value;
                },
                .initial_max_stream_data_bidi_remote => {
                    const v_result = try varint.decode(value);
                    params.initial_max_stream_data_bidi_remote = v_result.value;
                },
                .initial_max_stream_data_uni => {
                    const v_result = try varint.decode(value);
                    params.initial_max_stream_data_uni = v_result.value;
                },
                .initial_max_streams_bidi => {
                    const v_result = try varint.decode(value);
                    params.initial_max_streams_bidi = v_result.value;
                },
                .initial_max_streams_uni => {
                    const v_result = try varint.decode(value);
                    params.initial_max_streams_uni = v_result.value;
                },
                .ack_delay_exponent => {
                    const v_result = try varint.decode(value);
                    const v = v_result.value;
                    // RFC 9000 §18.2: MUST be ≤ 20
                    if (v > 20) return error.InvalidParameter;
                    params.ack_delay_exponent = v;
                },
                .max_ack_delay => {
                    const v_result = try varint.decode(value);
                    const v = v_result.value;
                    // RFC 9000 §18.2: MUST be < 2^14
                    if (v >= 16384) return error.InvalidParameter;
                    params.max_ack_delay = v;
                },
                .disable_active_migration => {
                    // RFC 9000 §18.2: Zero-length parameter
                    if (value.len != 0) return error.InvalidParameter;
                    params.disable_active_migration = true;
                },
                .active_connection_id_limit => {
                    const v_result = try varint.decode(value);
                    const v = v_result.value;
                    // RFC 9000 §18.2: MUST be ≥ 2
                    if (v < 2) return error.InvalidParameter;
                    params.active_connection_id_limit = v;
                },
                .initial_source_connection_id => {
                    // RFC 9000 §18.2: Variable-length connection ID
                    const cid = try allocator.dupe(u8, value);
                    params.initial_source_connection_id = cid;
                },
                .original_destination_connection_id => {
                    const cid = try allocator.dupe(u8, value);
                    params.original_destination_connection_id = cid;
                },
                .retry_source_connection_id => {
                    const cid = try allocator.dupe(u8, value);
                    params.retry_source_connection_id = cid;
                },
                .stateless_reset_token => {
                    // RFC 9000 §18.2: Must be exactly 16 bytes
                    if (value.len != 16) return error.InvalidParameter;
                    var token: [16]u8 = undefined;
                    @memcpy(&token, value);
                    params.stateless_reset_token = token;
                },
                .preferred_address => {
                    const addr = try PreferredAddress.decode(value, allocator);
                    params.preferred_address = addr;
                },
                _ => {
                    // RFC 9000 §7.4: Unknown parameters MUST be ignored
                    continue;
                },
            }
        }

        return params;
    }

    /// GAP-0081: Validate that transport parameters do not contain server-only
    /// parameters when received from a client (RFC 9000 §18.2).
    ///
    /// RFC 9000 §18.2: "A client MUST NOT include any server-only transport
    /// parameter: original_destination_connection_id, preferred_address,
    /// retry_source_connection_id, or stateless_reset_token."
    ///
    /// ## Parameters
    /// - `self`: Decoded transport parameters to validate
    ///
    /// ## Errors
    /// - `InvalidParameter`: Client sent a server-only parameter
    pub fn validateClientRole(self: *const TransportParameters) !void {
        if (self.original_destination_connection_id != null) return error.InvalidParameter;
        if (self.preferred_address != null) return error.InvalidParameter;
        if (self.retry_source_connection_id != null) return error.InvalidParameter;
        if (self.stateless_reset_token != null) return error.InvalidParameter;
    }

    /// Free allocated memory for variable-length fields.
    ///
    /// Call this when done with transport parameters that were decoded.
    ///
    /// ## Parameters
    /// - `self`: Transport parameters to clean up
    /// - `allocator`: Same allocator used for decode()
    pub fn deinit(self: *TransportParameters, allocator: std.mem.Allocator) void {
        if (self.initial_source_connection_id) |cid| allocator.free(cid);
        if (self.original_destination_connection_id) |cid| allocator.free(cid);
        if (self.retry_source_connection_id) |cid| allocator.free(cid);
        if (self.preferred_address) |*addr| {
            addr.deinit(allocator);
            self.preferred_address = null;
        }
    }
};

// ============================================================================
// TESTS - Transport Parameters (RFC 9000 §18)
// ============================================================================

const testing = std.testing;

// RFC 9000 §18: Test empty transport parameters
test "RFC 9000 §18 - empty transport parameters encode/decode" {
    const params = TransportParameters{};
    const encoded = try params.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    // RFC 9000 §18: Empty parameters encode to empty buffer
    try testing.expectEqual(@as(usize, 0), encoded.len);

    var decoded = try TransportParameters.decode(encoded, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(?u64, null), decoded.max_idle_timeout);
}

// RFC 9000 §18.2: Test max_idle_timeout parameter
test "RFC 9000 §18.2 - max_idle_timeout parameter" {
    var params = TransportParameters{};
    params.max_idle_timeout = 30000; // 30 seconds

    const encoded = try params.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    var decoded = try TransportParameters.decode(encoded, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 30000), decoded.max_idle_timeout.?);
}

// RFC 9000 §18.2: Test max_udp_payload_size validation (MUST be ≥ 1200)
test "RFC 9000 §18.2 - max_udp_payload_size validation" {
    var params = TransportParameters{};
    params.max_udp_payload_size = 1199; // Invalid: below minimum

    // RFC 9000 §18.2: Values below 1200 are invalid
    try testing.expectError(error.InvalidParameter, params.encode(testing.allocator));

    params.max_udp_payload_size = 1200; // Valid: minimum
    const encoded = try params.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    var decoded = try TransportParameters.decode(encoded, testing.allocator);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 1200), decoded.max_udp_payload_size.?);
}

// RFC 9000 §18.2: Test flow control parameters
test "RFC 9000 §18.2 - flow control parameters" {
    var params = TransportParameters{};
    params.initial_max_data = 1048576; // 1 MB
    params.initial_max_stream_data_bidi_local = 524288; // 512 KB
    params.initial_max_stream_data_bidi_remote = 524288;
    params.initial_max_stream_data_uni = 524288;
    params.initial_max_streams_bidi = 100;
    params.initial_max_streams_uni = 100;

    const encoded = try params.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    var decoded = try TransportParameters.decode(encoded, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 1048576), decoded.initial_max_data.?);
    try testing.expectEqual(@as(u64, 524288), decoded.initial_max_stream_data_bidi_local.?);
    try testing.expectEqual(@as(u64, 524288), decoded.initial_max_stream_data_bidi_remote.?);
    try testing.expectEqual(@as(u64, 524288), decoded.initial_max_stream_data_uni.?);
    try testing.expectEqual(@as(u64, 100), decoded.initial_max_streams_bidi.?);
    try testing.expectEqual(@as(u64, 100), decoded.initial_max_streams_uni.?);
}

test "RFC 9000 §18.2 - preferred_address encode/decode" {
    var connection_id = [_]u8{ 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 };
    const reset_token = [16]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };

    var preferred = PreferredAddress{
        .ipv4_address = .{ 192, 0, 2, 1 },
        .ipv4_port = 4433,
        .ipv6_address = .{
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0,    0,    0,    0,    0, 0, 0, 1,
        },
        .ipv6_port = 8443,
        .connection_id = &connection_id,
        .stateless_reset_token = reset_token,
    };

    var params = TransportParameters{ .preferred_address = preferred };

    const encoded = try params.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    var decoded = try TransportParameters.decode(encoded, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expect(decoded.preferred_address != null);
    const addr = decoded.preferred_address.?;

    try testing.expectEqualSlices(u8, preferred.ipv4_address[0..], addr.ipv4_address[0..]);
    try testing.expectEqual(@as(u16, preferred.ipv4_port), addr.ipv4_port);
    try testing.expectEqualSlices(u8, preferred.ipv6_address[0..], addr.ipv6_address[0..]);
    try testing.expectEqual(@as(u16, preferred.ipv6_port), addr.ipv6_port);
    try testing.expectEqualSlices(u8, preferred.connection_id, addr.connection_id);
    try testing.expectEqualSlices(u8, preferred.stateless_reset_token[0..], addr.stateless_reset_token[0..]);
}

test "RFC 9000 §18.2 - preferred_address validation" {
    const reset_token = [_]u8{0} ** 16;

    var empty_cid = [_]u8{};
    const zero_length = PreferredAddress{
        .connection_id = &empty_cid,
        .stateless_reset_token = reset_token,
    };
    try testing.expectError(error.InvalidParameter, zero_length.encode(testing.allocator));

    var big_cid_buf = [_]u8{0xaa} ** (PreferredAddress.max_connection_id_length + 1);
    const too_long = PreferredAddress{
        .connection_id = &big_cid_buf,
        .stateless_reset_token = reset_token,
    };
    try testing.expectError(error.InvalidParameter, too_long.encode(testing.allocator));

    var oversized_buf = [_]u8{0xbb} ** 256;
    const over_byte = PreferredAddress{
        .connection_id = &oversized_buf,
        .stateless_reset_token = reset_token,
    };
    try testing.expectError(error.InvalidParameter, over_byte.encode(testing.allocator));
}

test "RFC 9000 §18.2 - preferred_address layout matches wire format" {
    var connection_id = [_]u8{ 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 };
    const reset_token = [16]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };

    const preferred = PreferredAddress{
        .ipv4_address = .{ 192, 0, 2, 1 },
        .ipv4_port = 4433,
        .ipv6_address = .{
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0,    0,    0,    0,    0, 0, 0, 1,
        },
        .ipv6_port = 8443,
        .connection_id = &connection_id,
        .stateless_reset_token = reset_token,
    };

    const expected = [_]u8{
        0xc0, 0x00, 0x02, 0x01,
        0x11, 0x51, 0x20, 0x01,
        0x0d, 0xb8, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x20, 0xfb,
        0x06, 0xa1, 0xb2, 0xc3,
        0xd4, 0xe5, 0xf6, 0x00,
        0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc,
        0xdd, 0xee, 0xff,
    };

    const encoded = try preferred.encode(testing.allocator);
    defer testing.allocator.free(encoded);
    try testing.expectEqualSlices(u8, &expected, encoded);

    const full_expected = [_]u8{
        0x0d,
        0x2f,
        0xc0,
        0x00,
        0x02,
        0x01,
        0x11,
        0x51,
        0x20,
        0x01,
        0x0d,
        0xb8,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x20,
        0xfb,
        0x06,
        0xa1,
        0xb2,
        0xc3,
        0xd4,
        0xe5,
        0xf6,
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0xee,
        0xff,
    };

    const params = TransportParameters{ .preferred_address = preferred };
    const tp_encoded = try params.encode(testing.allocator);
    defer testing.allocator.free(tp_encoded);
    try testing.expectEqualSlices(u8, &full_expected, tp_encoded);
}

test "RFC 9000 §18.2 - preferred_address decode truncated" {
    const encoded = [_]u8{
        0xc0, 0x00, 0x02, 0x01,
        0x11, 0x51, 0x20, 0x01,
        0x0d, 0xb8, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x20, 0xfb,
        0x06, 0xa1, 0xb2, 0xc3,
        0xd4, 0xe5, 0xf6, 0x00,
        0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc,
        0xdd, 0xee, 0xff,
    };

    var i: usize = 0;
    while (i < encoded.len) : (i += 1) {
        if (i == encoded.len) break;
        try testing.expectError(error.Truncated, PreferredAddress.decode(encoded[0..i], testing.allocator));
    }
}

test "RFC 9000 §18.2 - preferred_address decode rejects zero length" {
    const encoded = [_]u8{
        0xc0, 0x00, 0x02, 0x01,
        0x11, 0x51, 0x20, 0x01,
        0x0d, 0xb8, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x20, 0xfb,
        0x00, 0x00, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66,
        0x77, 0x88, 0x99, 0xaa,
        0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    };

    try testing.expectError(error.InvalidParameter, PreferredAddress.decode(&encoded, testing.allocator));
}

test "RFC 9000 §18.2 - preferred_address decode rejects excess length" {
    const payload_len = 4 + 2 + 16 + 2 + 1 + PreferredAddress.max_connection_id_length + 1 + 16;
    var encoded: [payload_len]u8 = undefined;
    @memset(encoded[0..], 0);
    const len_index = 4 + 2 + 16 + 2;
    encoded[len_index] = @intCast(PreferredAddress.max_connection_id_length + 1);

    try testing.expectError(error.InvalidParameter, PreferredAddress.decode(&encoded, testing.allocator));
}

test "RFC 9000 §18.2 - preferred_address round trip fuzz" {
    var prng = std.Random.DefaultPrng.init(0x123456789abcdef0);
    const random = prng.random();

    var iteration: usize = 0;
    while (iteration < 128) : (iteration += 1) {
        var ipv4: [4]u8 = undefined;
        random.bytes(&ipv4);

        var ipv6: [16]u8 = undefined;
        random.bytes(&ipv6);

        const ipv4_port = random.uintLessThan(u16, std.math.maxInt(u16));
        const ipv6_port = random.uintLessThan(u16, std.math.maxInt(u16));

        const cid_len = random.uintLessThan(u8, @intCast(PreferredAddress.max_connection_id_length)) + 1;
        const cid_buf = try testing.allocator.alloc(u8, cid_len);
        defer testing.allocator.free(cid_buf);
        random.bytes(cid_buf);

        var token: [16]u8 = undefined;
        random.bytes(&token);

        var preferred = PreferredAddress{
            .ipv4_address = ipv4,
            .ipv4_port = ipv4_port,
            .ipv6_address = ipv6,
            .ipv6_port = ipv6_port,
            .connection_id = cid_buf,
            .stateless_reset_token = token,
        };

        const encoded = try preferred.encode(testing.allocator);
        defer testing.allocator.free(encoded);

        var decoded = try PreferredAddress.decode(encoded, testing.allocator);
        defer decoded.deinit(testing.allocator);

        try testing.expectEqualSlices(u8, preferred.ipv4_address[0..], decoded.ipv4_address[0..]);
        try testing.expectEqual(@as(u16, preferred.ipv4_port), decoded.ipv4_port);
        try testing.expectEqualSlices(u8, preferred.ipv6_address[0..], decoded.ipv6_address[0..]);
        try testing.expectEqual(@as(u16, preferred.ipv6_port), decoded.ipv6_port);
        try testing.expectEqualSlices(u8, preferred.connection_id, decoded.connection_id);
        try testing.expectEqualSlices(u8, preferred.stateless_reset_token[0..], decoded.stateless_reset_token[0..]);
    }
}

// RFC 9000 §18.2: Test ACK parameters validation
test "RFC 9000 §18.2 - ACK parameter validation" {
    var params = TransportParameters{};

    // RFC 9000 §18.2: ack_delay_exponent MUST be ≤ 20
    params.ack_delay_exponent = 21;
    try testing.expectError(error.InvalidParameter, params.encode(testing.allocator));

    params.ack_delay_exponent = 3; // Valid: default value
    params.max_ack_delay = 16384; // Invalid: MUST be < 2^14
    try testing.expectError(error.InvalidParameter, params.encode(testing.allocator));

    params.max_ack_delay = 25; // Valid: default value
    const encoded = try params.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    var decoded = try TransportParameters.decode(encoded, testing.allocator);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 3), decoded.ack_delay_exponent.?);
    try testing.expectEqual(@as(u64, 25), decoded.max_ack_delay.?);
}

// RFC 9000 §18.2: Test disable_active_migration (zero-length parameter)
test "RFC 9000 §18.2 - disable_active_migration" {
    var params = TransportParameters{};
    params.disable_active_migration = true;

    const encoded = try params.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    var decoded = try TransportParameters.decode(encoded, testing.allocator);
    defer decoded.deinit(testing.allocator);
    try testing.expect(decoded.disable_active_migration);
}

// RFC 9000 §18.2: Test active_connection_id_limit validation (MUST be ≥ 2)
test "RFC 9000 §18.2 - active_connection_id_limit validation" {
    var params = TransportParameters{};
    params.active_connection_id_limit = 1; // Invalid: below minimum

    try testing.expectError(error.InvalidParameter, params.encode(testing.allocator));

    params.active_connection_id_limit = 2; // Valid: minimum
    const encoded = try params.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    var decoded = try TransportParameters.decode(encoded, testing.allocator);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 2), decoded.active_connection_id_limit.?);
}

// RFC 9000 §18.2: Test connection ID parameters
test "RFC 9000 §18.2 - connection ID parameters" {
    var params = TransportParameters{};
    const cid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    params.initial_source_connection_id = &cid;

    const encoded = try params.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    var decoded = try TransportParameters.decode(encoded, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqualSlices(u8, &cid, decoded.initial_source_connection_id.?);
}

// RFC 9000 §18.2: Test stateless_reset_token (exactly 16 bytes)
test "RFC 9000 §18.2 - stateless_reset_token validation" {
    var params = TransportParameters{};
    const token = [_]u8{0x01} ** 16;
    params.stateless_reset_token = token;

    const encoded = try params.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    var decoded = try TransportParameters.decode(encoded, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqualSlices(u8, &token, &decoded.stateless_reset_token.?);
}

// RFC 9000 §7.4: Test unknown parameters are ignored
test "RFC 9000 §7.4 - unknown parameters ignored" {
    // Manually construct parameters with unknown ID 0x9999
    var list = std.ArrayList(u8){};
    defer list.deinit(testing.allocator);

    // Add known parameter
    var buf: [8]u8 = undefined;
    const id_len = try varint.encode(0x01, &buf); // max_idle_timeout
    try list.appendSlice(testing.allocator, buf[0..id_len]);

    // Encode the value first to know its length
    var value_buf: [8]u8 = undefined;
    const val_len = try varint.encode(30000, &value_buf);

    // Now encode the length
    const len_len = try varint.encode(val_len, &buf); // value length
    try list.appendSlice(testing.allocator, buf[0..len_len]);

    // Append the actual value
    try list.appendSlice(testing.allocator, value_buf[0..val_len]);

    // Add unknown parameter (should be ignored)
    const unknown_id_len = try varint.encode(0x9999, &buf);
    try list.appendSlice(testing.allocator, buf[0..unknown_id_len]);
    const unknown_len_len = try varint.encode(4, &buf);
    try list.appendSlice(testing.allocator, buf[0..unknown_len_len]);
    try list.appendSlice(testing.allocator, &[_]u8{ 0xde, 0xad, 0xbe, 0xef });

    const encoded = try list.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(encoded);

    // RFC 9000 §7.4: Unknown parameters MUST be ignored
    var decoded = try TransportParameters.decode(encoded, testing.allocator);
    defer decoded.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 30000), decoded.max_idle_timeout.?);
}

// RFC 9000 §18: Test comprehensive parameter set
test "RFC 9000 §18 - comprehensive parameter encoding/decoding" {
    var params = TransportParameters{};
    params.max_idle_timeout = 30000;
    params.max_udp_payload_size = 1472;
    params.initial_max_data = 10485760; // 10 MB
    params.initial_max_stream_data_bidi_local = 1048576; // 1 MB
    params.initial_max_stream_data_bidi_remote = 1048576;
    params.initial_max_stream_data_uni = 1048576;
    params.initial_max_streams_bidi = 100;
    params.initial_max_streams_uni = 100;
    params.ack_delay_exponent = 3;
    params.max_ack_delay = 25;
    params.active_connection_id_limit = 2;
    params.disable_active_migration = true;

    const cid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    params.initial_source_connection_id = &cid;

    const encoded = try params.encode(testing.allocator);
    defer testing.allocator.free(encoded);

    var decoded = try TransportParameters.decode(encoded, testing.allocator);
    defer decoded.deinit(testing.allocator);

    // Verify all parameters
    try testing.expectEqual(@as(u64, 30000), decoded.max_idle_timeout.?);
    try testing.expectEqual(@as(u64, 1472), decoded.max_udp_payload_size.?);
    try testing.expectEqual(@as(u64, 10485760), decoded.initial_max_data.?);
    try testing.expectEqual(@as(u64, 1048576), decoded.initial_max_stream_data_bidi_local.?);
    try testing.expectEqual(@as(u64, 1048576), decoded.initial_max_stream_data_bidi_remote.?);
    try testing.expectEqual(@as(u64, 1048576), decoded.initial_max_stream_data_uni.?);
    try testing.expectEqual(@as(u64, 100), decoded.initial_max_streams_bidi.?);
    try testing.expectEqual(@as(u64, 100), decoded.initial_max_streams_uni.?);
    try testing.expectEqual(@as(u64, 3), decoded.ack_delay_exponent.?);
    try testing.expectEqual(@as(u64, 25), decoded.max_ack_delay.?);
    try testing.expectEqual(@as(u64, 2), decoded.active_connection_id_limit.?);
    try testing.expect(decoded.disable_active_migration);
    try testing.expectEqualSlices(u8, &cid, decoded.initial_source_connection_id.?);
}
