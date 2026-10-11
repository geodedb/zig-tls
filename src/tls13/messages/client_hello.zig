// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! TLS 1.3 ClientHello Message
//!
//! Implements ClientHello message parsing per RFC 8446 §4.1.2. The ClientHello
//! is the first message in the TLS 1.3 handshake, containing the client's
//! capabilities, preferences, and cryptographic parameters.
//!
//! ## RFC Coverage
//!
//! - RFC 8446 §4.1.2: ClientHello message structure
//! - RFC 8446 §4.2: Extension definitions and processing
//! - RFC 8446 §9.2: Required extensions for TLS 1.3
//! - RFC 6066 §3: Server Name Indication (SNI)
//! - RFC 7301: ALPN extension
//! - RFC 9001 §8.2: QUIC transport parameters
//!
//! ## INTEROP FIRST Design
//!
//! This implementation follows the INTEROP FIRST principle:
//! - Parses all standard extension types from RFC 8446
//! - Gracefully ignores unknown extensions (per RFC 8446 §4.2)
//! - Zero-copy parsing (slices reference input buffer)
//! - Supports real-world QUIC implementations
//!
//! ## QUAL-096: Shared ClientHello Builder
//!
//! The `buildClientHello` function provides a single, shared implementation
//! for encoding TLS 1.3 ClientHello message bodies. It is used by:
//! - `context.zig:startClientHandshake` (initial ClientHello with PSK support)
//! - `context.zig:sendClientHello2` (ClientHello2 after HelloRetryRequest)
//!
//! The builder uses a single-buffer pattern (PERF-015) where extensions are
//! written directly into the output buffer with length fields patched at the
//! end, eliminating the ext_buf double-copy pattern.
//!
//! This module contains both parsing and building.

const std = @import("std");
const core_types = @import("core_types.zig");
const helpers = @import("helpers.zig");
const handlers_mod = @import("client_hello_handlers.zig");

/// Parsed ClientHello message (RFC 8446 §4.1.2).
///
/// ClientHello is the first message in the TLS 1.3 handshake, sent by the client
/// to initiate a connection. It contains the client's capabilities, preferences,
/// and cryptographic parameters.
///
/// ## Structure (RFC 8446 §4.1.2)
///
/// ```
/// struct {
///     ProtocolVersion legacy_version = 0x0303; // TLS 1.2 for compatibility
///     Random random;                            // 32 bytes of randomness
///     opaque legacy_session_id<0..32>;         // For middlebox compatibility
///     CipherSuite cipher_suites<2..2^16-2>;    // Client's supported cipher suites
///     opaque legacy_compression_methods<1..2^8-1>; // Must be [0x00] for TLS 1.3
///     Extension extensions<8..2^16-1>;         // MUST be present in TLS 1.3
/// } ClientHello;
/// ```
///
/// ## Required Extensions (RFC 8446 §9.2)
///
/// TLS 1.3 ClientHello MUST contain:
/// - **supported_versions** (0x002b): Indicates TLS 1.3 support
/// - **signature_algorithms** (0x000d): Signature schemes for CertificateVerify
///
/// ## Common Extensions
///
/// - **server_name** (0x0000): SNI for virtual hosting
/// - **supported_groups** (0x000a): ECDHE/FFDHE groups
/// - **key_share** (0x0033): Client's ECDHE public key(s)
/// - **alpn** (0x0010): Application-Layer Protocol Negotiation
/// - **quic_transport_parameters** (0x0039): QUIC-specific parameters (QUIC only)
/// - **pre_shared_key** (0x0029): PSK identities for resumption/0-RTT (MUST be last)
///
/// ## Memory Management
///
/// All slices reference the input buffer (zero-copy parsing). The ClientHello
/// struct is valid only as long as the original message buffer remains live.
pub const ClientHello = struct {
    random: [32]u8, // RFC 8446 §4.1.2: Client random (32 bytes)
    session_id: []const u8, // RFC 8446 §4.1.2: Legacy session ID (for middlebox compat)
    cipher_suites: []core_types.CipherSuite, // RFC 8446 §4.1.2: Client's supported cipher suites
    compression_methods: []const u8, // RFC 8446 §4.1.2: Must be [0x00] in TLS 1.3

    // Extensions (RFC 8446 §4.2)
    server_name: ?[]const u8 = null, // RFC 6066 §3: SNI hostname
    supported_groups: ?[]core_types.NamedGroup = null, // RFC 8446 §4.2.7: ECDHE/FFDHE groups
    signature_algorithms: ?[]core_types.SignatureScheme = null, // RFC 8446 §4.2.3: Signature algorithms
    supported_versions: ?[]const u8 = null, // RFC 8446 §4.2.1: TLS version list (REQUIRED)
    key_share: ?KeyShareEntry = null, // RFC 8446 §4.2.8: ECDHE public key
    alpn_list: ?[][]const u8 = null, // RFC 7301: Application protocols
    quic_transport_parameters: ?[]const u8 = null, // RFC 9001 §8.2: QUIC parameters
    psk_key_exchange_modes: ?[]const u8 = null, // RFC 8446 §4.2.9: PSK modes (psk_ke, psk_dhe_ke)
    pre_shared_key: ?PreSharedKey = null, // RFC 8446 §4.2.11: PSK identities (MUST be last extension)
    early_data: bool = false, // RFC 8446 §4.2.10: 0-RTT early data indication
    cookie: ?[]const u8 = null, // RFC 8446 §4.2.2: HRR cookie echo (CH2 only)
};

/// Key share entry for ECDHE key exchange (RFC 8446 §4.2.8).
///
/// Contains the client's or server's ephemeral public key for a specific
/// named group (elliptic curve or finite field group).
///
/// ## Structure
///
/// ```
/// struct {
///     NamedGroup group;
///     opaque key_exchange<1..2^16-1>;
/// } KeyShareEntry;
/// ```
///
/// ## Key Exchange Data Formats
///
/// - **X25519**: 32-byte public key (RFC 7748 §6)
/// - **secp256r1**: 65-byte uncompressed point (0x04 || x || y) (RFC 8422 §5.4)
/// - **FFDHE groups**: Big-endian integer (RFC 7919)
pub const KeyShareEntry = struct {
    group: core_types.NamedGroup, // RFC 8446 §4.2.8: Named group identifier
    key_exchange: []const u8, // RFC 8446 §4.2.8: Public key bytes (format depends on group)

    /// Raw u16 codepoint as offered by the client.
    ///
    /// For groups that round-trip through `core_types.NamedGroup` this equals
    /// `@intFromEnum(group)`. For codepoints outside the enum (e.g. PQ-hybrid
    /// `x25519_kyber768_draft00 = 0x6399`) the parser stores a non-X25519
    /// sentinel in `group` so `negotiateCipherAndKeys` can issue HRR per
    /// RFC 8446 §4.1.4, while `raw_group_code` preserves the original
    /// codepoint for diagnostics and future logic that wants to switch on
    /// the actual offered group (instead of the sentinel).
    raw_group_code: u16 = 0,
};

/// TLS 1.3 Pre-Shared Key identity entry (RFC 8446 §4.2.11).
///
/// Identifies a pre-shared key (PSK) from a previous session or external source.
/// Used for session resumption and 0-RTT early data.
///
/// ## Structure
///
/// ```
/// struct {
///     opaque identity<1..2^16-1>;
///     uint32 obfuscated_ticket_age;
/// } PskIdentity;
/// ```
///
/// ## Obfuscated Ticket Age
///
/// For resumption PSKs from NewSessionTicket:
/// - Client computes: ticket_age_add + (current_time - ticket_received_time) mod 2^32
/// - Server verifies freshness and detects replays
/// - For external PSKs: set to 0
pub const PskIdentity = struct {
    identity: []const u8, // RFC 8446 §4.2.11: PSK identity (session ticket or external PSK)
    obfuscated_ticket_age: u32, // RFC 8446 §4.2.11: Obfuscated age for replay prevention
};

/// TLS 1.3 pre_shared_key extension payload (RFC 8446 §4.2.11).
///
/// Contains PSK identities and corresponding binders. The binder is an HMAC
/// over the partial ClientHello transcript, proving the client possesses the PSK.
///
/// ## Structure
///
/// ```
/// struct {
///     PskIdentity identities<7..2^16-1>;
///     PskBinderEntry binders<33..2^16-1>;
/// } OfferedPsks;
/// ```
///
/// ## Binder Computation (RFC 8446 §4.2.11.2)
///
/// ```
/// binder = HMAC(binder_key, transcript_hash(ClientHello_truncated))
/// ```
///
/// where ClientHello_truncated excludes the binders themselves.
///
/// ## Security Critical
///
/// - Binder MUST be verified before accepting PSK
/// - pre_shared_key extension MUST be last in ClientHello (RFC 8446 §4.2.11)
/// - Binder covers all preceding extensions (prevents tampering)
pub const PreSharedKey = struct {
    identities: []PskIdentity, // RFC 8446 §4.2.11: List of offered PSK identities
    binders: [][]const u8, // RFC 8446 §4.2.11: HMAC binders for each identity
};

/// Parse a full TLS 1.3 ClientHello message (RFC 8446 §4.1.2).
///
/// Parses the ClientHello wire format into a structured representation, extracting
/// all standard extensions. This implements the INTEROP FIRST design principle by:
/// - Gracefully ignoring unknown extensions (per RFC 8446 §4.2)
/// - Supporting all standard TLS 1.3 cipher suites and extensions
/// - Using zero-copy parsing (returned slices reference input buffer)
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for variable-length fields (cipher suites, extension arrays)
/// - `data`: ClientHello message bytes (without Handshake header, i.e., just the ClientHello payload)
///
/// ## Returns
///
/// - `ClientHello`: Parsed structure with all recognized extensions
/// - `error.TooShort`: Message too short to be valid ClientHello
///
/// ## Memory Management
///
/// - Allocates memory for: cipher_suites, supported_groups, signature_algorithms, alpn_list, PSK identities/binders
/// - All other fields are slices into the input buffer (zero-copy)
/// - Caller must free allocated fields when done
///
/// ## RFC Compliance
///
/// - RFC 8446 §4.1.2: ClientHello structure parsing
/// - RFC 8446 §4.2: Extension processing (unknown extensions ignored)
/// - RFC 8446 §4.2.11: Pre-shared key extension (MUST be last, validated during parsing)
///
/// ## INTEROP FIRST Implementation
///
/// - Supports all standard extension types from RFC 8446, RFC 6066, RFC 7301, RFC 9001
/// - Filters cipher suites to TLS 1.3 suites only (0x1301-0x1305)
/// - Recognizes but skips unsupported extensions (no handshake failure)
/// - Currently focuses on X25519 for key_share parsing
///
/// ## Extension Parsing
///
/// The following extensions are parsed and extracted:
/// - **server_name** (0x0000): SNI hostname
/// - **supported_groups** (0x000a): Named groups for ECDHE
/// - **signature_algorithms** (0x000d): Signature schemes
/// - **supported_versions** (0x002b): TLS version list
/// - **key_share** (0x0033): Client's ECDHE public key
/// - **alpn** (0x0010): Application protocols
/// - **quic_transport_parameters** (0x0039): QUIC parameters
/// - **psk_key_exchange_modes** (0x002d): PSK modes
/// - **pre_shared_key** (0x0029): PSK identities and binders
/// - **early_data** (0x002a): 0-RTT indication
///
/// Unknown extensions are silently ignored per RFC 8446 §4.2.
///
/// ## Usage
///
/// ```zig
/// const ch = try parseClientHello(allocator, client_hello_bytes);
/// defer {
///     allocator.free(ch.cipher_suites);
///     if (ch.supported_groups) |groups| allocator.free(groups);
///     if (ch.signature_algorithms) |algs| allocator.free(algs);
///     if (ch.alpn_list) |list| allocator.free(list);
///     if (ch.pre_shared_key) |psk| {
///         allocator.free(psk.identities);
///         allocator.free(psk.binders);
///     }
/// }
/// ```
pub fn parseClientHello(allocator: std.mem.Allocator, data: []const u8) !ClientHello {
    return parseClientHelloForGroup(allocator, data, .x25519);
}

/// Parse all key shares and prefer the caller's active key-agreement group.
/// The first other share is retained so the server can request a retry.
pub fn parseClientHelloForGroup(allocator: std.mem.Allocator, data: []const u8, preferred_group: core_types.NamedGroup) !ClientHello {
    if (data.len < 34) return error.TooShort;

    var ch = ClientHello{
        .random = undefined,
        .session_id = &[_]u8{},
        .cipher_suites = &[_]core_types.CipherSuite{},
        .compression_methods = &[_]u8{},
    };

    // SEC-054: On any error after partial allocation, free all owned slices
    // to prevent memory leaks from repeated malformed ClientHello messages.
    errdefer {
        if (ch.cipher_suites.len > 0) allocator.free(ch.cipher_suites);
        if (ch.supported_groups) |sg| allocator.free(sg);
        if (ch.signature_algorithms) |sa| allocator.free(sa);
        if (ch.alpn_list) |al| allocator.free(al);
        if (ch.pre_shared_key) |psk| {
            allocator.free(psk.identities);
            allocator.free(psk.binders);
        }
    }

    var pos: usize = 0;

    // Skip legacy_version (2 bytes)
    pos += 2;

    // Random (32 bytes)
    @memcpy(&ch.random, data[pos .. pos + 32]);
    pos += 32;

    // Session ID
    if (pos >= data.len) return error.TooShort;
    const sid_len = data[pos];
    pos += 1;
    if (pos + sid_len > data.len) return error.TooShort;
    ch.session_id = data[pos .. pos + sid_len];
    pos += sid_len;

    // Cipher suites
    if (pos + 2 > data.len) return error.TooShort;
    const cs_len = helpers.readU16(data[pos .. pos + 2]);
    pos += 2;
    if (pos + cs_len > data.len) return error.TooShort;
    // SEC-099 / RFC 8446 §4.1.2: `CipherSuite cipher_suites<2..2^16-2>;`. Each
    // CipherSuite is exactly two bytes, so an odd length is malformed. Without
    // this check, the `cs_pos += 2` loop below reads `data[pos+cs_len-1 ..
    // pos+cs_len+1]` on the final iteration — a one-byte over-read that panics
    // when the ClientHello has no compression/extensions tail (pre-auth crash).
    if (cs_len % 2 != 0) return error.IllegalCipherSuites;

    var cipher_suites = try std.ArrayList(core_types.CipherSuite).initCapacity(allocator, 4);
    defer cipher_suites.deinit(allocator);

    var cs_pos: usize = 0;
    while (cs_pos < cs_len) : (cs_pos += 2) {
        const cs_value = helpers.readU16(data[pos + cs_pos .. pos + cs_pos + 2]);
        // Check if it's a supported TLS 1.3 cipher suite
        if (cs_value == 0x1301 or cs_value == 0x1302 or cs_value == 0x1303) {
            try cipher_suites.append(allocator, @enumFromInt(cs_value));
        }
    }
    ch.cipher_suites = try cipher_suites.toOwnedSlice(allocator);
    pos += cs_len;

    // Compression methods
    // RFC 8446 §4.1.2: legacy_compression_methods MUST contain exactly one
    // byte set to zero (the null compression method). Any other shape
    // indicates a non-TLS-1.3 ClientHello or a tampered message and the
    // server MUST abort with `illegal_parameter`. SEC-088 surfaces this as
    // a typed `error.IllegalCompressionMethods` so the alert layer can map
    // it deterministically without reaching the cipher-suite negotiation.
    if (pos >= data.len) return error.TooShort;
    const comp_len = data[pos];
    pos += 1;
    if (pos + comp_len > data.len) return error.TooShort;
    if (comp_len != 1 or data[pos] != 0x00) return error.IllegalCompressionMethods;
    ch.compression_methods = data[pos .. pos + comp_len];
    pos += comp_len;

    // Extensions
    if (pos + 2 > data.len) return error.TooShort;
    const ext_len = helpers.readU16(data[pos .. pos + 2]);
    pos += 2;
    if (pos + ext_len > data.len) return error.TooShort;

    const ext_end = pos + ext_len;
    var psk_seen = false; // RFC 8446 §4.2.11: Track if pre_shared_key was seen
    // SEC-066 / GAP-0145: Track which extension types have been seen so duplicates are
    // rejected. A repeated extension with its own allocated payload would
    // overwrite the pointer stored by the first copy and leak the prior
    // allocation. RFC 8446 §4.2: "There MUST NOT be more than one extension
    // of the same type in a given extension block."
    // We use a fixed-size array of raw u16 types to ensure unknown extensions are
    // also tracked and rejected if duplicated, preventing GAP-0145 evasion.
    var seen_extensions: [core_types.MAX_EXTENSION_TYPES]u16 = undefined;
    var seen_count: usize = 0;

    // QUAL-339: ParseCtx threads ch + allocator into per-extension handlers.
    // Handlers only populate fields on `ch`; they never own cleanup or touch
    // psk_seen — both concerns stay at this outer-loop scope.
    var parse_ctx = handlers_mod.ParseCtx{ .ch = &ch, .alloc = allocator, .preferred_group = preferred_group };

    while (pos + 4 <= ext_end) {
        const ext_type_raw = helpers.readU16(data[pos .. pos + 2]);
        const ext_data_len = helpers.readU16(data[pos + 2 .. pos + 4]);
        pos += 4;

        if (pos + ext_data_len > ext_end) return error.TooShort;
        const ext_data = data[pos .. pos + ext_data_len];

        // SEC-066 / GAP-0145: Reject duplicate extension types (RFC 8446 §4.2).
        // QUAL-386: canonical error.DuplicateExtension (maps to decode_error).
        for (seen_extensions[0..seen_count]) |seen| {
            if (seen == ext_type_raw) return error.DuplicateExtension;
        }
        // APPSEC-04: capacity cap is a distinct condition from a duplicate; do
        // not mislabel a message with >64 DISTINCT extension types as a dup.
        if (seen_count == seen_extensions.len) return error.TooManyExtensions;
        seen_extensions[seen_count] = ext_type_raw;
        seen_count += 1;

        // SEC-057: Use enums.fromInt to reject unknown extension-type
        // discriminants without panicking on peer-chosen bytes.
        const ext = std.enums.fromInt(core_types.ExtensionType, ext_type_raw) orelse {
            // Unknown extension type - ignore per TLS 1.3 §4.2.
            // CWE-345: but still reject if we've seen PSK (must be last).
            if (psk_seen) {
                return error.PskNotLastExtension;
            }
            pos += ext_data_len;
            continue;
        };

        // CWE-345: pre_shared_key MUST be the last extension. Any non-PSK
        // extension after a PSK is a protocol violation.
        if (psk_seen and ext != .pre_shared_key) {
            return error.PskNotLastExtension;
        }

        // QUAL-339: dispatch to the shared HANDLERS table. Unknown but
        // structurally-valid extensions (e.g. certificate_authorities) that
        // have no registered handler are silently ignored — matching the
        // prior `else` fall-through in the switch. SEC-054 errdefer (above)
        // owns cleanup of any partially-populated allocations on handler
        // failure; handlers never errdefer themselves.
        for (handlers_mod.HANDLERS) |h| {
            if (h.tag == ext) {
                try h.parse(&parse_ctx, ext_data);
                if (ext == .pre_shared_key) psk_seen = true;
                break;
            }
        }

        pos += ext_data_len;
    }

    if (pos != ext_end or ext_end != data.len) return error.MalformedExtensions;
    return ch;
}

// ============================================================================
// ClientHello Builder (QUAL-096)
// ============================================================================

/// Parameters for building a TLS 1.3 ClientHello message body.
///
/// Encapsulates all varying inputs so that `startClientHandshake` and
/// `sendClientHello2` can share the same wire-encoding logic.
///
/// ## RFC Coverage
///
/// - RFC 8446 §4.1.2: ClientHello structure
/// - RFC 8446 §4.2: Extensions
/// - RFC 9001 §8.2: QUIC transport parameters extension
pub const ClientHelloParams = struct {
    /// 32-byte client random (RFC 8446 §4.1.2).
    random: [32]u8,

    /// Client public key for key_share extension (RFC 8446 §4.2.8).
    client_pub: [32]u8 = .{0} ** 32,

    /// Provider-encoded key share; overrides client_pub for variable-length groups.
    key_share_bytes: ?[]const u8 = null,

    /// Named group for the key_share entry (default: x25519).
    key_share_group: core_types.NamedGroup = .x25519,

    /// Cipher suites to offer (RFC 8446 §4.1.2).
    /// If empty, defaults to AES-128-GCM, AES-256-GCM, CHACHA20-POLY1305.
    cipher_suites: []const core_types.CipherSuite = &.{},

    /// Supported groups to advertise (RFC 8446 §4.2.7).
    /// If empty, the extension is omitted.
    supported_groups: []const core_types.NamedGroup = &.{},

    /// Signature algorithms to advertise (RFC 8446 §4.2.3).
    /// If empty, the extension is omitted.
    signature_algorithms: []const core_types.SignatureScheme = &.{},

    /// ALPN protocol names (RFC 7301). If empty/null, the extension is omitted.
    alpn_protocols: ?[]const []const u8 = null,

    /// QUIC transport parameters (RFC 9001 §8.2). If null, the extension is omitted.
    quic_transport_parameters: ?[]const u8 = null,

    /// Cookie from HelloRetryRequest (RFC 8446 §4.2.2). If null, the extension is omitted.
    cookie: ?[]const u8 = null,

    /// Whether to include the early_data extension (RFC 8446 §4.2.10).
    include_early_data: bool = false,

    /// Whether to include psk_key_exchange_modes + pre_shared_key extensions.
    /// When true, `psk_identity` must be set.
    include_psk: bool = false,

    /// PSK identity bytes (session ticket or external PSK identity).
    psk_identity: ?[]const u8 = null,

    /// Obfuscated ticket age for the PSK identity (RFC 8446 §4.2.11).
    psk_ticket_age: u32 = 0,

    /// Digest length for the PSK binder (e.g. 32 for SHA-256, 48 for SHA-384).
    /// Only used when `include_psk` is true.
    psk_binder_len: u8 = 0,

    /// PERF-208: When true, the returned `body` buffer starts with a
    /// 4-byte handshake message header (`HsType.client_hello` + 3-byte
    /// big-endian length) that has been written in place. This
    /// eliminates the caller-side second allocation + memcpy previously
    /// required to prepend the header before PSK binder computation.
    /// When enabled:
    ///   * `ClientHelloResult.body` is the full handshake message
    ///     (4-byte header followed by the ClientHello body bytes) --
    ///     NOT a body-only slice.
    ///   * `ClientHelloResult.binder_offset`, when non-null, is an
    ///     offset into `body` that already accounts for the 4-byte
    ///     header; the caller must NOT add 4 to it.
    ///   * `ClientHelloResult.binders_tail_len` is unchanged.
    prepend_handshake_header: bool = false,
};

/// Result from `buildClientHello` containing the encoded body and optional
/// PSK binder metadata needed by the caller to compute and patch the binder.
pub const ClientHelloResult = struct {
    /// The fully-encoded ClientHello body (NOT including the 4-byte handshake
    /// header). Caller owns this memory and must free it via the same allocator.
    body: []u8,

    /// If a PSK extension was written, this is the byte offset (within `body`)
    /// where the binder placeholder (zeros) starts. Null when no PSK was included.
    binder_offset: ?usize = null,

    /// Length of the binder placeholder in bytes (same as `psk_binder_len`).
    binder_len: u8 = 0,

    /// Number of trailing bytes that form the binders list
    /// (binders_list_len_field(2) + binder_len_field(1) + binder_data).
    /// The truncated message for binder computation is `body[0 .. body.len - binders_tail_len]`.
    binders_tail_len: usize = 0,
};

/// Build a TLS 1.3 ClientHello message body (RFC 8446 §4.1.2).
///
/// Encodes the ClientHello body bytes suitable for wrapping in a handshake
/// message (type 0x01 + 3-byte length prefix). The caller is responsible for
/// adding the handshake header and, when PSK is used, computing and patching
/// the binder into the placeholder returned via `ClientHelloResult`.
///
/// ## Parameters
///
/// - `allocator`: Memory allocator for the returned body buffer.
/// - `params`: All varying inputs for the ClientHello.
///
/// ## Returns
///
/// - `ClientHelloResult`: Encoded body and optional PSK binder metadata.
///
/// ## Extension Order (RFC 8446 §4.2)
///
/// 1. supported_versions (REQUIRED)
/// 2. supported_groups
/// 3. signature_algorithms
/// 4. key_share
/// 5. cookie (if present, from HRR)
/// 6. ALPN
/// 7. QUIC transport parameters
/// 8. early_data (if enabled)
/// 9. psk_key_exchange_modes (if PSK)
/// 10. pre_shared_key (MUST be last per RFC 8446 §4.2.11)
pub fn buildClientHello(allocator: std.mem.Allocator, params: ClientHelloParams) !ClientHelloResult {
    // Use the same cipher suites defaulting logic as all 3 call sites.
    const cipher_suites = if (params.cipher_suites.len > 0)
        params.cipher_suites
    else
        &[_]core_types.CipherSuite{
            .TLS_AES_128_GCM_SHA256,
            .TLS_AES_256_GCM_SHA384,
            .TLS_CHACHA20_POLY1305_SHA256,
        };

    // Pre-allocate with a typical ClientHello size (~256 bytes).
    var buf = try std.ArrayList(u8).initCapacity(allocator, 256);
    errdefer buf.deinit(allocator);

    // PERF-208: Optionally reserve the 4-byte handshake message header in
    // the same buffer so callers don't need a second alloc+memcpy to
    // prepend it. The length is backfilled after the body is built.
    if (params.prepend_handshake_header) {
        try buf.appendSlice(allocator, &.{ 0x01, 0x00, 0x00, 0x00 });
    }

    // Offset at which the ClientHello body starts (0 without header,
    // 4 when prepended). All body-relative offsets computed via
    // buf.items.len implicitly include this shift.
    const body_start = buf.items.len;

    // --- ClientHello body ---

    // legacy_version (RFC 8446 §4.1.2: MUST be 0x0303)
    try buf.appendSlice(allocator, &.{ 0x03, 0x03 });

    // random (32 bytes)
    try buf.appendSlice(allocator, &params.random);

    // legacy_session_id (empty for QUIC, RFC 9001 §8.4)
    try buf.append(allocator, 0);

    // cipher_suites
    const cipher_list_len: u16 = @intCast(cipher_suites.len * 2);
    try buf.appendSlice(allocator, &.{ @intCast(cipher_list_len >> 8), @intCast(cipher_list_len & 0xff) });
    for (cipher_suites) |suite| {
        const val: u16 = @intFromEnum(suite);
        try buf.appendSlice(allocator, &.{ @intCast(val >> 8), @intCast(val & 0xff) });
    }

    // compression_methods (MUST be [0x00] for TLS 1.3)
    try buf.appendSlice(allocator, &.{ 0x01, 0x00 });

    // Reserve 2 bytes for extensions length (patched at end)
    const exts_len_offset = buf.items.len;
    try buf.appendSlice(allocator, &.{ 0x00, 0x00 });
    const exts_start = buf.items.len;

    // --- Extensions ---
    //
    // QUAL-339: delegate per-extension emission to the shared HANDLERS
    // table. The table order is authoritative (RFC 8446 §4.2), and
    // handlers_mod.HANDLERS places `pre_shared_key` LAST (CWE-345).
    // Build handlers check their params-source-of-truth field and
    // early-return when the extension should be omitted.
    var build_ctx = handlers_mod.BuildCtx{ .params = &params };
    for (handlers_mod.HANDLERS) |h| {
        try h.build(&build_ctx, &buf, allocator);
    }

    var result = ClientHelloResult{
        .body = undefined,
        .binder_offset = build_ctx.psk_binder_offset,
        .binder_len = build_ctx.psk_binder_len,
        .binders_tail_len = build_ctx.psk_binders_tail_len,
    };

    // Patch extensions length
    const exts_total: u16 = @intCast(buf.items.len - exts_start);
    buf.items[exts_len_offset] = @intCast(exts_total >> 8);
    buf.items[exts_len_offset + 1] = @intCast(exts_total & 0xff);

    // PERF-208: Backfill the handshake header length prefix in place when
    // the caller asked for a framed message.
    if (params.prepend_handshake_header) {
        const body_len_u32: u32 = @intCast(buf.items.len - body_start);
        buf.items[1] = @intCast((body_len_u32 >> 16) & 0xff);
        buf.items[2] = @intCast((body_len_u32 >> 8) & 0xff);
        buf.items[3] = @intCast(body_len_u32 & 0xff);
    }

    result.body = try buf.toOwnedSlice(allocator);
    return result;
}
