// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Minimal ASN.1 DER Decoder for X.509 Certificate Parsing
//!
//! Implements a subset of ASN.1 Distinguished Encoding Rules (DER) decoding
//! as specified in:
//! - ITU-T X.690 (07/2002) - ASN.1 Encoding Rules: BER, CER, DER
//! - RFC 5280 (Internet X.509 Public Key Infrastructure Certificate and CRL Profile)
//! - RFC 5911 (ASN.1 Modules for X.509 Certificate and CRL Structures)
//!
//! This module provides the ASN.1 decoding primitives required for parsing
//! X.509 v3 certificates in TLS 1.3 handshakes. It focuses on DER encoding,
//! which is the canonical encoding used for certificates.
//!
//! ## DER Encoding Characteristics (X.690 §10)
//! DER is a restricted subset of BER (Basic Encoding Rules) that ensures
//! a unique encoding for each ASN.1 value:
//! - **Definite Length**: All lengths must use definite form (X.690 §10.1)
//! - **Minimal Encoding**: Lengths and integers use shortest possible representation
//! - **Sorted SETs**: SET elements are sorted by tag value (X.690 §11.6)
//! - **No Constructed Strings**: Primitive strings only, no chunking
//! - **UTC/Generalized Time**: Fixed formats with Zulu (Z) timezone only
//!
//! ## TLV (Tag-Length-Value) Structure
//! All DER encodings use TLV format (X.690 §8.1):
//! ```
//! +-----+--------+-------+
//! | Tag | Length | Value |
//! +-----+--------+-------+
//! ```
//!
//! **Tag Format** (X.690 §8.1.2):
//! ```
//! Bit:    7-6      5         4-0
//!       Class  Constructed  Tag Number
//! ```
//! - Class (bits 7-6): Universal (00), Application (01), Context (10), Private (11)
//! - Constructed (bit 5): Primitive (0) or Constructed (1)
//! - Tag Number (bits 4-0): Type identifier (0-30 for single-byte, 31 for multi-byte)
//!
//! **Length Format** (X.690 §8.1.3):
//! - Short form (0-127 bytes): Single byte with bit 7 = 0
//! - Long form (128+ bytes): First byte = 0x80 | num_octets, followed by big-endian length
//! - Indefinite form (0x80): FORBIDDEN in DER (X.690 §10.1)
//!
//! ## Supported Universal Types
//! This decoder supports the subset of ASN.1 types used in X.509 certificates:
//! - **SEQUENCE** (tag 16, constructed): Ordered collection of fields
//! - **SET** (tag 17, constructed): Unordered collection (sorted in DER)
//! - **INTEGER** (tag 2): Big-endian two's complement integers
//! - **BIT STRING** (tag 3): Bit-aligned binary data with unused bits count
//! - **OCTET STRING** (tag 4): Arbitrary byte sequences
//! - **OBJECT IDENTIFIER** (tag 6): OID dotted notation encoded as bytes
//! - **UTF8String** (tag 12): UTF-8 encoded text
//! - **IA5String** (tag 22): ASCII text (International Alphabet 5)
//! - **PrintableString** (tag 19): Limited ASCII subset
//! - **UTCTime** (tag 23): YYMMDDHHMMSSZ format (RFC 5280 §4.1.2.5.1)
//! - **GeneralizedTime** (tag 24): YYYYMMDDHHMMSSZ format (RFC 5280 §4.1.2.5.2)
//!
//! ## Context-Specific Tags
//! X.509 extensions use context-specific tags (class = 10b) to differentiate
//! optional fields. For example, X.509 v3 extensions use tag [3] EXPLICIT:
//! ```
//! [3] EXPLICIT Extensions OPTIONAL
//! ```
//! This is encoded as tag 0xA3 (context class, constructed, tag number 3).
//!
//! ## RFC 5280 Usage
//! X.509 certificates (RFC 5280 §4) use DER encoding exclusively:
//! - Certificate ::= SEQUENCE { ... }
//! - SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
//! - Extensions ::= SEQUENCE OF Extension
//! - All certificate chain validation requires parsing these structures
//!
//! ## Security Considerations
//! - **Length Validation**: All length fields are validated against buffer bounds
//!   to prevent buffer overruns
//! - **Integer Overflow**: Length calculations check for arithmetic overflow
//! - **Indefinite Length**: Rejected with error.IndefiniteLength (DER violation)
//! - **Malformed Encodings**: Tag/length parsing errors propagate as explicit
//!   error types (Truncated, UnexpectedTag, LengthTooLarge)
//! - **Resource Limits**: Length fields >8 bytes are rejected to prevent
//!   excessive memory allocation
//!
//! ## Design Notes
//! - Zero-copy parsing: Returns slices into the input buffer where possible
//! - Streaming decoder: Maintains offset state for sequential TLV parsing
//! - Explicit error handling: All parsing errors are typed and propagated
//! - No allocations: All operations work on caller-provided buffers
//! - Uses `std.crypto.codecs.asn1` from Zig standard library
//!
//! ## Usage Example
//! ```zig
//! var decoder = asn1.Decoder.init(der_bytes);
//! const seq = try decoder.readSequence();
//! var inner = asn1.Decoder.init(seq);
//! const version = try inner.readInteger();
//! const oid = try inner.readOID();
//! ```
//!
//! ## References
//! - ITU-T X.680: ASN.1 Specification
//! - ITU-T X.690: ASN.1 Encoding Rules (BER, CER, DER)
//! - RFC 5280: X.509 Certificate Profile
//! - RFC 5911: ASN.1 Modules for X.509
const std = @import("std");
const std_asn1 = std.crypto.codecs.asn1;

/// ASN.1 tag class categories for DER TLV headers.
///
/// Defined in X.690 §8.1.2.2. The tag class is encoded in bits 7-6 of the
/// first tag byte and identifies the scope/context of the tag:
///
/// - **universal** (00): Standard ASN.1 types (INTEGER, SEQUENCE, etc.)
/// - **application** (01): Application-specific types (rarely used)
/// - **context** (10): Context-specific tags for optional/alternative fields
/// - **private** (11): Private/vendor-specific types (rarely used)
///
/// X.509 certificates primarily use universal types for core structures and
/// context-specific tags for optional fields (e.g., [3] for v3 extensions).
///
/// ## RFC Reference
/// X.690 §8.1.2.2 - Encoding of tag class in bits 7-6
/// RFC 5280 §4.1 - X.509 certificate structure uses context-specific tags
pub const TagClass = enum { universal, application, context, private };

/// Extract the tag class from a DER tag byte.
///
/// Reads bits 7-6 of the tag byte to determine the tag class.
/// This identifies the scope of the tag (universal, application,
/// context-specific, or private).
///
/// ## Parameters
/// - `b`: The tag byte (first byte of a TLV structure)
///
/// ## Returns
/// TagClass enum value (universal, application, context, or private)
///
/// ## RFC Reference
/// X.690 §8.1.2.2 - Tag class is encoded in bits 8 and 7
///
/// ## Example
/// ```zig
/// const tag: u8 = 0x30; // SEQUENCE tag
/// const class = tagClass(tag); // returns .universal (bits 7-6 = 00)
///
/// const ctx_tag: u8 = 0xA3; // Context [3]
/// const ctx_class = tagClass(ctx_tag); // returns .context (bits 7-6 = 10)
/// ```
pub fn tagClass(b: u8) TagClass {
    // X.690 §8.1.2.2: Bits 8 and 7 encode the class
    return switch (b >> 6) {
        0 => .universal,
        1 => .application,
        2 => .context,
        else => .private,
    };
}

/// Check if a DER tag byte indicates constructed encoding.
///
/// Reads bit 5 of the tag byte to determine if the value is primitive
/// (contains actual data) or constructed (contains other TLV structures).
///
/// SEQUENCE and SET are always constructed. Primitive types like INTEGER
/// and OCTET STRING are typically primitive, but can be constructed in BER.
/// DER restricts strings to primitive encoding only (X.690 §10.2).
///
/// ## Parameters
/// - `b`: The tag byte (first byte of a TLV structure)
///
/// ## Returns
/// `true` if constructed (contains nested TLVs), `false` if primitive
///
/// ## RFC Reference
/// X.690 §8.1.2.5 - Bit 6 indicates primitive (0) or constructed (1)
/// X.690 §10.2 - DER string types must use primitive encoding
///
/// ## Example
/// ```zig
/// const seq_tag: u8 = 0x30; // SEQUENCE tag
/// const constructed = isConstructed(seq_tag); // returns true (bit 5 = 1)
///
/// const int_tag: u8 = 0x02; // INTEGER tag
/// const primitive = isConstructed(int_tag); // returns false (bit 5 = 0)
/// ```
pub fn isConstructed(b: u8) bool {
    // X.690 §8.1.2.5: Bit 6 indicates primitive (0) or constructed (1)
    return (b & 0x20) != 0;
}

/// Extract the tag number from a DER tag byte.
///
/// Reads bits 4-0 of the tag byte to get the tag number. For single-byte
/// tags, this gives tag numbers 0-30. If the tag number is 31, it indicates
/// a multi-byte tag encoding (not commonly used in X.509).
///
/// Common universal tag numbers:
/// - 2: INTEGER
/// - 3: BIT STRING
/// - 4: OCTET STRING
/// - 6: OBJECT IDENTIFIER
/// - 12: UTF8String
/// - 16: SEQUENCE
/// - 17: SET
/// - 22: IA5String
/// - 23: UTCTime
/// - 24: GeneralizedTime
///
/// ## Parameters
/// - `b`: The tag byte (first byte of a TLV structure)
///
/// ## Returns
/// Tag number (0-31, where 31 indicates multi-byte tag)
///
/// ## RFC Reference
/// X.690 §8.1.2.3 - Low-order tag numbers (0-30) use single byte
/// X.690 §8.1.2.4 - Tag number 31 indicates multi-byte encoding
///
/// ## Example
/// ```zig
/// const seq_tag: u8 = 0x30; // SEQUENCE tag
/// const tag_num = tagNumber(seq_tag); // returns 16 (0x10)
///
/// const ctx_tag: u8 = 0xA3; // Context [3]
/// const ctx_num = tagNumber(ctx_tag); // returns 3
/// ```
pub fn tagNumber(b: u8) u8 {
    // X.690 §8.1.2.3: Bits 5-1 encode the tag number
    return b & 0x1f;
}

/// SEC-076: Canonical full-slice OID equality.
///
/// DER encoding of an OID is unique (RFC 5280 §4.1.1.2). Prior code
/// used a suffix-match pattern that accepted any prefix — an
/// attacker-crafted `[0xFF] ++ canonical_suffix` was recognized as
/// the canonical OID. This helper performs a full-slice byte
/// equality check. SEC-069 uses it in x509.zig; SEC-076 migrates
/// ocsp.zig and sig.zig.
pub fn oidEqual(oid: []const u8, canonical: []const u8) bool {
    return std.mem.eql(u8, oid, canonical);
}

/// Streaming DER decoder for sequential TLV parsing.
///
/// Provides a stateful decoder over a DER-encoded byte buffer. The decoder
/// maintains an internal offset and provides methods to sequentially parse
/// TLV structures and extract typed values.
///
/// This implementation uses `std.crypto.codecs.asn1` from the Zig standard library.
///
/// ## Design Philosophy
/// - **Zero-copy**: Returns slices into the input buffer without allocations
/// - **Streaming**: Maintains parsing state for sequential TLV traversal
/// - **Type-safe**: Validates tag types before extracting values
/// - **Error handling**: Explicit error propagation for malformed encodings
///
/// ## Usage Pattern
/// ```zig
/// var decoder = asn1.Decoder.init(der_bytes);
/// const seq_data = try decoder.readSequence();
/// var inner = asn1.Decoder.init(seq_data);
/// const version = try inner.readInteger();
/// ```
///
/// ## Security Notes
/// - All length fields are validated against buffer bounds
/// - Indefinite-length encoding (0x80) is rejected (DER violation)
/// - Multi-byte lengths >8 bytes are rejected to prevent overflow attacks
///
/// ## RFC Reference
/// X.690 §8.1 - Basic encoding rules for TLV structures
pub const Decoder = struct {
    /// Input buffer containing DER-encoded data.
    buf: []const u8,

    /// Current parsing offset (next byte to read).
    off: usize = 0,

    /// Initialize a decoder over a DER-encoded buffer.
    ///
    /// Creates a new decoder positioned at the start of the buffer.
    /// The decoder can then be used to sequentially parse TLV structures.
    ///
    /// ## Parameters
    /// - `buf`: DER-encoded byte slice to parse
    ///
    /// ## Returns
    /// Initialized Decoder positioned at offset 0
    ///
    /// ## Example
    /// ```zig
    /// const der_data: []const u8 = ...;
    /// var decoder = asn1.Decoder.init(der_data);
    /// ```
    pub fn init(buf: []const u8) Decoder {
        return .{ .buf = buf, .off = 0 };
    }

    /// Read a single byte from the buffer and advance the offset.
    fn readByte(self: *Decoder) !u8 {
        if (self.off >= self.buf.len) return error.Truncated;
        const b = self.buf[self.off];
        self.off += 1;
        return b;
    }

    /// Read and decode a DER length field.
    fn readLen(self: *Decoder) !usize {
        const b = try self.readByte();
        if ((b & 0x80) == 0) return b;
        const n = b & 0x7f;
        if (n == 0) return error.IndefiniteLength;
        if (n > 8) return error.LengthTooLarge;
        var val: usize = 0;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            val = (val << 8) | try self.readByte();
        }
        return val;
    }

    /// Parse the next TLV header without consuming the value bytes.
    ///
    /// Reads and decodes the tag and length fields of the next TLV structure,
    /// advancing the decoder offset past the header but leaving the value
    /// bytes unread. This allows inspection of the TLV type and size before
    /// deciding whether to parse the value.
    ///
    /// ## Returns
    /// Anonymous struct containing:
    /// - `tag`: The tag byte (class + constructed + number)
    /// - `len`: Length of the value field in bytes
    /// - `hdr_len`: Length of the header (tag + length octets) in bytes
    ///
    /// ## Errors
    /// - `error.Truncated`: Not enough bytes for header
    /// - `error.IndefiniteLength`: DER violation (indefinite length)
    /// - `error.LengthTooLarge`: Length field too large (>8 bytes)
    ///
    /// ## Usage
    /// Useful for conditional parsing based on tag type:
    /// ```zig
    /// const hdr = try decoder.nextHeader();
    /// if (hdr.tag == 0x30) { // SEQUENCE
    ///     // Process sequence value
    /// }
    /// ```
    ///
    /// ## RFC Reference
    /// X.690 §8.1 - TLV header consists of tag + length fields
    pub fn nextHeader(self: *Decoder) !struct { tag: u8, len: usize, hdr_len: usize } {
        const start = self.off;
        const tag = try self.readByte();
        const len = try self.readLen();
        return .{ .tag = tag, .len = len, .hdr_len = self.off - start };
    }

    /// Read one complete TLV structure.
    ///
    /// Parses the tag and length fields, then extracts the value bytes as a
    /// slice. The decoder offset is advanced past the entire TLV structure.
    /// This is the fundamental primitive for zero-copy DER parsing.
    ///
    /// ## Returns
    /// Anonymous struct containing:
    /// - `tag`: The tag byte identifying the type
    /// - `val`: Slice of value bytes (zero-copy reference into input buffer)
    ///
    /// ## Errors
    /// - `error.Truncated`: Not enough bytes for complete TLV
    /// - `error.IndefiniteLength`: DER violation (indefinite length)
    /// - `error.LengthTooLarge`: Length field too large
    ///
    /// ## Security Considerations
    /// Validates that the value length does not exceed buffer bounds before
    /// creating the slice. This prevents out-of-bounds memory access.
    ///
    /// ## Usage
    /// Generic TLV extraction:
    /// ```zig
    /// const tlv = try decoder.readTLV();
    /// switch (tlv.tag) {
    ///     0x02 => // INTEGER
    ///     0x04 => // OCTET STRING
    ///     else => return error.UnexpectedTag,
    /// }
    /// ```
    ///
    /// ## RFC Reference
    /// X.690 §8.1 - Complete TLV structure encoding
    pub fn readTLV(self: *Decoder) !struct { tag: u8, val: []const u8 } {
        const hdr = try self.nextHeader();
        // APPSEC-2026-06-10-01: validate against remaining bytes WITHOUT the
        // overflowing `off + len` add. `hdr.len` is attacker-controlled up to
        // maxInt(usize) via an 8-octet DER long-form length; computing
        // `self.off + hdr.len` first could wrap and bypass the bounds check,
        // yielding an inverted (start > end) slice -> OOB read / panic.
        if (hdr.len > self.buf.len - self.off) return error.Truncated;
        const end = self.off + hdr.len;
        const val = self.buf[self.off..end];
        self.off = end;
        return .{ .tag = hdr.tag, .val = val };
    }

    /// Read a SEQUENCE and return its content bytes for nested decoding.
    ///
    /// Parses a SEQUENCE TLV structure and extracts its content bytes.
    /// SEQUENCE (tag 16, universal class, constructed) is the fundamental
    /// ASN.1 type for representing ordered collections of fields.
    ///
    /// The returned bytes contain the nested TLV structures that make up
    /// the sequence content. Callers should create a new Decoder over
    /// these bytes to parse the nested elements.
    ///
    /// ## Returns
    /// Slice containing the SEQUENCE content bytes (zero-copy)
    ///
    /// ## Errors
    /// - `error.UnexpectedTag`: Tag is not SEQUENCE (0x30)
    /// - `error.Truncated`: Not enough bytes for complete SEQUENCE
    ///
    /// ## DER Requirements
    /// - SEQUENCE tag must be 0x30 (universal, constructed, tag number 16)
    /// - Length must be definite (no indefinite length in DER)
    ///
    /// ## Usage Example
    /// ```zig
    /// // Parse Certificate ::= SEQUENCE { ... }
    /// const cert_seq = try decoder.readSequence();
    /// var inner = asn1.Decoder.init(cert_seq);
    /// const tbs_seq = try inner.readSequence(); // TBSCertificate
    /// ```
    ///
    /// ## RFC Reference
    /// X.690 §8.9 - SEQUENCE encoding (constructed, tag 16)
    /// X.690 §10.1 - DER requires definite length
    /// RFC 5280 §4.1 - X.509 Certificate uses nested SEQUENCE structures
    pub fn readSequence(self: *Decoder) ![]const u8 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 16 or !isConstructed(tlv.tag))
            return error.UnexpectedTag;
        return tlv.val;
    }

    /// Read an INTEGER and return its value as u64.
    ///
    /// Parses an INTEGER TLV structure and decodes the value as a non-negative
    /// integer up to 64 bits. ASN.1 INTEGER uses big-endian two's complement
    /// encoding, but this implementation only supports non-negative values.
    ///
    /// ## Returns
    /// Integer value as u64 (0 to 2^64-1)
    ///
    /// ## Errors
    /// - `error.UnexpectedTag`: Tag is not INTEGER (0x02)
    /// - `error.Truncated`: Not enough bytes for complete INTEGER
    ///
    /// ## Limitations
    /// - Only supports non-negative integers (no negative value handling)
    /// - Maximum value is 2^64-1 (8 bytes)
    /// - No overflow checking (values >64 bits will wrap)
    ///
    /// ## DER Requirements (X.690 §10.4)
    /// - Leading 0x00 byte only if high bit of first content byte is set
    /// - No leading 0xFF for negative numbers (not supported here)
    /// - Minimum number of octets (no unnecessary leading zeros)
    ///
    /// ## Usage in X.509
    /// Certificate version, serial number, and validity periods use INTEGER type.
    /// ```zig
    /// const version = try decoder.readInteger(); // Version (0, 1, 2 for v1/v2/v3)
    /// const serial = try decoder.readInteger(); // Serial number
    /// ```
    ///
    /// ## RFC Reference
    /// X.690 §8.3 - INTEGER encoding (tag 2)
    /// X.690 §10.4 - DER INTEGER encoding rules
    /// RFC 5280 §4.1.2.2 - Certificate serial number as INTEGER
    pub fn readInteger(self: *Decoder) !u64 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 2)
            return error.UnexpectedTag;
        // SEC-052: Reject integers that exceed 8 bytes to prevent silent
        // truncation when accumulating into a u64.  ASN.1 INTEGERs can be
        // arbitrarily large, but callers of this helper expect a u64 result.
        if (tlv.val.len > 8) return error.IntegerOverflow;
        var v: u64 = 0;
        for (tlv.val) |b| {
            v = (v << 8) | b;
        }
        return v;
    }

    /// Read an OCTET STRING and return its content bytes.
    ///
    /// Parses an OCTET STRING TLV structure and returns the raw byte content.
    /// OCTET STRING (tag 4) represents arbitrary byte sequences.
    ///
    /// In X.509 certificates, OCTET STRINGs are used for:
    /// - Extension values (which contain DER-encoded structures)
    /// - Key identifiers (Subject Key Identifier, Authority Key Identifier)
    /// - Encapsulated content that requires further parsing
    ///
    /// ## Returns
    /// Slice containing the OCTET STRING content bytes (zero-copy)
    ///
    /// ## Errors
    /// - `error.UnexpectedTag`: Tag is not OCTET STRING (0x04)
    /// - `error.Truncated`: Not enough bytes for complete OCTET STRING
    ///
    /// ## DER Requirements
    /// - OCTET STRING tag must be 0x04 (universal, primitive, tag number 4)
    /// - DER requires primitive encoding (X.690 §10.2), not constructed chunks
    ///
    /// ## Usage Example
    /// ```zig
    /// // Parse extension extnValue ::= OCTET STRING
    /// const ext_value = try decoder.readOctetString();
    /// var inner = asn1.Decoder.init(ext_value);
    /// // Parse DER structure inside OCTET STRING
    /// ```
    ///
    /// ## RFC Reference
    /// X.690 §8.7 - OCTET STRING encoding (tag 4)
    /// X.690 §10.2 - DER requires primitive encoding for strings
    /// RFC 5280 §4.2 - Extension values are OCTET STRINGs containing DER
    pub fn readOctetString(self: *Decoder) ![]const u8 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 4)
            return error.UnexpectedTag;
        return tlv.val;
    }

    /// Read a BIT STRING and return its content bytes (without unused bits prefix).
    ///
    /// Parses a BIT STRING TLV structure and returns the bit content as bytes.
    /// BIT STRING (tag 3) represents bit-aligned binary data where the number
    /// of bits may not be a multiple of 8.
    ///
    /// The first byte of the content specifies the number of unused bits (0-7)
    /// in the final byte. This implementation returns the remaining bytes without
    /// the unused bits prefix, but does not trim the unused bits from the last byte.
    ///
    /// In X.509 certificates, BIT STRINGs are used for:
    /// - SubjectPublicKeyInfo public key data
    /// - Certificate signature bits
    /// - KeyUsage extension bit flags
    /// - Issuer/Subject Unique Identifiers
    ///
    /// ## Returns
    /// Slice containing the BIT STRING content bytes (zero-copy, excluding unused bits byte)
    ///
    /// ## Errors
    /// - `error.UnexpectedTag`: Tag is not BIT STRING (0x03)
    /// - `error.Truncated`: Empty BIT STRING (missing unused bits byte)
    /// - `error.InvalidBitString`: Unused bits value >7 (DER violation)
    ///
    /// ## DER Requirements (X.690 §11.2)
    /// - BIT STRING tag must be 0x03 (universal, primitive, tag number 3)
    /// - First content byte = number of unused bits in final byte (0-7)
    /// - Unused bits must be set to 0 (but this is not validated here)
    /// - DER requires primitive encoding (X.690 §10.2)
    ///
    /// ## Usage Example
    /// ```zig
    /// // Parse SubjectPublicKeyInfo ::= SEQUENCE {
    /// //   algorithm AlgorithmIdentifier,
    /// //   subjectPublicKey BIT STRING  -- contains encoded public key
    /// // }
    /// const pubkey_bits = try decoder.readBitString();
    /// // pubkey_bits now contains the key bytes (e.g., EC point, RSA modulus)
    /// ```
    ///
    /// ## RFC Reference
    /// X.690 §8.6 - BIT STRING encoding (tag 3)
    /// X.690 §11.2 - DER BIT STRING encoding rules
    /// RFC 5280 §4.1 - SubjectPublicKeyInfo uses BIT STRING for public key
    pub fn readBitString(self: *Decoder) ![]const u8 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 3)
            return error.UnexpectedTag;
        if (tlv.val.len == 0) return error.Truncated;
        const unused_bits = tlv.val[0];
        if (unused_bits > 7) return error.InvalidBitString;
        return tlv.val[1..];
    }

    /// Read an OBJECT IDENTIFIER and return its encoded bytes.
    ///
    /// Parses an OBJECT IDENTIFIER (OID) TLV structure and returns the
    /// encoded OID bytes. OIDs (tag 6) uniquely identify algorithms,
    /// extensions, and other protocol elements using dotted notation
    /// (e.g., 1.2.840.113549.1.1.11 for sha256WithRSAEncryption).
    ///
    /// The encoding uses base-128 variable-length encoding for each arc.
    /// This implementation returns the raw encoded bytes; callers must
    /// decode the OID if they need the dotted notation.
    ///
    /// In X.509 certificates, OIDs are used for:
    /// - Signature algorithms (e.g., ecdsa-with-SHA256)
    /// - Public key algorithms (e.g., id-ecPublicKey, rsaEncryption)
    /// - Extension types (e.g., id-ce-subjectAltName, id-ce-basicConstraints)
    /// - Elliptic curve names (e.g., secp256r1, secp384r1)
    ///
    /// ## Returns
    /// Slice containing the OID encoded bytes (zero-copy)
    ///
    /// ## Errors
    /// - `error.UnexpectedTag`: Tag is not OBJECT IDENTIFIER (0x06)
    /// - `error.Truncated`: Not enough bytes for complete OID
    ///
    /// ## DER Requirements
    /// - OID tag must be 0x06 (universal, primitive, tag number 6)
    /// - First arc (X) and second arc (Y) are encoded together as (X*40 + Y)
    /// - Subsequent arcs use base-128 encoding (high bit = continuation)
    ///
    /// ## Usage Example
    /// ```zig
    /// // Parse AlgorithmIdentifier ::= SEQUENCE {
    /// //   algorithm OBJECT IDENTIFIER,
    /// //   parameters ANY DEFINED BY algorithm OPTIONAL
    /// // }
    /// const algo_seq = try decoder.readSequence();
    /// var inner = asn1.Decoder.init(algo_seq);
    /// const oid_bytes = try inner.readOID();
    /// // Compare against known OID values
    /// ```
    ///
    /// ## RFC Reference
    /// X.690 §8.19 - OBJECT IDENTIFIER encoding (tag 6)
    /// X.690 §8.19.2 - OID encoding rules (base-128)
    /// RFC 5280 §4.1.1.2 - AlgorithmIdentifier uses OID
    pub fn readOID(self: *Decoder) ![]const u8 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 6)
            return error.UnexpectedTag;
        return tlv.val;
    }

    /// Read a UTF8String and return its content bytes.
    ///
    /// Parses a UTF8String TLV structure and returns the UTF-8 encoded text.
    /// UTF8String (tag 12) represents Unicode text encoded in UTF-8.
    ///
    /// In X.509 certificates, UTF8String is used for:
    /// - Distinguished Name (DN) attributes (CN, O, OU, etc.)
    /// - Subject Alternative Name (DNS names, email addresses)
    /// - Extension values containing human-readable text
    ///
    /// ## Returns
    /// Slice containing the UTF-8 encoded string bytes (zero-copy)
    ///
    /// ## Errors
    /// - `error.UnexpectedTag`: Tag is not UTF8String (0x0C)
    /// - `error.Truncated`: Not enough bytes for complete UTF8String
    ///
    /// ## DER Requirements
    /// - UTF8String tag must be 0x0C (universal, primitive, tag number 12)
    /// - Content must be valid UTF-8 encoding (not validated here)
    /// - DER requires primitive encoding (X.690 §10.2)
    ///
    /// ## Usage Example
    /// ```zig
    /// // Parse DirectoryString ::= CHOICE {
    /// //   utf8String UTF8String,
    /// //   printableString PrintableString,
    /// //   ...
    /// // }
    /// const name = try decoder.readUtf8String();
    /// std.debug.print("Common Name: {s}\n", .{name});
    /// ```
    ///
    /// ## RFC Reference
    /// X.690 §8.23 - UTF8String encoding (tag 12)
    /// RFC 5280 §4.1.2.4 - DN attributes prefer UTF8String
    pub fn readUtf8String(self: *Decoder) ![]const u8 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 12)
            return error.UnexpectedTag;
        return tlv.val;
    }

    /// Read an IA5String and return its content bytes.
    ///
    /// Parses an IA5String TLV structure and returns the ASCII-encoded text.
    /// IA5String (tag 22) represents International Alphabet 5 (ASCII) text.
    ///
    /// In X.509 certificates, IA5String is used for:
    /// - DNS names in Subject Alternative Name (RFC 5280 §4.2.1.6)
    /// - Email addresses (rfc822Name)
    /// - URIs and URLs
    ///
    /// ## Returns
    /// Slice containing the IA5 (ASCII) encoded string bytes (zero-copy)
    ///
    /// ## Errors
    /// - `error.UnexpectedTag`: Tag is not IA5String (0x16)
    /// - `error.Truncated`: Not enough bytes for complete IA5String
    ///
    /// ## DER Requirements
    /// - IA5String tag must be 0x16 (universal, primitive, tag number 22)
    /// - Content must be valid ASCII (bytes 0x00-0x7F, not validated here)
    /// - DER requires primitive encoding (X.690 §10.2)
    ///
    /// ## Usage Example
    /// ```zig
    /// // Parse GeneralName ::= CHOICE {
    /// //   dNSName [2] IA5String,
    /// //   ...
    /// // }
    /// const dns_name = try decoder.readIa5String();
    /// // Match against server name (SNI)
    /// ```
    ///
    /// ## RFC Reference
    /// X.690 §8.21 - IA5String encoding (tag 22)
    /// RFC 5280 §4.2.1.6 - SubjectAltName dNSName uses IA5String
    pub fn readIa5String(self: *Decoder) ![]const u8 {
        const tlv = try self.readTLV();
        if (tagClass(tlv.tag) != .universal or tagNumber(tlv.tag) != 22)
            return error.UnexpectedTag;
        return tlv.val;
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

const testing = std.testing;

test "tagClass - extract tag class from tag byte" {
    // Universal class (00 in bits 7-6)
    try testing.expectEqual(TagClass.universal, tagClass(0x02)); // INTEGER
    try testing.expectEqual(TagClass.universal, tagClass(0x30)); // SEQUENCE

    // Application class (01 in bits 7-6)
    try testing.expectEqual(TagClass.application, tagClass(0x40));
    try testing.expectEqual(TagClass.application, tagClass(0x7F));

    // Context-specific class (10 in bits 7-6)
    try testing.expectEqual(TagClass.context, tagClass(0x80));
    try testing.expectEqual(TagClass.context, tagClass(0xA0));
    try testing.expectEqual(TagClass.context, tagClass(0xA3)); // Common in X.509 v3

    // Private class (11 in bits 7-6)
    try testing.expectEqual(TagClass.private, tagClass(0xC0));
    try testing.expectEqual(TagClass.private, tagClass(0xFF));
}

test "isConstructed - check if tag is constructed" {
    // Primitive tags (bit 5 = 0)
    try testing.expect(!isConstructed(0x02)); // INTEGER
    try testing.expect(!isConstructed(0x04)); // OCTET STRING
    try testing.expect(!isConstructed(0x06)); // OBJECT IDENTIFIER

    // Constructed tags (bit 5 = 1)
    try testing.expect(isConstructed(0x30)); // SEQUENCE
    try testing.expect(isConstructed(0x31)); // SET
    try testing.expect(isConstructed(0xA0)); // Context [0] EXPLICIT
    try testing.expect(isConstructed(0xA3)); // Context [3] EXPLICIT
}

test "tagNumber - extract tag number from tag byte" {
    // Universal tags
    try testing.expectEqual(@as(u8, 2), tagNumber(0x02)); // INTEGER
    try testing.expectEqual(@as(u8, 3), tagNumber(0x03)); // BIT STRING
    try testing.expectEqual(@as(u8, 4), tagNumber(0x04)); // OCTET STRING
    try testing.expectEqual(@as(u8, 6), tagNumber(0x06)); // OBJECT IDENTIFIER
    try testing.expectEqual(@as(u8, 16), tagNumber(0x30)); // SEQUENCE
    try testing.expectEqual(@as(u8, 17), tagNumber(0x31)); // SET

    // Context-specific tag numbers
    try testing.expectEqual(@as(u8, 0), tagNumber(0xA0)); // [0]
    try testing.expectEqual(@as(u8, 3), tagNumber(0xA3)); // [3]
    try testing.expectEqual(@as(u8, 31), tagNumber(0xBF)); // Multi-byte indicator
}

test "Decoder.readInteger - parse INTEGER values" {
    // Single byte integer: 42
    {
        const der = [_]u8{ 0x02, 0x01, 0x2A }; // INTEGER 42
        var decoder = Decoder.init(&der);
        const value = try decoder.readInteger();
        try testing.expectEqual(@as(u64, 42), value);
    }

    // Two byte integer: 256
    {
        const der = [_]u8{ 0x02, 0x02, 0x01, 0x00 }; // INTEGER 256
        var decoder = Decoder.init(&der);
        const value = try decoder.readInteger();
        try testing.expectEqual(@as(u64, 256), value);
    }

    // Multi-byte integer with leading zero (MSB is 0x80+)
    {
        const der = [_]u8{ 0x02, 0x03, 0x00, 0xFF, 0xFF }; // INTEGER 65535
        var decoder = Decoder.init(&der);
        const value = try decoder.readInteger();
        try testing.expectEqual(@as(u64, 65535), value);
    }

    // Zero
    {
        const der = [_]u8{ 0x02, 0x01, 0x00 }; // INTEGER 0
        var decoder = Decoder.init(&der);
        const value = try decoder.readInteger();
        try testing.expectEqual(@as(u64, 0), value);
    }
}

test "Decoder.readSequence - parse SEQUENCE structures" {
    // Empty sequence
    {
        const der = [_]u8{ 0x30, 0x00 }; // SEQUENCE { }
        var decoder = Decoder.init(&der);
        const seq = try decoder.readSequence();
        try testing.expectEqual(@as(usize, 0), seq.len);
    }

    // Sequence with INTEGER
    {
        const der = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x05 }; // SEQUENCE { INTEGER 5 }
        var decoder = Decoder.init(&der);
        const seq = try decoder.readSequence();
        try testing.expectEqual(@as(usize, 3), seq.len);

        var inner = Decoder.init(seq);
        const value = try inner.readInteger();
        try testing.expectEqual(@as(u64, 5), value);
    }

    // Nested sequences
    {
        const der = [_]u8{
            0x30, 0x06, // SEQUENCE (6 bytes) {
            0x30, 0x04, //   SEQUENCE (4 bytes) {
            0x02, 0x02, //     INTEGER (2 bytes)
            0x01, 0x00, //       256
            //   }
            // }
        };
        var decoder = Decoder.init(&der);
        const outer_seq = try decoder.readSequence();
        try testing.expectEqual(@as(usize, 6), outer_seq.len);

        var inner1 = Decoder.init(outer_seq);
        const inner_seq = try inner1.readSequence();
        try testing.expectEqual(@as(usize, 4), inner_seq.len);

        var inner2 = Decoder.init(inner_seq);
        const value = try inner2.readInteger();
        try testing.expectEqual(@as(u64, 256), value);
    }
}

test "Decoder.readOctetString - parse OCTET STRING" {
    // Empty octet string
    {
        const der = [_]u8{ 0x04, 0x00 }; // OCTET STRING ""
        var decoder = Decoder.init(&der);
        const octets = try decoder.readOctetString();
        try testing.expectEqual(@as(usize, 0), octets.len);
    }

    // Simple octet string
    {
        const der = [_]u8{ 0x04, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f }; // OCTET STRING "Hello"
        var decoder = Decoder.init(&der);
        const octets = try decoder.readOctetString();
        try testing.expectEqualSlices(u8, "Hello", octets);
    }

    // Octet string with binary data
    {
        const der = [_]u8{ 0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF }; // OCTET STRING with hex data
        var decoder = Decoder.init(&der);
        const octets = try decoder.readOctetString();
        try testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, octets);
    }
}

test "Decoder.readBitString - parse BIT STRING" {
    // Bit string with no unused bits
    {
        const der = [_]u8{ 0x03, 0x04, 0x00, 0x0A, 0x3B, 0x5F }; // BIT STRING, 0 unused bits
        var decoder = Decoder.init(&der);
        const bits = try decoder.readBitString();
        try testing.expectEqualSlices(u8, &[_]u8{ 0x0A, 0x3B, 0x5F }, bits);
    }

    // Bit string with 6 unused bits in last byte
    {
        const der = [_]u8{ 0x03, 0x04, 0x06, 0x6e, 0x5d, 0xc0 }; // BIT STRING, 6 unused bits
        var decoder = Decoder.init(&der);
        const bits = try decoder.readBitString();
        try testing.expectEqualSlices(u8, &[_]u8{ 0x6e, 0x5d, 0xc0 }, bits);
    }

    // Empty bit string
    {
        const der = [_]u8{ 0x03, 0x01, 0x00 }; // BIT STRING, 0 unused bits, no data
        var decoder = Decoder.init(&der);
        const bits = try decoder.readBitString();
        try testing.expectEqual(@as(usize, 0), bits.len);
    }
}

test "Decoder.readOID - parse OBJECT IDENTIFIER" {
    // OID 1.2.840.113549.1.1.1 (rsaEncryption)
    {
        const der = [_]u8{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
        var decoder = Decoder.init(&der);
        const oid = try decoder.readOID();
        try testing.expectEqualSlices(u8, &[_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 }, oid);
    }

    // OID 2.5.29.17 (id-ce-subjectAltName)
    {
        const der = [_]u8{ 0x06, 0x03, 0x55, 0x1D, 0x11 };
        var decoder = Decoder.init(&der);
        const oid = try decoder.readOID();
        try testing.expectEqualSlices(u8, &[_]u8{ 0x55, 0x1D, 0x11 }, oid);
    }

    // OID 1.3.101.112 (Ed25519)
    {
        const der = [_]u8{ 0x06, 0x03, 0x2B, 0x65, 0x70 };
        var decoder = Decoder.init(&der);
        const oid = try decoder.readOID();
        try testing.expectEqualSlices(u8, &[_]u8{ 0x2B, 0x65, 0x70 }, oid);
    }
}

test "Decoder.readUtf8String - parse UTF8String" {
    // ASCII string
    {
        const der = [_]u8{ 0x0C, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f }; // UTF8String "Hello"
        var decoder = Decoder.init(&der);
        const str = try decoder.readUtf8String();
        try testing.expectEqualSlices(u8, "Hello", str);
    }

    // UTF-8 multi-byte characters
    {
        const der = [_]u8{ 0x0C, 0x06, 0xE4, 0xBD, 0xA0, 0xE5, 0xA5, 0xBD }; // UTF8String "你好" (Hello in Chinese)
        var decoder = Decoder.init(&der);
        const str = try decoder.readUtf8String();
        try testing.expectEqualSlices(u8, &[_]u8{ 0xE4, 0xBD, 0xA0, 0xE5, 0xA5, 0xBD }, str);
    }

    // Empty string
    {
        const der = [_]u8{ 0x0C, 0x00 }; // UTF8String ""
        var decoder = Decoder.init(&der);
        const str = try decoder.readUtf8String();
        try testing.expectEqual(@as(usize, 0), str.len);
    }
}

test "Decoder.readIa5String - parse IA5String" {
    // Domain name
    {
        const der = [_]u8{ 0x16, 0x0B, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d }; // IA5String "example.com"
        var decoder = Decoder.init(&der);
        const str = try decoder.readIa5String();
        try testing.expectEqualSlices(u8, "example.com", str);
    }

    // Email address
    {
        const der = [_]u8{ 0x16, 0x10, 0x75, 0x73, 0x65, 0x72, 0x40, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d }; // IA5String "user@example.com" (16 bytes)
        var decoder = Decoder.init(&der);
        const str = try decoder.readIa5String();
        try testing.expectEqualSlices(u8, "user@example.com", str);
    }
}

test "Decoder.readTLV - parse Tag-Length-Value" {
    // Read a complete TLV structure
    const der = [_]u8{ 0x02, 0x02, 0x01, 0x00 }; // INTEGER 256
    var decoder = Decoder.init(&der);
    const tlv = try decoder.readTLV();

    try testing.expectEqual(@as(u8, 0x02), tlv.tag); // INTEGER tag
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00 }, tlv.val);
}

test "Decoder.nextHeader - peek at TLV header" {
    const der = [_]u8{ 0x30, 0x05, 0x02, 0x01, 0x42, 0x02, 0x00 }; // SEQUENCE { INTEGER 66, INTEGER 0 }
    var decoder = Decoder.init(&der);

    // Peek at SEQUENCE header
    const hdr1 = try decoder.nextHeader();
    try testing.expectEqual(@as(u8, 0x30), hdr1.tag);
    try testing.expectEqual(@as(usize, 5), hdr1.len);
    try testing.expectEqual(@as(usize, 2), hdr1.hdr_len);
}

test "Decoder - sequential parsing" {
    // Parse multiple TLVs sequentially
    const der = [_]u8{
        0x02, 0x01, 0x01, // INTEGER 1
        0x02, 0x01, 0x02, // INTEGER 2
        0x02, 0x01, 0x03, // INTEGER 3
    };
    var decoder = Decoder.init(&der);

    const val1 = try decoder.readInteger();
    try testing.expectEqual(@as(u64, 1), val1);

    const val2 = try decoder.readInteger();
    try testing.expectEqual(@as(u64, 2), val2);

    const val3 = try decoder.readInteger();
    try testing.expectEqual(@as(u64, 3), val3);
}

test "Decoder - long form length encoding" {
    // Test length field requiring multiple bytes (> 127)
    var der: [200]u8 = undefined;
    der[0] = 0x04; // OCTET STRING tag
    der[1] = 0x81; // Long form length: 1 byte follows
    der[2] = 150; // Length = 150 bytes
    @memset(der[3..153], 0xAB); // Fill with data

    var decoder = Decoder.init(der[0..153]);
    const octets = try decoder.readOctetString();
    try testing.expectEqual(@as(usize, 150), octets.len);
    try testing.expect(octets[0] == 0xAB);
}

test "Decoder - context-specific tags" {
    // Context [3] EXPLICIT tag (common in X.509 v3 extensions)
    const der = [_]u8{
        0xA3, 0x04, // [3] EXPLICIT (4 bytes)
        0x02, 0x02, //   INTEGER (2 bytes)
        0x01, 0x00, //     value: 256
    };
    var decoder = Decoder.init(&der);
    const tlv = try decoder.readTLV();

    try testing.expectEqual(TagClass.context, tagClass(tlv.tag));
    try testing.expectEqual(@as(u8, 3), tagNumber(tlv.tag));
    try testing.expect(isConstructed(tlv.tag));
    try testing.expectEqual(@as(usize, 4), tlv.val.len);

    // Parse inner INTEGER
    var inner = Decoder.init(tlv.val);
    const value = try inner.readInteger();
    try testing.expectEqual(@as(u64, 256), value);
}
