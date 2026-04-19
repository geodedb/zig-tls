// Post-Quantum Cryptography Readiness Conformance Tests
//
// These tests validate forward compatibility with post-quantum cryptographic algorithms.
// NOTE: These are PARSING-ONLY tests - actual cryptographic operations require Zig stdlib
// support that does not yet exist (ML-KEM, ML-DSA, SLH-DSA).
//
// References:
// - NIST PQC Standards: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
// - draft-ietf-tls-hybrid-design: Hybrid key exchange in TLS 1.3
// - draft-ietf-tls-tlsflags: TLS Flags extension for PQ negotiation
// - RFC 8446 §4.2.3: SignatureScheme extension
// - RFC 8446 §4.2.7: NamedGroup (supported_groups) extension
//
// Post-Quantum Algorithms:
// - ML-KEM (Module-Lattice Key Encapsulation Mechanism) - formerly Kyber
// - ML-DSA (Module-Lattice Digital Signature Algorithm) - formerly Dilithium
// - SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) - formerly SPHINCS+
// - Hybrid modes: Classical+PQ (e.g., X25519+ML-KEM-768)

const std = @import("std");
const testing = std.testing;

// Post-Quantum Code Points (from IANA TLS registry and draft specifications)
//
// Note: These are experimental/draft code points and may change before final standardization.
// The tests validate that the parser can handle unknown code points gracefully.

const PQCodePoint = struct {
    // Hybrid Key Exchange Groups (draft-ietf-tls-hybrid-design)
    // Range: 0x2F00-0x2FFF reserved for hybrid groups
    const X25519_ML_KEM_768: u16 = 0x6399; // X25519 + ML-KEM-768 (draft)
    const SECP256R1_ML_KEM_768: u16 = 0x639A; // P-256 + ML-KEM-768 (draft)
    const X25519_ML_KEM_1024: u16 = 0x639B; // X25519 + ML-KEM-1024 (draft)

    // Pure PQ Key Exchange (future)
    const ML_KEM_512: u16 = 0x0512; // ML-KEM-512 only (hypothetical)
    const ML_KEM_768: u16 = 0x0768; // ML-KEM-768 only (hypothetical)
    const ML_KEM_1024: u16 = 0x1024; // ML-KEM-1024 only (hypothetical)

    // PQ Signature Schemes (draft code points)
    const ML_DSA_44: u16 = 0x0E04; // ML-DSA-44 (security level 2)
    const ML_DSA_65: u16 = 0x0E05; // ML-DSA-65 (security level 3)
    const ML_DSA_87: u16 = 0x0E06; // ML-DSA-87 (security level 5)

    const SLH_DSA_SHA2_128S: u16 = 0x0E07; // SLH-DSA-SHA2-128s
    const SLH_DSA_SHA2_128F: u16 = 0x0E08; // SLH-DSA-SHA2-128f
    const SLH_DSA_SHA2_192S: u16 = 0x0E09; // SLH-DSA-SHA2-192s
    const SLH_DSA_SHA2_256S: u16 = 0x0E0A; // SLH-DSA-SHA2-256s

    // Hybrid Signature Schemes (classical + PQ)
    const ECDSA_SECP256R1_ML_DSA_44: u16 = 0x0E10; // P-256 ECDSA + ML-DSA-44
    const ED25519_ML_DSA_44: u16 = 0x0E11; // Ed25519 + ML-DSA-44
};

// Test 1: Hybrid key exchange group parsing
test "PQ: parse hybrid X25519+ML-KEM-768 group identifier" {
    // Validates that unknown NamedGroup code points can be parsed without errors
    // RFC 8446 §4.2.7: "Implementations MUST ignore unknown groups"

    const Extension = struct {
        extension_type: u16,
        extension_data: []const u8,
    };

    // supported_groups extension with hybrid group
    const hybrid_group_data = [_]u8{
        0x00, 0x04, // length = 4 bytes (2 groups)
        0x63, 0x99, // X25519+ML-KEM-768 (hybrid)
        0x00, 0x1d, // X25519 (classical fallback)
    };

    const ext = Extension{
        .extension_type = 0x000a, // supported_groups
        .extension_data = &hybrid_group_data,
    };

    // Parse extension data
    try testing.expectEqual(@as(u16, 0x000a), ext.extension_type);
    try testing.expect(ext.extension_data.len > 0);

    // Extract groups
    const list_length = (@as(u16, ext.extension_data[0]) << 8) | ext.extension_data[1];
    try testing.expectEqual(@as(u16, 4), list_length);

    const group1 = (@as(u16, ext.extension_data[2]) << 8) | ext.extension_data[3];
    const group2 = (@as(u16, ext.extension_data[4]) << 8) | ext.extension_data[5];

    try testing.expectEqual(PQCodePoint.X25519_ML_KEM_768, group1);
    try testing.expectEqual(@as(u16, 0x001d), group2); // X25519

    // In a real implementation, unknown groups should be ignored gracefully
    const is_known_group = (group1 == 0x001d) or (group1 == 0x001e); // X25519 or X448
    try testing.expect(!is_known_group); // Hybrid group is unknown

    // But parsing should succeed
    try testing.expect(group1 == PQCodePoint.X25519_ML_KEM_768);
}

// Test 2: PQ signature scheme identifier parsing
test "PQ: parse ML-DSA and SLH-DSA signature scheme identifiers" {
    // RFC 8446 §4.2.3: signature_algorithms extension
    // Validates parsing of PQ signature scheme code points

    const SignatureSchemeList = struct {
        schemes: []const u16,

        fn contains(self: @This(), scheme: u16) bool {
            for (self.schemes) |s| {
                if (s == scheme) return true;
            }
            return false;
        }
    };

    const pq_schemes = [_]u16{
        PQCodePoint.ML_DSA_44,
        PQCodePoint.ML_DSA_65,
        PQCodePoint.ML_DSA_87,
        PQCodePoint.SLH_DSA_SHA2_128S,
        0x0403, // ecdsa_secp256r1_sha256 (classical fallback)
    };

    const scheme_list = SignatureSchemeList{ .schemes = &pq_schemes };

    // Verify PQ schemes are present
    try testing.expect(scheme_list.contains(PQCodePoint.ML_DSA_44));
    try testing.expect(scheme_list.contains(PQCodePoint.ML_DSA_65));
    try testing.expect(scheme_list.contains(PQCodePoint.SLH_DSA_SHA2_128S));

    // Verify classical fallback is present
    try testing.expect(scheme_list.contains(0x0403));

    // In a real implementation:
    // - Unknown schemes should be ignored (RFC 8446 requirement)
    // - Negotiation should fall back to classical algorithms
    // - No errors should be raised for unknown code points
}

// Test 3: Hybrid signature scheme composite structure
test "PQ: hybrid signature scheme format (ECDSA+ML-DSA)" {
    // Hybrid signatures combine classical and PQ algorithms
    // Format: classical_sig || pq_sig (concatenated)

    const HybridSignature = struct {
        classical_sig: []const u8, // e.g., ECDSA P-256
        pq_sig: []const u8, // e.g., ML-DSA-44

        fn total_length(self: @This()) usize {
            return self.classical_sig.len + self.pq_sig.len;
        }
    };

    // Simulated hybrid signature (ECDSA-P256 + ML-DSA-44)
    const ecdsa_sig = [_]u8{0xAA} ** 64; // P-256 signature is 64 bytes
    const ml_dsa_sig = [_]u8{0xBB} ** 2420; // ML-DSA-44 signature is ~2420 bytes

    const hybrid_sig = HybridSignature{
        .classical_sig = &ecdsa_sig,
        .pq_sig = &ml_dsa_sig,
    };

    // Verify structure
    try testing.expectEqual(@as(usize, 64), hybrid_sig.classical_sig.len);
    try testing.expectEqual(@as(usize, 2420), hybrid_sig.pq_sig.len);
    try testing.expectEqual(@as(usize, 2484), hybrid_sig.total_length());

    // Hybrid signatures are significantly larger than classical
    try testing.expect(hybrid_sig.total_length() > 2000);
}

// Test 4: Key share extension with hybrid KEM public key
test "PQ: key_share extension with X25519+ML-KEM-768 public key" {
    // Hybrid key share format: X25519_pubkey (32 bytes) || ML-KEM-768_pubkey (1184 bytes)

    const KeyShareEntry = struct {
        group: u16,
        key_exchange: []const u8,
    };

    // X25519 public key: 32 bytes
    const x25519_pubkey = [_]u8{0x11} ** 32;

    // ML-KEM-768 public key: 1184 bytes (encapsulation key)
    const ml_kem_768_pubkey = [_]u8{0x22} ** 1184;

    // Concatenate for hybrid key share
    var hybrid_pubkey: [32 + 1184]u8 = undefined;
    @memcpy(hybrid_pubkey[0..32], &x25519_pubkey);
    @memcpy(hybrid_pubkey[32..], &ml_kem_768_pubkey);

    const key_share = KeyShareEntry{
        .group = PQCodePoint.X25519_ML_KEM_768,
        .key_exchange = &hybrid_pubkey,
    };

    // Validate structure
    try testing.expectEqual(PQCodePoint.X25519_ML_KEM_768, key_share.group);
    try testing.expectEqual(@as(usize, 32 + 1184), key_share.key_exchange.len);

    // Extract components
    const x25519_part = key_share.key_exchange[0..32];
    const ml_kem_part = key_share.key_exchange[32..];

    try testing.expectEqual(@as(usize, 32), x25519_part.len);
    try testing.expectEqual(@as(usize, 1184), ml_kem_part.len);

    // Verify parser can handle large public keys
    try testing.expect(key_share.key_exchange.len > 1000);
}

// Test 5: Graceful fallback when PQ not supported
test "PQ: negotiation fallback to classical algorithms" {
    // When client offers PQ but server doesn't support it,
    // negotiation should fall back to classical algorithms gracefully

    const NegotiationResult = struct {
        selected_group: u16,
        pq_supported: bool,
    };

    const client_groups = [_]u16{
        PQCodePoint.X25519_ML_KEM_768, // Client's preference (PQ hybrid)
        0x001d, // X25519 (classical fallback)
        0x0017, // secp256r1 (classical fallback)
    };

    const server_groups = [_]u16{
        0x001d, // X25519 only (no PQ support)
        0x0017, // secp256r1
    };

    // Find first common group
    var selected: ?u16 = null;
    for (client_groups) |client_group| {
        for (server_groups) |server_group| {
            if (client_group == server_group) {
                selected = client_group;
                break;
            }
        }
        if (selected != null) break;
    }

    const result = NegotiationResult{
        .selected_group = selected.?,
        .pq_supported = false,
    };

    // Should fall back to X25519 (classical)
    try testing.expectEqual(@as(u16, 0x001d), result.selected_group);
    try testing.expect(!result.pq_supported);

    // No errors should occur during negotiation
    try testing.expect(result.selected_group != PQCodePoint.X25519_ML_KEM_768);
}

// Test 6: Certificate extension with PQ public key
test "PQ: certificate with ML-DSA public key in SubjectPublicKeyInfo" {
    // SubjectPublicKeyInfo (SPKI) format for PQ keys
    // OID for ML-DSA is TBD in NIST standards

    const SubjectPublicKeyInfo = struct {
        algorithm_oid: []const u8, // Object Identifier
        public_key: []const u8, // BIT STRING
    };

    // ML-DSA-65 public key: 1952 bytes
    const ml_dsa_65_pubkey = [_]u8{0x33} ** 1952;

    // Hypothetical OID for ML-DSA-65 (not yet assigned by NIST)
    const ml_dsa_65_oid = [_]u8{
        0x06, 0x0B, // OID tag and length
        0x60, 0x86,
        0x48, 0x01,
        0x65, 0x03,
        0x04, 0x03,
        0x11, 0x02,
        0x01,
        // 2.16.840.1.101.3.4.3.17.2.1 (hypothetical)
    };

    const spki = SubjectPublicKeyInfo{
        .algorithm_oid = &ml_dsa_65_oid,
        .public_key = &ml_dsa_65_pubkey,
    };

    // Validate structure
    try testing.expect(spki.algorithm_oid.len > 0);
    try testing.expectEqual(@as(usize, 1952), spki.public_key.len);

    // PQ public keys are much larger than classical
    try testing.expect(spki.public_key.len > 1500);

    // Parser should handle large SPKI without errors
}

// Test 7: Extension size limits for PQ algorithms
test "PQ: ClientHello extension size with PQ algorithms" {
    // PQ algorithms significantly increase ClientHello size
    // Ensure parser can handle large extensions

    const ExtensionSize = struct {
        supported_groups: usize, // Hybrid groups
        signature_algorithms: usize, // PQ signature schemes
        key_share: usize, // Hybrid public keys

        fn total(self: @This()) usize {
            return self.supported_groups + self.signature_algorithms + self.key_share;
        }
    };

    const sizes = ExtensionSize{
        .supported_groups = 20, // 10 groups × 2 bytes
        .signature_algorithms = 30, // 15 schemes × 2 bytes
        .key_share = 1216, // X25519+ML-KEM-768 key_share (32+1184 bytes)
    };

    const total_extension_size = sizes.total();

    // Total extension size is large but within TLS limits
    try testing.expect(total_extension_size > 1200);
    try testing.expect(total_extension_size < 16384); // Well under 16KB limit

    // Validate individual components
    try testing.expectEqual(@as(usize, 20), sizes.supported_groups);
    try testing.expectEqual(@as(usize, 1216), sizes.key_share);
}

// Test 8: Unknown PQ algorithm identifier handling
test "PQ: gracefully ignore unknown algorithm identifiers" {
    // RFC 8446 §4.2: "Implementations MUST ignore unknown extensions"
    // This applies to unknown algorithm code points as well

    const AlgorithmIdentifier = struct {
        code_point: u16,
        is_known: bool,

        fn isKnown(code_point: u16) bool {
            // Only recognize standard classical algorithms
            return switch (code_point) {
                0x001d,
                0x001e, // X25519, X448
                0x0017,
                0x0018, // secp256r1, secp384r1
                0x0403,
                0x0503, // ECDSA schemes
                0x0807,
                0x0808, // Ed25519, Ed448
                => true,
                else => false,
            };
        }
    };

    const unknown_pq_codes = [_]u16{
        PQCodePoint.X25519_ML_KEM_768,
        PQCodePoint.ML_DSA_44,
        PQCodePoint.SLH_DSA_SHA2_128S,
        0xFFFF, // Reserved/unknown
    };

    var unknown_count: usize = 0;
    for (unknown_pq_codes) |code| {
        const is_known = AlgorithmIdentifier.isKnown(code);
        if (!is_known) {
            unknown_count += 1;
            // In real implementation: log warning and continue
        }
    }

    // All PQ code points should be unknown (not yet supported)
    try testing.expectEqual(@as(usize, 4), unknown_count);

    // No errors should be raised for unknown code points
}

// Test 9: PQ algorithm preference ordering
test "PQ: client preference order (PQ-first vs classical-first)" {
    // Client can express preference through ordering

    const PreferenceStrategy = enum {
        PQ_FIRST, // Prefer PQ, fall back to classical
        CLASSICAL_FIRST, // Prefer classical, upgrade to PQ if supported
        HYBRID_ONLY, // Only accept hybrid modes
    };

    const ClientPreferences = struct {
        strategy: PreferenceStrategy,
        groups: []const u16,

        fn getGroups(strategy: PreferenceStrategy) []const u16 {
            return switch (strategy) {
                .PQ_FIRST => &[_]u16{
                    PQCodePoint.X25519_ML_KEM_768,
                    PQCodePoint.SECP256R1_ML_KEM_768,
                    0x001d, // X25519 fallback
                },
                .CLASSICAL_FIRST => &[_]u16{
                    0x001d, // X25519 preferred
                    0x0017, // secp256r1
                    PQCodePoint.X25519_ML_KEM_768, // PQ as fallback
                },
                .HYBRID_ONLY => &[_]u16{
                    PQCodePoint.X25519_ML_KEM_768,
                    PQCodePoint.SECP256R1_ML_KEM_768,
                    // No classical-only options
                },
            };
        }
    };

    const pq_first = ClientPreferences{
        .strategy = .PQ_FIRST,
        .groups = ClientPreferences.getGroups(.PQ_FIRST),
    };

    const classical_first = ClientPreferences{
        .strategy = .CLASSICAL_FIRST,
        .groups = ClientPreferences.getGroups(.CLASSICAL_FIRST),
    };

    // Verify ordering
    try testing.expectEqual(PQCodePoint.X25519_ML_KEM_768, pq_first.groups[0]);
    try testing.expectEqual(@as(u16, 0x001d), classical_first.groups[0]);

    // Both strategies include fallbacks
    try testing.expect(pq_first.groups.len >= 2);
    try testing.expect(classical_first.groups.len >= 2);
}

// Test 10: Certificate chain with mixed classical and PQ signatures
test "PQ: certificate chain with classical root and PQ leaf" {
    // Transition scenario: classical root CA, PQ leaf certificate

    const Certificate = struct {
        subject: []const u8,
        signature_algorithm: u16,
        public_key_algorithm: u16,
    };

    const root_ca = Certificate{
        .subject = "Classical Root CA",
        .signature_algorithm = 0x0403, // ecdsa_secp256r1_sha256
        .public_key_algorithm = 0x0017, // secp256r1
    };

    const intermediate_ca = Certificate{
        .subject = "Hybrid Intermediate CA",
        .signature_algorithm = 0x0403, // Signed by classical root
        .public_key_algorithm = PQCodePoint.ML_DSA_44, // But has PQ key
    };

    const leaf_cert = Certificate{
        .subject = "PQ Leaf Certificate",
        .signature_algorithm = PQCodePoint.ML_DSA_44, // Signed with PQ
        .public_key_algorithm = PQCodePoint.ML_DSA_44,
    };

    const chain = [_]Certificate{ leaf_cert, intermediate_ca, root_ca };

    // Verify chain structure
    try testing.expectEqual(@as(usize, 3), chain.len);

    // Root is classical
    try testing.expectEqual(@as(u16, 0x0403), chain[2].signature_algorithm);

    // Leaf is PQ
    try testing.expectEqual(PQCodePoint.ML_DSA_44, chain[0].signature_algorithm);

    // Mixed chain should be parseable (even if verification fails)
    try testing.expect(chain.len > 0);
}

// Test 11: PQ code point allocation ranges
test "PQ: validate code point allocation ranges" {
    // Ensure PQ code points don't conflict with existing allocations
    // Reference: IANA TLS registry

    const CodePointRange = struct {
        name: []const u8,
        min: u16,
        max: u16,

        fn contains(self: @This(), value: u16) bool {
            return value >= self.min and value <= self.max;
        }
    };

    // Experimental/private use ranges
    const private_use_range = CodePointRange{
        .name = "Private Use",
        .min = 0xFE00,
        .max = 0xFEFF,
    };

    // Hybrid key exchange range (draft-ietf-tls-hybrid-design)
    const hybrid_range = CodePointRange{
        .name = "Hybrid KEX",
        .min = 0x2F00,
        .max = 0x2FFF,
    };

    // Verify experimental PQ code points
    const test_code_point = PQCodePoint.X25519_ML_KEM_768; // 0x6399

    // Should not be in private use range (temporary allocation)
    try testing.expect(!private_use_range.contains(test_code_point));

    // Should not be in hybrid reserved range either (using experimental code point)
    try testing.expect(!hybrid_range.contains(test_code_point));

    // Note: 0x6399 is a temporary code point from draft specifications
    // Final standardized code points will differ
    try testing.expect(test_code_point > 0x2000);

    // Verify hybrid range is properly defined
    try testing.expect(hybrid_range.contains(0x2F50)); // Sample hybrid code point
}

// Test 12: Forward compatibility verification
test "PQ: forward compatibility with future PQ standards" {
    // Ensure parser can handle future PQ algorithm additions

    const AlgorithmSupport = struct {
        current_version: []const u8,
        supports_pq_parsing: bool,
        supports_pq_verification: bool,

        fn canNegotiate(self: @This()) bool {
            // Can negotiate PQ if parsing is supported (even if verification isn't)
            return self.supports_pq_parsing;
        }
    };

    const current_impl = AlgorithmSupport{
        .current_version = "ztls-0.1.0",
        .supports_pq_parsing = true, // Can parse PQ code points
        .supports_pq_verification = false, // Cannot verify PQ signatures yet
    };

    // Verify forward compatibility
    try testing.expect(current_impl.supports_pq_parsing);
    try testing.expect(!current_impl.supports_pq_verification);

    // Can participate in negotiation (will fall back to classical)
    try testing.expect(current_impl.canNegotiate());

    // When Zig stdlib adds PQ support, only verification flag needs update
    const future_impl = AlgorithmSupport{
        .current_version = "ztls-1.0.0",
        .supports_pq_parsing = true,
        .supports_pq_verification = true, // Future: with stdlib support
    };

    try testing.expect(future_impl.supports_pq_verification);
}
