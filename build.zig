// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // SEC-077: Build gate for insecure cert-validation bypass.
    // When false (default), any runtime use of
    // x509.InsecureValidation.testing_only_i_know_what_i_am_doing panics.
    // Must be explicitly set to true at build time to enable test-only
    // validation bypass; NEVER set in a production build.
    const tls_insecure_testing = b.option(
        bool,
        "tls-insecure-testing",
        "Enable insecure test-only cert validation bypass (SEC-077; never use in production)",
    ) orelse false;

    // -Dwith_otel: compile in otel instrumentation. OFF by default;
    // when off the otel dependency is never resolved and the seam
    // collapses to a comptime-known no-op (verified by
    // otel/scripts/verify-consumer-noop.sh).
    const with_otel = false; // 2026-05-02: hardcoded after removing the lazy otel dep — see build.zig.zon header note.

    // -Dfips: route security crypto through the linked OpenSSL FIPS-140-3
    // provider. OFF by default; when off the fips dependency is never
    // resolved and the seam collapses to the std_shim backend (zero
    // OpenSSL link, zero overhead). Mirrors -Dwith_otel.
    const fips = b.option(bool, "fips", "Route security crypto through the linked FIPS-140-3 provider (off by default; zero overhead when off)") orelse false;
    const openssl_path = b.option([]const u8, "openssl_path", "OpenSSL install prefix for non-standard installs (e.g. /usr/local/ssl)");
    const link = @import("src/link.zig");

    const build_options = b.addOptions();
    build_options.addOption(bool, "tls_insecure_testing", tls_insecure_testing);
    build_options.addOption(bool, "with_otel", with_otel);
    build_options.addOption(bool, "fips", fips);
    // Materialize ONE shared `build_options` module. Each consumer module
    // imports the SAME module instance via `addImport` to avoid Zig 0.16's
    // "file exists in modules X and X0" error when two independent
    // `addOptions` modules end up sharing a transitive file path.
    const build_options_mod = build_options.createModule();

    // std_shim backend (always available; std.crypto-backed; no OpenSSL
    // link). Shared NAMED module so it is reached via one module identity.
    // It imports its sibling policy.zig via @import("policy.zig") (a
    // path-relative import, NOT a named module), so the canonical
    // non-fips backend is self-contained — no policy module wiring and no
    // fips dependency. Zig resolves @import("policy.zig") relative to
    // src/std_shim.zig, so policy.zig needs no addModule entry here.
    const std_shim_mod = b.addModule("std_shim", .{
        .root_source_file = b.path("src/std_shim.zig"),
        .target = target,
        .optimize = optimize,
    });

    // The crypto seam is a SHARED NAMED MODULE so every consumer resolves
    // the same crypto_backend.zig source via one module identity.
    const crypto_backend_mod = b.addModule("crypto_backend", .{
        .root_source_file = b.path("src/crypto_backend.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "build_options", .module = build_options_mod },
            .{ .name = "std_shim", .module = std_shim_mod },
        },
    });

    // fips backend: resolved LAZILY only when -Dfips=true so the disabled
    // build never fetches OpenSSL-linked code. In production this resolves
    // the git+https lazy dep declared in build.zig.zon; in this workspace
    // the dep is a LOCAL PATH dep (no remote yet — see build.zig.zon).
    if (fips) {
        if (b.lazyDependency("fips", .{ .target = target, .optimize = optimize })) |fips_dep| {
            const fips_mod = fips_dep.module("fips");
            crypto_backend_mod.addImport("fips", fips_mod);
            link.linkOpenssl(b, fips_mod, openssl_path);
            // Any compile unit that pulls crypto_backend transitively
            // links OpenSSL; link it onto the seam module too so the
            // symbols resolve in test/lib roots.
            link.linkOpenssl(b, crypto_backend_mod, openssl_path);
        }
    }

    // Observability seam (otel). Declared as a SHARED NAMED MODULE so
    // every consumer (lib + test roots that exercise the seam) resolves
    // to the same source file via `@import("observability")`. Using
    // relative `@import("observability.zig")` from each module would
    // trip Zig's "file exists in modules X and Y" error because the
    // file would be pulled into multiple module trees. The seam's
    // `enabled` flag tracks `build_options.with_otel`; when off, every
    // helper compiles to a comptime-known no-op and the otel dependency
    // is never resolved. The optional `otel` import is wired below
    // inside the `if (with_otel)` block.
    const observability_mod = b.addModule("observability", .{
        .root_source_file = b.path("src/observability.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "build_options", .module = build_options_mod },
        },
    });

    // thread-pool parallelism option
    const enable_tp = b.option(bool, "thread-pool", "Enable thread-pool-based parallelism") orelse true;

    // Get thread-pool dependency if enabled
    const tp_mod: ?*std.Build.Module = if (enable_tp) blk: {
        const tp_dep = b.dependency("thread_pool", .{
            .target = target,
            .optimize = optimize,
        });
        break :blk tp_dep.module("thread_pool");
    } else null;

    // ========================================================================
    // Define all TLS modules
    // ========================================================================
    //
    // Module organization follows RFC structure:
    // - Core cryptographic primitives (asn1, sig, key_schedule)
    // - Certificate handling (x509, ocsp, sct)
    // - TLS protocol (tls13, tls13_full, record)
    // - QUIC integration (transport_params, zero_rtt)
    // - Utilities (alert, logger, varint)

    // RFC 8446 §6: Alert Protocol
    // TLS alert descriptions and severity levels
    const alert_mod = b.addModule("alert", .{
        .root_source_file = b.path("src/alert.zig"),
        .target = target,
    });

    // SEC-074 / SEC-081: Cross-platform fail-closed entropy helper.
    // Wraps std.Io.Threaded.global_single_threaded.io().random so all
    // TLS code paths use the same portable, panic-on-failure source.
    const entropy_mod = b.addModule("entropy", .{
        .root_source_file = b.path("src/entropy.zig"),
        .target = target,
    });

    // PERF-024: Test-only allocator wrapper that tracks allocation counts
    // and byte totals. Consumed by tests/perf/*.zig to assert allocation
    // regressions (PERF-201, PERF-207). Not for production use.
    const counting_allocator_mod = b.addModule("counting_allocator", .{
        .root_source_file = b.path("src/testing/counting_allocator.zig"),
    });

    // QUAL-205: shared test helpers (hexToBytes, ...). Test-only. Consumed
    // by tests/*.zig and tests/rfc*/*.zig; must be registered as a named
    // module because Zig's module-path sandbox blocks `../test_utils.zig`
    // relative imports from subdirectories.
    const test_utils_mod = b.addModule("test_utils", .{
        .root_source_file = b.path("tests/test_utils.zig"),
    });

    // Shared embedded X.509 test-cert fixtures (so nested conformance test
    // modules can reach tests/test_certs/ despite the module path sandbox).
    const test_certs_mod = b.addModule("test_certs", .{
        .root_source_file = b.path("tests/test_certs.zig"),
    });

    // ITU-T X.690: ASN.1 DER encoding/decoding
    // Used for X.509 certificate parsing
    const asn1_mod = b.addModule("asn1", .{
        .root_source_file = b.path("src/asn1.zig"),
        .target = target,
    });

    // RFC 8446 §7: Key Schedule (HKDF-based)
    // RFC 9001 §5.1: QUIC packet protection keys
    const key_schedule_mod = b.addModule("quic_tls", .{
        .root_source_file = b.path("src/key_schedule.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "crypto_backend", .module = crypto_backend_mod },
            .{ .name = "build_options", .module = build_options_mod },
        },
    });

    // Logging utilities for QUIC-TLS debugging
    const logger_mod = b.addModule("quic_logger", .{
        .root_source_file = b.path("src/quic_logger.zig"),
        .target = target,
    });

    // RFC 9000 §16: Variable-Length Integer Encoding
    // Network byte order utilities
    const byteorder_mod = b.addModule("byteorder", .{
        .root_source_file = b.path("src/byteorder.zig"),
        .target = target,
    });

    // RFC 9000 §16: QUIC Variable-Length Integer Encoding
    const varint_mod = b.addModule("varint", .{
        .root_source_file = b.path("src/varint.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "byteorder", .module = byteorder_mod },
        },
    });

    // RFC 9000 §7.4, RFC 9001 §8.2: QUIC Transport Parameters
    // Extension 0x0039 in TLS EncryptedExtensions
    const transport_params_mod = b.addModule("quic_transport_params", .{
        .root_source_file = b.path("src/quic_transport_params.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "varint", .module = varint_mod },
        },
    });

    // RFC 8446 §4.2.3, §4.4.3: Signature Algorithms and Verification
    // Supports ECDSA (P-256, P-384), RSA-PSS, Ed25519
    const sig_mod = b.addModule("sig", .{
        .root_source_file = b.path("src/sig.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "asn1", .module = asn1_mod },
        },
    });

    // RFC 6962 §3.3: Signed Certificate Timestamp (SCT)
    // Certificate Transparency extension
    const sct_mod = b.addModule("sct", .{
        .root_source_file = b.path("src/sct.zig"),
        .target = target,
    });

    // RFC 5280: X.509 Public Key Infrastructure
    // Certificate parsing and validation
    const x509_mod = b.addModule("x509", .{
        .root_source_file = b.path("src/x509.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "asn1", .module = asn1_mod },
            .{ .name = "sig", .module = sig_mod },
            .{ .name = "build_options", .module = build_options_mod },
        },
    });

    // RFC 6960: Online Certificate Status Protocol (OCSP)
    // Certificate revocation checking
    const ocsp_mod = b.addModule("ocsp", .{
        .root_source_file = b.path("src/ocsp.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "asn1", .module = asn1_mod },
            .{ .name = "x509", .module = x509_mod },
        },
    });

    // RFC 5280 §5.1: Certificate Revocation List (CRL)
    // CRL parsing + provided-CRL revocation checking
    const crl_mod = b.addModule("crl", .{
        .root_source_file = b.path("src/crl.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "asn1", .module = asn1_mod },
            .{ .name = "x509", .module = x509_mod },
            .{ .name = "test_certs", .module = test_certs_mod },
        },
    });

    // RFC 8446 §5: Record Protocol
    // TLSPlaintext/TLSCiphertext, AEAD operations
    const record_mod = b.addModule("record", .{
        .root_source_file = b.path("src/record.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "quic_tls", .module = key_schedule_mod },
            .{ .name = "crypto_backend", .module = crypto_backend_mod },
            .{ .name = "build_options", .module = build_options_mod },
        },
    });

    // RFC 8446 §8: 0-RTT and Anti-Replay
    // Early data and replay prevention
    const zero_rtt_mod = b.addModule("zero_rtt", .{
        .root_source_file = b.path("src/zero_rtt.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "quic_tls", .module = key_schedule_mod },
        },
    });

    // RFC 8446 §4: Handshake Protocol (Message Parsing)
    // ClientHello, ServerHello, extensions, message building
    // Modularized in Phase 2: src/tls13/messages/
    const tls13_full_mod = b.addModule("tls13_full", .{
        .root_source_file = b.path("src/tls13_full.zig"),
        .target = target,
    });

    // RFC 8446 §4: Handshake State Machine (ClientHelloInfo.parse, phase
    // tracking, CRYPTO buffering). Exposed as a standalone module so
    // allocation-count benchmarks (tests/bench_allocs.zig) can import
    // ClientHelloInfo directly without pulling in the full tls13 module.
    const handshake_state_mod = b.addModule("handshake_state", .{
        .root_source_file = b.path("src/tls13/handshake_state.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "tls13_full", .module = tls13_full_mod },
        },
    });

    // QUAL-339: Standalone module rooted at src/tls13/messages/client_hello.zig
    // so the trace-capture executable (tests/fuzz/client_hello_trace_capture.zig)
    // can drive parseClientHello directly without pulling in the full
    // tls13/tls13_full hierarchy. The file's relative imports
    // ("core_types.zig", "helpers.zig") resolve from the same directory.
    const client_hello_mod = b.addModule("client_hello", .{
        .root_source_file = b.path("src/tls13/messages/client_hello.zig"),
        .target = target,
    });

    // RFC 8446: TLS 1.3 Core Protocol
    // RFC 9001: QUIC-TLS Integration
    // Main handshake state machine and context
    // Modularized in Phase 1: src/tls13/
    const tls13_mod = b.addModule("tls13", .{
        .root_source_file = b.path("src/tls13/mod.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "quic_tls", .module = key_schedule_mod },
            .{ .name = "x509", .module = x509_mod },
            .{ .name = "sig", .module = sig_mod },
            .{ .name = "alert", .module = alert_mod },
            .{ .name = "zero_rtt", .module = zero_rtt_mod },
            .{ .name = "tls13_full", .module = tls13_full_mod },
            .{ .name = "quic_logger", .module = logger_mod },
            .{ .name = "quic_transport_params", .module = transport_params_mod },
            .{ .name = "ocsp", .module = ocsp_mod },
            .{ .name = "sct", .module = sct_mod },
            .{ .name = "entropy", .module = entropy_mod },
            .{ .name = "build_options", .module = build_options_mod },
            // Observability seam: handshake span call sites live in
            // src/tls13/context.zig. Every emit collapses to a no-op
            // when -Dwith_otel=false.
            .{ .name = "observability", .module = observability_mod },
        },
    });

    // ========================================================================
    // Parallel Module
    // ========================================================================
    //
    // PERF-237b: removed in 0.2.0. The thread-pool-backed batch operations
    // (`parallelCertificateValidate`, `parallelSignatureVerify`, …) are no
    // longer part of the public API surface; the underlying `thread_pool`
    // dependency remains available for the `bench-threadpool` diagnostic
    // step, but no library code consumes it.

    // ========================================================================
    // Public API Module - Main Entry Point
    // ========================================================================
    //
    // The "ztls" module provides the stable public API surface.
    // All other modules are re-exported through src/lib.zig for
    // backward compatibility and ease of use.
    //
    // Usage: const ztls = @import("ztls");
    //        const tls13 = ztls.tls13;
    //        const Context = ztls.tls13.Context;

    const zig_tls_mod = b.addModule("ztls", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "alert", .module = alert_mod },
            .{ .name = "asn1", .module = asn1_mod },
            .{ .name = "quic_tls", .module = key_schedule_mod },
            .{ .name = "record", .module = record_mod },
            .{ .name = "sig", .module = sig_mod },
            .{ .name = "x509", .module = x509_mod },
            .{ .name = "zero_rtt", .module = zero_rtt_mod },
            .{ .name = "tls13_full", .module = tls13_full_mod },
            .{ .name = "tls13", .module = tls13_mod },
            .{ .name = "quic_logger", .module = logger_mod },
            .{ .name = "quic_transport_params", .module = transport_params_mod },
            .{ .name = "ocsp", .module = ocsp_mod },
            .{ .name = "sct", .module = sct_mod },
            // Observability seam re-exported as `ztls.observability` so
            // downstream consumers (and the seam tests) can drive the
            // disabled/enabled invariants through the public root.
            .{ .name = "observability", .module = observability_mod },
            .{ .name = "build_options", .module = build_options_mod },
        },
    });
    // PERF-237b: parallel module removed in 0.2.0; no addImport here.

    // ========================================================================
    // Unit Tests - Test each module independently
    // ========================================================================
    //
    // PERF-024: CountingAllocator lives at src/testing/counting_allocator.zig
    // and is consumed by tests/perf/*.zig to assert allocation-count regressions.

    const test_step = b.step("test", "Run all unit tests");

    // Helper to create test with imports
    const TestInfo = struct {
        name: []const u8,
        source: []const u8,
        imports: []const std.Build.Module.Import,
    };

    const tests = [_]TestInfo{
        .{ .name = "alert", .source = "src/alert.zig", .imports = &.{} },
        .{ .name = "asn1", .source = "src/asn1.zig", .imports = &.{} },
        .{
            .name = "key_schedule",
            .source = "src/key_schedule.zig",
            .imports = &.{
                .{ .name = "crypto_backend", .module = crypto_backend_mod },
                .{ .name = "build_options", .module = build_options_mod },
            },
        },
        .{ .name = "quic_logger", .source = "src/quic_logger.zig", .imports = &.{} },
        .{
            .name = "quic_transport_params",
            .source = "src/quic_transport_params.zig",
            .imports = &.{
                .{ .name = "varint", .module = varint_mod },
            },
        },
        .{ .name = "tls13_full", .source = "src/tls13_full.zig", .imports = &.{} },
        .{
            .name = "sig",
            .source = "src/sig.zig",
            .imports = &.{
                .{ .name = "asn1", .module = asn1_mod },
            },
        },
        .{
            .name = "x509",
            .source = "src/x509.zig",
            .imports = &.{
                .{ .name = "asn1", .module = asn1_mod },
                .{ .name = "build_options", .module = build_options_mod },
            },
        },
        .{
            .name = "crl",
            .source = "src/crl.zig",
            .imports = &.{
                .{ .name = "asn1", .module = asn1_mod },
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "test_certs", .module = test_certs_mod },
            },
        },
        .{
            .name = "record",
            .source = "src/record.zig",
            .imports = &.{
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "crypto_backend", .module = crypto_backend_mod },
                .{ .name = "build_options", .module = build_options_mod },
            },
        },
        .{
            .name = "zero_rtt",
            .source = "src/zero_rtt.zig",
            .imports = &.{
                .{ .name = "quic_tls", .module = key_schedule_mod },
            },
        },
        .{
            .name = "sec057_sigalg_panic",
            .source = "tests/security/sec057_sigalg_panic.zig",
            .imports = &.{
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        },
        .{
            .name = "sec058_tp_length_overflow",
            .source = "tests/security/sec058_tp_length_overflow.zig",
            .imports = &.{
                .{ .name = "quic_transport_params", .module = transport_params_mod },
            },
        },
        .{
            // APPSEC-2026-06-10-01: DER length-bounds `off + attacker_len`
            // integer-overflow rejection in asn1.readTLV and x509.parseCert.
            .name = "appsec01_asn1_length_overflow",
            .source = "tests/security/appsec01_asn1_length_overflow.zig",
            .imports = &.{
                .{ .name = "asn1", .module = asn1_mod },
                .{ .name = "x509", .module = x509_mod },
            },
        },
        .{
            // NEWGAP-06 / NEWGAP-07: client ServerHello hardening — duplicate
            // unknown-extension rejection + legacy_session_id_echo check.
            .name = "newgap06_07_serverhello_hardening",
            .source = "tests/security/newgap06_07_serverhello_hardening.zig",
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        },
        .{
            // NEWGAP-08: HelloRetryRequest §4.1.3/§4.1.4 field MUST-checks
            // (legacy_version, session_id echo, compression, cipher_suite).
            .name = "newgap08_hrr_field_checks",
            .source = "tests/security/newgap08_hrr_field_checks.zig",
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        },
        .{
            .name = "sec066_clienthello_dup_ext",
            .source = "tests/security/sec066_clienthello_dup_ext.zig",
            .imports = &.{
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        },
        .{
            // SEC-088: legacy_compression_methods enforcement (RFC 8446 §4.1.2).
            .name = "sec088_clienthello_compression",
            .source = "tests/security/sec088_clienthello_compression.zig",
            .imports = &.{
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        },
        .{
            // SEC-092: EncryptedExtensions duplicate-extension rejection.
            .name = "sec092_ee_dup_ext",
            .source = "tests/security/sec092_ee_dup_ext.zig",
            .imports = &.{
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        },
        .{
            // SEC-099: ClientHello.cipher_suites length-parity check
            // (RFC 8446 §4.1.2). Odd `cs_len` is rejected with
            // `error.IllegalCipherSuites` before the cipher-suite loop runs.
            .name = "sec099_cipher_suites_parity",
            .source = "tests/security/sec099_cipher_suites_parity.zig",
            .imports = &.{
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        },
        .{
            // SEC-098: pre_shared_key identities/binders cardinality
            // (RFC 8446 §4.2.11). Mismatched lists are rejected with
            // `error.PskBinderMismatch` before downstream PSK selection
            // can index out of bounds.
            .name = "sec098_psk_cardinality",
            .source = "tests/security/sec098_psk_cardinality.zig",
            .imports = &.{
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        },
        .{
            // GAP-0144 (= SEC-104 cross-ref): HelloRetryRequest
            // duplicate-extension gate (RFC 8446 §4.2). Twin of SEC-066
            // (CH), SEC-092 (EE/SH), and SEC-079 (X.509).
            .name = "gap0144_hrr_dup_ext",
            .source = "tests/security/gap0144_hrr_dup_ext.zig",
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        },
        .{
            // GAP-0139: CertificateRequest level + post-handshake-auth gate.
            .name = "gap0139_certreq_level_gate",
            .source = "tests/security/gap0139_certreq_level_gate.zig",
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        },
        .{
            // GAP-0138: handshake errors queue fatal alerts (RFC 8446 §6.2).
            .name = "gap0138_handshake_alert_emit",
            .source = "tests/security/gap0138_handshake_alert_emit.zig",
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        },
        .{
            // QUIC-INTEROP-HRR (2026-04-27): upstream diagnostics on the
            // server's CH1/CH2 path. Asserts the new `[TLS-HRR]` log lines
            // surface every silent early-return that was previously masked
            // by the QUIC layer's generic NoHandshakeKeys.
            .name = "quic_interop_hrr_diagnostics",
            .source = "tests/security/quic_interop_hrr_diagnostics.zig",
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
                .{ .name = "quic_logger", .module = logger_mod },
            },
        },
        .{
            .name = "sec074_rng_fail_closed",
            .source = "tests/security/sec074_rng_fail_closed.zig",
            .imports = &.{
                .{ .name = "entropy", .module = entropy_mod },
            },
        },
        .{
            // SEC-077: sentinel-enum regression test.
            .name = "sec077_allow_insecure_gate",
            .source = "tests/security/sec077_allow_insecure_gate.zig",
            .imports = &.{
                .{ .name = "x509", .module = x509_mod },
            },
        },
        .{
            // SEC-076: canonical OID equality regression test.
            .name = "sec076_oid_canonical_match",
            .source = "tests/security/sec076_oid_canonical_match.zig",
            .imports = &.{
                .{ .name = "asn1", .module = asn1_mod },
                .{ .name = "ocsp", .module = ocsp_mod },
            },
        },
        .{
            // SEC-075: RFC 5280 §4.2 critical-unknown-extension reject.
            .name = "sec075_unknown_critical_ext",
            .source = "tests/security/sec075_unknown_critical_ext.zig",
            .imports = &.{
                .{ .name = "x509", .module = x509_mod },
            },
        },
        .{
            .name = "sec068_tp_dup_cid",
            .source = "tests/security/sec068_tp_dup_cid.zig",
            .imports = &.{
                .{ .name = "quic_transport_params", .module = transport_params_mod },
            },
        },
        .{
            // SEC-065/085: persistent cross-connection anti-replay regression.
            .name = "sec065_persistent_anti_replay",
            .source = "tests/security/sec065_persistent_anti_replay.zig",
            .imports = &.{
                .{ .name = "zero_rtt", .module = zero_rtt_mod },
            },
        },
        .{
            // GAP-0135: KeyUpdate CPU exhaustion budget test.
            .name = "gap0135_key_update_exhaustion",
            .source = "tests/security/gap0135_key_update_exhaustion.zig",
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        },
        .{
            .name = "counting_allocator",
            .source = "src/testing/counting_allocator.zig",
            .imports = &.{},
        },
        .{
            .name = "perf_clienthello_allocs",
            .source = "tests/perf/test_clienthello_allocs.zig",
            .imports = &.{
                .{ .name = "counting_allocator", .module = counting_allocator_mod },
                .{ .name = "handshake_state", .module = handshake_state_mod },
            },
        },
        .{
            .name = "perf_validate_chain_parsed",
            .source = "tests/perf/test_validate_chain_parsed.zig",
            .imports = &.{
                .{ .name = "counting_allocator", .module = counting_allocator_mod },
                .{ .name = "x509", .module = x509_mod },
                // SEC-077: skip-guard uses the insecure-testing build flag.
                .{ .name = "build_options", .module = build_options_mod },
            },
        },
        .{
            .name = "perf_clienthello2_allocs",
            .source = "tests/perf/test_clienthello2_allocs.zig",
            .imports = &.{
                .{ .name = "counting_allocator", .module = counting_allocator_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        },
        .{
            .name = "perf_alpn_server_borrow",
            .source = "tests/perf/test_alpn_server_borrow.zig",
            .imports = &.{
                .{ .name = "counting_allocator", .module = counting_allocator_mod },
                .{ .name = "tls13", .module = tls13_mod },
            },
        },
        .{
            // PERF-249: outbound CryptoBuffer pre-sizing regression.
            .name = "perf_outbound_allocs",
            .source = "tests/perf/test_outbound_allocs.zig",
            .imports = &.{
                .{ .name = "counting_allocator", .module = counting_allocator_mod },
                .{ .name = "tls13", .module = tls13_mod },
            },
        },
    };

    // QUAL-315: optional `zig build coverage` step. Per ADR-0003, line
    // coverage is collected by running each unit-test binary under kcov.
    // The step is intentionally additive: callers without kcov on their
    // PATH still get the unmodified `zig build test` flow, and CI images
    // are expected to install kcov before invoking this target.
    const coverage_step = b.step(
        "coverage",
        "Run unit tests under kcov and write line-coverage reports to zig-out/coverage/ (requires `kcov` on PATH; see docs/adr/0003-coverage-tooling.md)",
    );

    for (tests) |test_info| {
        const unit_test = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(test_info.source),
                .target = target,
                .optimize = optimize,
                .imports = test_info.imports,
            }),
        });

        const run_test = b.addRunArtifact(unit_test);
        test_step.dependOn(&run_test.step);

        // QUAL-315: shadow the test executable under kcov so line-level
        // coverage spans the full src/ tree on every invocation. Writes
        // to `zig-out/coverage/<test_name>` per kcov's directory layout.
        const kcov_outdir = b.fmt("zig-out/coverage/{s}", .{test_info.name});
        const run_kcov = b.addSystemCommand(&.{
            "kcov",
            "--include-pattern=src/",
            "--exclude-pattern=src/build_options",
            kcov_outdir,
        });
        run_kcov.addArtifactArg(unit_test);
        coverage_step.dependOn(&run_kcov.step);
    }

    // TLS13 tests with full dependencies
    const tls13_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tls13/mod.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "sig", .module = sig_mod },
                .{ .name = "alert", .module = alert_mod },
                .{ .name = "zero_rtt", .module = zero_rtt_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
                .{ .name = "quic_logger", .module = logger_mod },
                .{ .name = "quic_transport_params", .module = transport_params_mod },
                .{ .name = "ocsp", .module = ocsp_mod },
                .{ .name = "sct", .module = sct_mod },
                .{ .name = "entropy", .module = entropy_mod },
                .{ .name = "build_options", .module = build_options_mod },
                // Observability seam: context.zig calls into the seam.
                .{ .name = "observability", .module = observability_mod },
            },
        }),
    });
    const run_tls13_test = b.addRunArtifact(tls13_test);
    test_step.dependOn(&run_tls13_test.step);

    // Lib tests
    const lib_test = b.addTest(.{
        .root_module = zig_tls_mod,
    });
    const run_lib_test = b.addRunArtifact(lib_test);
    test_step.dependOn(&run_lib_test.step);

    // FIPS seam test: proves the crypto_backend module resolves and the
    // approved API surface works in BOTH -Dfips modes.
    const fips_seam_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/fips_seam_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "crypto_backend", .module = crypto_backend_mod },
            },
        }),
    });
    const run_fips_seam_test = b.addRunArtifact(fips_seam_test);
    test_step.dependOn(&run_fips_seam_test.step);

    // ========================================================================
    // RFC 8446 Test Vectors
    // ========================================================================

    const test_vectors_step = b.step("test-vectors", "Run RFC 8446 test vector validation");

    const vectors_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/rfc8446_vectors.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "record", .module = record_mod },
            },
        }),
    });

    const run_vectors_test = b.addRunArtifact(vectors_test);
    test_vectors_step.dependOn(&run_vectors_test.step);

    // Add to main test step
    test_step.dependOn(test_vectors_step);

    // ========================================================================
    // RFC-Specific Test Suites - Organized by RFC section
    // ========================================================================

    // RFC 8446: TLS 1.3 Core Protocol Tests
    const test_rfc8446_step = b.step("test-rfc8446", "Run RFC 8446 (TLS 1.3) test suite");

    const rfc8446_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/rfc8446/mod.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "record", .module = record_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
                // GAP-0120: RFC 8446 §4.6.3 KeyUpdate tests use the
                // higher-level `tls13` module for post-handshake APIs.
                .{ .name = "tls13", .module = tls13_mod },
                // GAP-0120: RFC 8446 §6 Alert Protocol tests.
                .{ .name = "alert", .module = alert_mod },
                // GAP-0120: RFC 8446 §8 0-RTT / anti-replay tests.
                .{ .name = "zero_rtt", .module = zero_rtt_mod },
                .{ .name = "test_utils", .module = test_utils_mod },
            },
        }),
    });

    const run_rfc8446_test = b.addRunArtifact(rfc8446_test);
    test_rfc8446_step.dependOn(&run_rfc8446_test.step);

    // Add RFC 8446 tests to main test suite
    test_step.dependOn(test_rfc8446_step);

    // RFC Compliance Tests (enum/constant verification against RFC specs)
    const rfc_compliance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/rfc_compliance_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "sig", .module = sig_mod },
                .{ .name = "quic_logger", .module = logger_mod },
                .{ .name = "asn1", .module = asn1_mod },
                .{ .name = "alert", .module = alert_mod },
                .{ .name = "record", .module = record_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        }),
    });
    const run_rfc_compliance_test = b.addRunArtifact(rfc_compliance_test);
    test_step.dependOn(&run_rfc_compliance_test.step);

    // RFC 9001: QUIC-TLS Tests
    const test_rfc9001_step = b.step("test-rfc9001", "Run RFC 9001 (QUIC-TLS) test suite");

    const rfc9001_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/rfc9001/mod.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "record", .module = record_mod },
                .{ .name = "test_utils", .module = test_utils_mod },
            },
        }),
    });

    const run_rfc9001_test = b.addRunArtifact(rfc9001_test);
    test_rfc9001_step.dependOn(&run_rfc9001_test.step);

    // Add RFC 9001 tests to main test suite
    test_step.dependOn(test_rfc9001_step);

    // RFC 5280: X.509 Certificate Tests
    const test_rfc5280_step = b.step("test-rfc5280", "Run RFC 5280 (X.509) test suite");

    const rfc5280_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/rfc5280/mod.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "asn1", .module = asn1_mod },
                .{ .name = "sig", .module = sig_mod },
            },
        }),
    });

    const run_rfc5280_test = b.addRunArtifact(rfc5280_test);
    test_rfc5280_step.dependOn(&run_rfc5280_test.step);

    // Add RFC 5280 tests to main test suite
    test_step.dependOn(test_rfc5280_step);

    // ========================================================================
    // Extended Unit Tests - Comprehensive module-specific tests
    // ========================================================================

    const x509_unit_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/x509_unit_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "asn1", .module = asn1_mod },
                .{ .name = "sig", .module = sig_mod },
                .{ .name = "test_utils", .module = test_utils_mod },
                // SEC-077: tests consult the insecure-testing build flag
                // so the insecure-bypass case can skip safely.
                .{ .name = "build_options", .module = build_options_mod },
            },
        }),
    });
    const run_x509_unit_test = b.addRunArtifact(x509_unit_test);
    test_step.dependOn(&run_x509_unit_test.step);

    const sig_unit_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/sig_unit_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "sig", .module = sig_mod },
                .{ .name = "asn1", .module = asn1_mod },
                .{ .name = "test_utils", .module = test_utils_mod },
            },
        }),
    });
    const run_sig_unit_test = b.addRunArtifact(sig_unit_test);
    test_step.dependOn(&run_sig_unit_test.step);

    // OCSP unit tests
    const ocsp_unit_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/ocsp_unit_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ocsp", .module = ocsp_mod },
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "asn1", .module = asn1_mod },
            },
        }),
    });
    const run_ocsp_unit_test = b.addRunArtifact(ocsp_unit_test);
    test_step.dependOn(&run_ocsp_unit_test.step);

    // SCT unit tests
    const sct_unit_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/sct_unit_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "sct", .module = sct_mod },
            },
        }),
    });
    const run_sct_unit_test = b.addRunArtifact(sct_unit_test);
    test_step.dependOn(&run_sct_unit_test.step);

    // ========================================================================
    // TLS 1.3 Handshake Integration Tests
    // ========================================================================

    const tls13_handshake_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/tls13_handshake_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "record", .module = record_mod },
                .{ .name = "alert", .module = alert_mod },
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "sig", .module = sig_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
                .{ .name = "quic_transport_params", .module = transport_params_mod },
                // SEC-077: one handshake test uses the insecure sentinel.
                .{ .name = "build_options", .module = build_options_mod },
            },
        }),
    });
    const run_tls13_handshake_test = b.addRunArtifact(tls13_handshake_test);
    test_step.dependOn(&run_tls13_handshake_test.step);

    // TLS 1.3 Key Update Tests
    const key_update_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/key_update_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "quic_tls", .module = key_schedule_mod },
            },
        }),
    });
    const run_key_update_test = b.addRunArtifact(key_update_test);
    test_step.dependOn(&run_key_update_test.step);

    // QUAL-099: Context-level HRR Tests
    const context_hrr_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/context_hrr_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        }),
    });
    const run_context_hrr_test = b.addRunArtifact(context_hrr_test);
    test_step.dependOn(&run_context_hrr_test.step);

    // QUIC-INTEROP-HRR: Server-side HRR conformance tests.
    // RFC 8446 §4.1.4: server emits HRR when client offers a non-X25519
    // key_share but supported_groups overlaps. Regression coverage for the
    // QUIC interop break against quic-go / mvfst (docs/QUIC_INTEROP_HRR_ISSUE.md).
    const context_hrr_server_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/context_hrr_server_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        }),
    });
    const run_context_hrr_server_test = b.addRunArtifact(context_hrr_server_test);
    test_step.dependOn(&run_context_hrr_server_test.step);

    // ========================================================================
    // Conformance Tests - Interoperability with BoringSSL and OpenSSL
    // ========================================================================

    const conformance_step = b.step("test-conformance", "Run conformance tests against BoringSSL and OpenSSL (requires libssl-dev)");

    // Windows vcpkg OpenSSL support
    const vcpkg_root = b.graph.environ_map.get("VCPKG_ROOT");
    const vcpkg_include_path = if (vcpkg_root) |root|
        b.fmt("{s}/installed/x64-windows/include", .{root})
    else
        null;

    // BoringSSL conformance tests
    const boringssl_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/boringssl_conformance.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "alert", .module = alert_mod },
                .{ .name = "record", .module = record_mod },
                .{ .name = "varint", .module = varint_mod },
                .{ .name = "quic_transport_params", .module = transport_params_mod },
                .{ .name = "sct", .module = sct_mod },
                .{ .name = "ocsp", .module = ocsp_mod },
                .{ .name = "test_utils", .module = test_utils_mod },
            },
        }),
    });
    boringssl_test.root_module.linkSystemLibrary("ssl", .{});
    boringssl_test.root_module.linkSystemLibrary("crypto", .{});
    boringssl_test.root_module.link_libc = true;
    if (vcpkg_include_path) |path| {
        boringssl_test.root_module.addIncludePath(.{ .cwd_relative = path });
    }

    const run_boringssl_test = b.addRunArtifact(boringssl_test);
    conformance_step.dependOn(&run_boringssl_test.step);

    // OpenSSL conformance tests
    const openssl_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/openssl_conformance.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "alert", .module = alert_mod },
                .{ .name = "record", .module = record_mod },
                .{ .name = "varint", .module = varint_mod },
                .{ .name = "quic_transport_params", .module = transport_params_mod },
                .{ .name = "sct", .module = sct_mod },
                .{ .name = "ocsp", .module = ocsp_mod },
                .{ .name = "test_utils", .module = test_utils_mod },
            },
        }),
    });
    openssl_test.root_module.linkSystemLibrary("ssl", .{});
    openssl_test.root_module.linkSystemLibrary("crypto", .{});
    openssl_test.root_module.link_libc = true;
    if (vcpkg_include_path) |path| {
        openssl_test.root_module.addIncludePath(.{ .cwd_relative = path });
    }

    const run_openssl_test = b.addRunArtifact(openssl_test);
    conformance_step.dependOn(&run_openssl_test.step);

    // X.509 OpenSSL conformance tests
    const x509_openssl_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/x509_openssl_conformance.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "asn1", .module = asn1_mod },
                .{ .name = "sig", .module = sig_mod },
                .{ .name = "test_utils", .module = test_utils_mod },
            },
        }),
    });
    x509_openssl_test.root_module.linkSystemLibrary("ssl", .{});
    x509_openssl_test.root_module.linkSystemLibrary("crypto", .{});
    x509_openssl_test.root_module.link_libc = true;
    if (vcpkg_include_path) |path| {
        x509_openssl_test.root_module.addIncludePath(.{ .cwd_relative = path });
    }

    const run_x509_openssl_test = b.addRunArtifact(x509_openssl_test);
    conformance_step.dependOn(&run_x509_openssl_test.step);

    // OCSP OpenSSL conformance tests
    const ocsp_openssl_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/ocsp_openssl_conformance.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ocsp", .module = ocsp_mod },
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "asn1", .module = asn1_mod },
            },
        }),
    });
    ocsp_openssl_test.root_module.linkSystemLibrary("ssl", .{});
    ocsp_openssl_test.root_module.linkSystemLibrary("crypto", .{});
    ocsp_openssl_test.root_module.link_libc = true;
    if (vcpkg_include_path) |path| {
        ocsp_openssl_test.root_module.addIncludePath(.{ .cwd_relative = path });
    }

    const run_ocsp_openssl_test = b.addRunArtifact(ocsp_openssl_test);
    conformance_step.dependOn(&run_ocsp_openssl_test.step);

    // SCT OpenSSL conformance tests
    const sct_openssl_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/sct_openssl_conformance.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "sct", .module = sct_mod },
            },
        }),
    });
    sct_openssl_test.root_module.linkSystemLibrary("ssl", .{});
    sct_openssl_test.root_module.linkSystemLibrary("crypto", .{});
    sct_openssl_test.root_module.link_libc = true;
    if (vcpkg_include_path) |path| {
        sct_openssl_test.root_module.addIncludePath(.{ .cwd_relative = path });
    }

    const run_sct_openssl_test = b.addRunArtifact(sct_openssl_test);
    conformance_step.dependOn(&run_sct_openssl_test.step);

    // TLS 1.3 Handshake conformance tests
    const handshake_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/handshake_conformance.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "record", .module = record_mod },
                .{ .name = "alert", .module = alert_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        }),
    });
    handshake_conformance_test.root_module.linkSystemLibrary("ssl", .{});
    handshake_conformance_test.root_module.linkSystemLibrary("crypto", .{});
    handshake_conformance_test.root_module.link_libc = true;
    if (vcpkg_include_path) |path| {
        handshake_conformance_test.root_module.addIncludePath(.{ .cwd_relative = path });
    }

    const run_handshake_conformance_test = b.addRunArtifact(handshake_conformance_test);
    conformance_step.dependOn(&run_handshake_conformance_test.step);

    // Handshake Secret Derivation conformance tests (OpenSSL parity)
    const handshake_secrets_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/handshake_secrets.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "tls13", .module = tls13_mod },
            },
        }),
    });
    handshake_secrets_test.root_module.linkSystemLibrary("ssl", .{});
    handshake_secrets_test.root_module.linkSystemLibrary("crypto", .{});
    handshake_secrets_test.root_module.link_libc = true;
    if (vcpkg_include_path) |path| {
        handshake_secrets_test.root_module.addIncludePath(.{ .cwd_relative = path });
    }

    const run_handshake_secrets_test = b.addRunArtifact(handshake_secrets_test);
    conformance_step.dependOn(&run_handshake_secrets_test.step);

    // HelloRetryRequest conformance tests (Phase 1, Task 13)
    const hrr_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/boringssl/hello_retry_request.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        }),
    });
    const run_hrr_conformance_test = b.addRunArtifact(hrr_conformance_test);
    conformance_step.dependOn(&run_hrr_conformance_test.step);

    // Chain Validation conformance tests (Phase 1, Task 14)
    const chain_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/openssl/chain_validation.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "test_certs", .module = test_certs_mod },
            },
        }),
    });
    const run_chain_conformance_test = b.addRunArtifact(chain_conformance_test);
    conformance_step.dependOn(&run_chain_conformance_test.step);

    // Key Update conformance tests (Phase 1, Task 15)
    const key_update_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/boringssl/key_update.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "quic_tls", .module = key_schedule_mod },
            },
        }),
    });
    const run_key_update_conformance_test = b.addRunArtifact(key_update_conformance_test);
    conformance_step.dependOn(&run_key_update_conformance_test.step);

    // Security Test Suite (Phase 1, Task 16)
    const security_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/security/phase1_security.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tls13_full", .module = tls13_full_mod },
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "alert", .module = alert_mod },
            },
        }),
    });
    const run_security_test = b.addRunArtifact(security_test);
    conformance_step.dependOn(&run_security_test.step);

    // PSK Handshake conformance tests (Phase 2, Task 1)
    const psk_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/boringssl/psk_handshake.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "quic_tls", .module = key_schedule_mod },
            },
        }),
    });
    const run_psk_conformance_test = b.addRunArtifact(psk_conformance_test);
    conformance_step.dependOn(&run_psk_conformance_test.step);

    // 0-RTT conformance tests (Phase 2, Task 2)
    const zero_rtt_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/boringssl/zero_rtt.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "zero_rtt", .module = zero_rtt_mod },
            },
        }),
    });
    const run_zero_rtt_conformance_test = b.addRunArtifact(zero_rtt_conformance_test);
    conformance_step.dependOn(&run_zero_rtt_conformance_test.step);

    // Session Ticket conformance tests (Phase 2, Task 3)
    const session_ticket_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/boringssl/session_ticket.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic_tls", .module = key_schedule_mod },
            },
        }),
    });
    const run_session_ticket_conformance_test = b.addRunArtifact(session_ticket_conformance_test);
    conformance_step.dependOn(&run_session_ticket_conformance_test.step);

    // Replay Attack Prevention conformance tests (Phase 2, Task 4)
    const replay_prevention_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/boringssl/replay_prevention.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zero_rtt", .module = zero_rtt_mod },
            },
        }),
    });
    const run_replay_prevention_conformance_test = b.addRunArtifact(replay_prevention_conformance_test);
    conformance_step.dependOn(&run_replay_prevention_conformance_test.step);

    // Client Authentication conformance tests (Phase 3, Task 1)
    const client_auth_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/openssl/client_auth.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "test_certs", .module = test_certs_mod },
            },
        }),
    });
    const run_client_auth_conformance_test = b.addRunArtifact(client_auth_conformance_test);
    conformance_step.dependOn(&run_client_auth_conformance_test.step);

    // Trust Store conformance tests (Phase 3, Task 2)
    const trust_store_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/openssl/trust_store.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_trust_store_conformance_test = b.addRunArtifact(trust_store_conformance_test);
    conformance_step.dependOn(&run_trust_store_conformance_test.step);

    // Mutual TLS integration conformance tests (Phase 3, Task 3)
    const mutual_tls_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/openssl/mutual_tls.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "test_certs", .module = test_certs_mod },
            },
        }),
    });
    const run_mutual_tls_conformance_test = b.addRunArtifact(mutual_tls_conformance_test);
    conformance_step.dependOn(&run_mutual_tls_conformance_test.step);

    // mTLS OpenSSL interop conformance tests (CertificateRequest/Verify/Certificate round-trip + EVP)
    const mtls_openssl_interop_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/openssl/mtls_interop.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        }),
    });
    mtls_openssl_interop_test.root_module.linkSystemLibrary("ssl", .{});
    mtls_openssl_interop_test.root_module.linkSystemLibrary("crypto", .{});
    mtls_openssl_interop_test.root_module.link_libc = true;
    if (vcpkg_include_path) |path| {
        mtls_openssl_interop_test.root_module.addIncludePath(.{ .cwd_relative = path });
    }

    const run_mtls_openssl_interop_test = b.addRunArtifact(mtls_openssl_interop_test);
    conformance_step.dependOn(&run_mtls_openssl_interop_test.step);

    // P-256/P-384 ECDHE conformance tests (Phase 4, Task 1)
    const p256_ecdhe_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/boringssl/p256_ecdhe.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_p256_ecdhe_conformance_test = b.addRunArtifact(p256_ecdhe_conformance_test);
    conformance_step.dependOn(&run_p256_ecdhe_conformance_test.step);

    // FFDHE conformance tests (Phase 4, Task 2)
    const ffdhe_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/openssl/ffdhe.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_ffdhe_conformance_test = b.addRunArtifact(ffdhe_conformance_test);
    conformance_step.dependOn(&run_ffdhe_conformance_test.step);

    // Cross-suite interoperability conformance tests (Phase 4, Task 3)
    const cross_suite_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/boringssl/cross_suite_interop.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_cross_suite_conformance_test = b.addRunArtifact(cross_suite_conformance_test);
    conformance_step.dependOn(&run_cross_suite_conformance_test.step);

    // mTLS BoringSSL format parity tests (CertificateRequest wire encoding validation)
    const mtls_format_parity_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/boringssl/mtls_format_parity.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        }),
    });
    const run_mtls_format_parity_test = b.addRunArtifact(mtls_format_parity_test);
    conformance_step.dependOn(&run_mtls_format_parity_test.step);

    // OCSP validation conformance tests (Phase 5, Task 1)
    const ocsp_validation_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/openssl/ocsp_validation.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "ocsp", .module = ocsp_mod },
                .{ .name = "test_certs", .module = test_certs_mod },
            },
        }),
    });
    const run_ocsp_validation_conformance_test = b.addRunArtifact(ocsp_validation_conformance_test);
    conformance_step.dependOn(&run_ocsp_validation_conformance_test.step);

    // CRL validation conformance tests (Phase 5, Task 2)
    const crl_validation_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/openssl/crl_validation.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "crl", .module = crl_mod },
                .{ .name = "test_certs", .module = test_certs_mod },
            },
        }),
    });
    const run_crl_validation_conformance_test = b.addRunArtifact(crl_validation_conformance_test);
    conformance_step.dependOn(&run_crl_validation_conformance_test.step);

    // AIA validation conformance tests (Phase 5, Task 3)
    const aia_validation_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/openssl/aia_validation.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "test_certs", .module = test_certs_mod },
            },
        }),
    });
    const run_aia_validation_conformance_test = b.addRunArtifact(aia_validation_conformance_test);
    conformance_step.dependOn(&run_aia_validation_conformance_test.step);

    // Certificate policy validation conformance tests (Phase 5, Task 4)
    const policy_validation_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/openssl/policy_validation.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "test_certs", .module = test_certs_mod },
            },
        }),
    });
    const run_policy_validation_conformance_test = b.addRunArtifact(policy_validation_conformance_test);
    conformance_step.dependOn(&run_policy_validation_conformance_test.step);

    // Name constraints enforcement conformance tests (Phase 5, Task 5)
    const name_constraints_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/openssl/name_constraints.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "test_certs", .module = test_certs_mod },
            },
        }),
    });
    const run_name_constraints_conformance_test = b.addRunArtifact(name_constraints_conformance_test);
    conformance_step.dependOn(&run_name_constraints_conformance_test.step);

    // TLS 1.3 extensions conformance tests (Phase 6, Task 1)
    const extensions_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/rfc8446/extensions.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_extensions_conformance_test = b.addRunArtifact(extensions_conformance_test);
    conformance_step.dependOn(&run_extensions_conformance_test.step);

    // Performance benchmarking conformance tests (Phase 6, Task 2)
    const performance_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/boringssl/performance.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_performance_conformance_test = b.addRunArtifact(performance_conformance_test);
    conformance_step.dependOn(&run_performance_conformance_test.step);

    // Memory usage optimization conformance tests (Phase 6, Task 3)
    const memory_optimization_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/boringssl/memory_optimization.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_memory_optimization_conformance_test = b.addRunArtifact(memory_optimization_conformance_test);
    conformance_step.dependOn(&run_memory_optimization_conformance_test.step);

    // Post-quantum cryptography readiness conformance tests (Phase 6, Task 4)
    const post_quantum_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/boringssl/post_quantum_readiness.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_post_quantum_conformance_test = b.addRunArtifact(post_quantum_conformance_test);
    conformance_step.dependOn(&run_post_quantum_conformance_test.step);

    // Comprehensive fuzzing conformance tests (Phase 6, Task 5)
    const fuzzing_conformance_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/conformance/boringssl/fuzzing.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_fuzzing_conformance_test = b.addRunArtifact(fuzzing_conformance_test);
    conformance_step.dependOn(&run_fuzzing_conformance_test.step);

    // Note: conformance tests require OpenSSL/BoringSSL development libraries
    // They are not included in the default test step

    // ========================================================================
    // GAP-0109: RSA-PSS Differential Fuzz Harness
    // ========================================================================
    //
    // Drives `sig.rsa_pss_verify_sha256` (SHA-256 path) and
    // `sig.rsaPssVerifyGeneric` (generic path) over the seed corpus.
    // PERF-237b: was previously a differential harness against
    // `parallel.verifyRsaPssWithHash`; that helper was removed in 0.2.0
    // along with src/parallel.zig.
    //
    // Run seeds only:   zig build fuzz-rsa-pss
    // Run fuzz:         zig build fuzz-rsa-pss --fuzz

    {
        const fuzz_rsa_pss_step = b.step("fuzz-rsa-pss", "Run RSA-PSS verify harness (GAP-0109)");
        const fuzz_rsa_pss_test = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("tests/fuzz/rsa_pss_verify.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "sig", .module = sig_mod },
                },
            }),
        });
        const run_fuzz_rsa_pss_test = b.addRunArtifact(fuzz_rsa_pss_test);
        fuzz_rsa_pss_step.dependOn(&run_fuzz_rsa_pss_test.step);
        // Also exercise the seed corpus as part of the default `test` step
        // so regressions are caught by routine CI, not only by the explicit
        // fuzz job.
        test_step.dependOn(&run_fuzz_rsa_pss_test.step);
    }

    // ========================================================================
    // QUAL-339: ClientHello Error-Trace Oracle Capture
    // ========================================================================
    //
    // Standalone executable that drives `parseClientHello` across the seed
    // corpus + deterministic single-bit-flip mutations and writes a binary
    // error-trace file (tests/fuzz/corpus/client_hello_golden.bin). The file
    // serves as an empirical regression oracle for the table-driven
    // ExtHandler refactor — any divergence in post-refactor output indicates
    // a security-invariant regression (SEC-054 errdefer / SEC-057 enum
    // guard / CWE-345 psk_seen ordering).
    //
    // Run: zig build capture-client-hello-oracle

    const trace_capture = b.addExecutable(.{
        .name = "client_hello_trace_capture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/fuzz/client_hello_trace_capture.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "client_hello", .module = client_hello_mod },
            },
        }),
    });

    const capture_step = b.step(
        "capture-client-hello-oracle",
        "Capture pre/post-refactor ClientHello parse error traces (QUAL-339)",
    );
    const run_capture = b.addRunArtifact(trace_capture);
    run_capture.addArgs(&.{
        "tests/fuzz/corpus/client_hello",
        "tests/fuzz/corpus/client_hello_golden.bin",
    });
    capture_step.dependOn(&run_capture.step);

    // ========================================================================
    // QUAL-317: context.zig Decomposition Error-Trace Oracle Capture
    // ========================================================================
    //
    // Standalone executable that drives `Context.processCrypto(.Initial, ...)`
    // across handshake byte fixtures aggregated from the existing
    // client_hello/, quic_tp/, and rsa_pss/ corpora (collected via
    // tests/fuzz/corpus/context_decomp/collect_fixtures.sh) and writes a
    // binary error-trace file (tests/fuzz/corpus/context_decomp_golden.bin).
    // The file serves as an empirical regression oracle for the 8-module
    // Context decomposition plan -- every extraction commit must re-run
    // `zig build capture-context-decomp-oracle` and cmp the output against
    // this committed golden. Any divergence means the refactor changed
    // observable Context behavior, which should block the offending commit.
    //
    // Pattern mirrors Cycle 4 QUAL-339's client_hello_trace_capture above.
    //
    // Run: zig build capture-context-decomp-oracle

    const ctx_decomp_trace_capture = b.addExecutable(.{
        .name = "context_decomp_trace_capture",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/fuzz/context_decomp_trace_capture.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "tls13", .module = tls13_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        }),
    });

    const capture_ctx_decomp_step = b.step(
        "capture-context-decomp-oracle",
        "Capture pre/post-refactor Context.processCrypto error traces (QUAL-317)",
    );
    const run_capture_ctx_decomp = b.addRunArtifact(ctx_decomp_trace_capture);
    run_capture_ctx_decomp.addArgs(&.{
        "tests/fuzz/corpus/context_decomp",
        "tests/fuzz/corpus/context_decomp_golden.bin",
    });
    capture_ctx_decomp_step.dependOn(&run_capture_ctx_decomp.step);

    // ========================================================================
    // Benchmark Suite (PERF-011)
    // ========================================================================
    //
    // Run with: zig build bench -Doptimize=ReleaseFast
    // Measures key derivation, transcript hashing, and AEAD throughput.

    const bench_step = b.step("bench", "Run performance benchmarks");

    const bench_exe = b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/bench.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic_tls", .module = key_schedule_mod },
                .{ .name = "record", .module = record_mod },
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "sig", .module = sig_mod },
                .{ .name = "tls13_full", .module = tls13_full_mod },
            },
        }),
    });

    const run_bench = b.addRunArtifact(bench_exe);
    if (b.args) |user_args| run_bench.addArgs(user_args);
    bench_step.dependOn(&run_bench.step);

    // PERF-258: dedicated emit-json step. Forwards args after `--` so callers
    // can override the output path:
    //   zig build bench-emit-json -Doptimize=ReleaseFast -- tests/perf/baseline.json
    const bench_emit_json_step = b.step(
        "bench-emit-json",
        "Run benchmarks and emit results as JSON (default: tests/perf/baseline.json)",
    );
    const run_bench_emit = b.addRunArtifact(bench_exe);
    if (b.args) |user_args| {
        run_bench_emit.addArg("--emit-json");
        run_bench_emit.addArgs(user_args);
    } else {
        run_bench_emit.addArgs(&.{ "--emit-json", "tests/perf/baseline.json" });
    }
    bench_emit_json_step.dependOn(&run_bench_emit.step);

    // PERF-258: regression-detect step. Loads the committed baseline JSON
    // and exits non-zero on any sample exceeding the ±10% tolerance.
    const bench_check_baseline_step = b.step(
        "bench-check-baseline",
        "Run benchmarks and compare against tests/perf/baseline.json (10% tolerance)",
    );
    const run_bench_check = b.addRunArtifact(bench_exe);
    if (b.args) |user_args| {
        run_bench_check.addArg("--check-baseline");
        run_bench_check.addArgs(user_args);
    } else {
        run_bench_check.addArgs(&.{ "--check-baseline", "tests/perf/baseline.json" });
    }
    bench_check_baseline_step.dependOn(&run_bench_check.step);

    // ========================================================================
    // Allocation-Count Baseline Harness (PERF-024 / PERF-201)
    // ========================================================================
    //
    // Run with: zig build bench-allocs -Doptimize=ReleaseFast
    // Prints the number of allocations performed by ClientHelloInfo.parse
    // against a CountingAllocator. Used to establish the pre-PERF-201
    // baseline (~14 allocs) and confirm the post-fix target (≤3 allocs).

    const bench_allocs_step = b.step("bench-allocs", "Allocation-count baseline for hot paths");
    const bench_allocs_exe = b.addExecutable(.{
        .name = "bench-allocs",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/bench_allocs.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "counting_allocator", .module = counting_allocator_mod },
                .{ .name = "handshake_state", .module = handshake_state_mod },
            },
        }),
    });
    const run_bench_allocs = b.addRunArtifact(bench_allocs_exe);
    bench_allocs_step.dependOn(&run_bench_allocs.step);

    // ========================================================================
    // PERF-209 Reproducer: ThreadPool allocator diagnostic
    // ========================================================================
    //
    // Submits 10_000 small SHA-256 tasks into a freshly-initialised
    // ThreadPool per allocator variant (page_allocator, smp_allocator,
    // c_allocator) and prints wall-time / getrusage majflt / minflt /
    // maxrss deltas. Used to decide whether PERF-209 (suspected
    // page_allocator friction) is closed Won't-Do or promoted to a real
    // allocator-swap follow-up.
    //
    // Run with: zig build bench-threadpool -Doptimize=ReleaseFast

    if (tp_mod) |tm| {
        const bench_tp_step = b.step("bench-threadpool", "ThreadPool allocator reproducer (PERF-209)");
        const bench_tp_exe = b.addExecutable(.{
            .name = "bench-threadpool",
            .root_module = b.createModule(.{
                .root_source_file = b.path("tests/perf/bench_threadpool_alloc.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "thread_pool", .module = tm },
                },
            }),
        });
        // c_allocator needs libc.
        bench_tp_exe.root_module.link_libc = true;
        const run_bench_tp = b.addRunArtifact(bench_tp_exe);
        bench_tp_step.dependOn(&run_bench_tp.step);
    }

    // ========================================================================
    // Observability (otel) -- gated dep + disabled-mode no-op test
    // ========================================================================
    //
    // Gated otel dependency. The `lazy = true` entry in build.zig.zon
    // means Zig only fetches the package when this branch executes;
    // with the flag off the dependency is never resolved and the
    // produced artifacts contain zero otel symbols (verified by
    // otel/scripts/verify-consumer-noop.sh).
    if (with_otel) {
        const otel_dep = b.lazyDependency("otel", .{
            .target = target,
            .optimize = optimize,
        }) orelse return;
        const otel_module = otel_dep.module("otel");
        // Wire `otel` onto the shared observability module so every
        // consumer sees the same otel namespace.
        observability_mod.addImport("otel", otel_module);

        // Bootstrap helper. Only registered when `-Dwith_otel=true` so
        // the disabled build never compiles otel-touching code. Gated
        // from lib.zig via
        // `if (observability.enabled) @import("observability_init")`.
        const observability_init_mod = b.addModule("observability_init", .{
            .root_source_file = b.path("src/observability_init.zig"),
            .target = target,
            .imports = &.{
                .{ .name = "otel", .module = otel_module },
                .{ .name = "observability", .module = observability_mod },
            },
        });
        zig_tls_mod.addImport("observability_init", observability_init_mod);
    }

    // Disabled-mode no-op tests. Verifies `build_options.with_otel ==
    // false` and the seam's `enabled` flag tracks it; drives every
    // helper to confirm the no-op fallback compiles and never touches
    // otel symbols.
    const observability_disabled_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/observability_disabled_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ztls", .module = zig_tls_mod },
                .{ .name = "build_options", .module = build_options_mod },
            },
        }),
    });
    const run_observability_disabled_tests = b.addRunArtifact(observability_disabled_tests);
    test_step.dependOn(&run_observability_disabled_tests.step);

    // Enabled-mode smoke test. Skips under -Dwith_otel=false; under
    // -Dwith_otel=true it installs an in-memory recorder, drives one
    // `startHandshakeSpan(.client)` -> `endHandshakeSpan` round-trip,
    // and asserts exactly one span with name "TLS handshake" and the
    // expected `tls.role`, `tls.protocol.version`, `tls.cipher_suite`
    // attributes.
    const observability_enabled_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/observability_enabled_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ztls", .module = zig_tls_mod },
                .{ .name = "build_options", .module = build_options_mod },
            },
        }),
    });
    if (with_otel) {
        // Re-resolve the otel module under the same `with_otel` guard
        // so the test root can call into the otel SDK directly. The
        // module identity matches the one wired onto observability_mod
        // earlier in this branch.
        const otel_dep = b.lazyDependency("otel", .{
            .target = target,
            .optimize = optimize,
        }) orelse return;
        observability_enabled_tests.root_module.addImport("otel", otel_dep.module("otel"));
    }
    const run_observability_enabled_tests = b.addRunArtifact(observability_enabled_tests);
    test_step.dependOn(&run_observability_enabled_tests.step);
}
