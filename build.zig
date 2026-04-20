// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

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

    // RFC 8446 §5: Record Protocol
    // TLSPlaintext/TLSCiphertext, AEAD operations
    const record_mod = b.addModule("record", .{
        .root_source_file = b.path("src/record.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "quic_tls", .module = key_schedule_mod },
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
        .root_source_file = b.path("src/tls13.zig"),
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
        },
    });

    // ========================================================================
    // Parallel Module - thread-pool-based parallelism
    // ========================================================================

    const parallel_mod: ?*std.Build.Module = if (enable_tp) blk: {
        break :blk b.addModule("parallel", .{
            .root_source_file = b.path("src/parallel.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "x509", .module = x509_mod },
                .{ .name = "sig", .module = sig_mod },
                .{ .name = "record", .module = record_mod },
                .{ .name = "quic_tls", .module = key_schedule_mod },
            },
        });
    } else null;
    if (parallel_mod) |pm| {
        if (tp_mod) |tm| pm.addImport("thread_pool", tm);
    }

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
        },
    });
    if (parallel_mod) |pm| zig_tls_mod.addImport("parallel", pm);

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
        .{ .name = "key_schedule", .source = "src/key_schedule.zig", .imports = &.{} },
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
            },
        },
        .{
            .name = "record",
            .source = "src/record.zig",
            .imports = &.{
                .{ .name = "quic_tls", .module = key_schedule_mod },
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
            .name = "sec066_clienthello_dup_ext",
            .source = "tests/security/sec066_clienthello_dup_ext.zig",
            .imports = &.{
                .{ .name = "tls13_full", .module = tls13_full_mod },
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
    };

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
    }

    // TLS13 tests with full dependencies
    const tls13_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tls13.zig"),
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
    // Drives both `sig.rsa_pss_verify_sha256` and
    // `parallel.verifyRsaPssWithHash` with identical inputs and asserts
    // byte-equivalent verdicts. Seed corpus lives under
    // tests/fuzz/corpus/rsa_pss/ and is consumed via @embedFile.
    //
    // Run seeds only:   zig build fuzz-rsa-pss
    // Run fuzz:         zig build fuzz-rsa-pss --fuzz
    //
    // Only registered when the `parallel` module is built (thread-pool on).

    if (parallel_mod) |pm| {
        const fuzz_rsa_pss_step = b.step("fuzz-rsa-pss", "Run RSA-PSS differential fuzz harness (GAP-0109)");
        const fuzz_rsa_pss_test = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("tests/fuzz/rsa_pss_verify.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "sig", .module = sig_mod },
                    .{ .name = "parallel", .module = pm },
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
    bench_step.dependOn(&run_bench.step);

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
}
