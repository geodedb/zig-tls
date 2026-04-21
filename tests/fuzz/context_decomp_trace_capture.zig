// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// QUAL-317: Pre-refactor error-trace oracle for context.zig decomposition.
//
// Standalone executable that drives `Context.processCrypto(.Initial, input)`
// across a seed corpus gathered from tests/fuzz/corpus/{client_hello,
// quic_tp,rsa_pss}/ and writes a binary error-trace file. The post-refactor
// build must produce a byte-identical file across the same inputs; any
// divergence indicates that the 8-module decomposition altered observable
// Context behavior, which should block the offending extraction commit.
//
// Strategy (documented per the QUAL-317 Task 1 plan):
//
// We construct a minimal Client-role Context with `allow_insecure = true`
// (avoids SEC-029 MissingServerName precondition) and a zero-length QUIC
// transport_parameters blob (satisfies RFC 9001 §8.2 presence check but
// carries no semantic payload). The capture harness does NOT start a
// real handshake -- it simply feeds each fixture into `processCrypto` at
// the Initial level as if the peer had sent CRYPTO frame payload. The
// parser reaches `parseHandshakeOne` followed by `handleHandshakeMessage`
// and either returns an error or (for well-formed inputs) transitions
// state. We record the resulting error tag, not the wire output.
//
// A Client-role context feeding arbitrary bytes at Initial level exercises:
//   * length-prefix / truncation handling in parseHandshakeOne
//   * handshake-type dispatch in handleHandshakeMessage
//   * UnexpectedMessage guards (most fixtures will hit this)
//   * allocator pressure on malformed length fields
//   * CRYPTO buffer overflow guard (SEC-018, 64KiB cap)
//
// This is intentionally a shallow probe: the goal is DETERMINISM so any
// refactor that changes the error-tag map reveals itself in a diff.
//
// Output record format (repeated, one per input):
//   u16 input_len (little-endian)
//   input bytes  (variable, input_len bytes)
//   u8 outcome_tag
//
// Outcome tag table (stable numeric values; never renumber existing entries):
//   0   = ok
//   1   = unexpected_message
//   2   = unsupported_version
//   3   = missing_key_share
//   4   = unsupported_key_share_group
//   5   = no_cipher_suite
//   6   = missing_transport_parameters
//   7   = alpn_negotiation_failed
//   8   = no_signature_scheme
//   9   = decrypt_error
//  10   = crypto_error
//  11   = internal_error
//  12   = out_of_memory
//  13   = duplicate_client_hello
//  14   = psk_related               (any PSK-family error)
//  15   = finished_verify_failed
//  16   = downgrade_attempt
//  17   = certificate_related      (any certificate-family error)
// 255   = other
//
// Usage: context_decomp_trace_capture <corpus_dir> <out_file>
//
// Zig 0.16 note: mirrors tests/fuzz/client_hello_trace_capture.zig's use of
// `std.process.Init` and `std.Io.Dir` because `std.testing.fuzz` is still
// broken upstream on 0.16.

const std = @import("std");
const tls13 = @import("tls13");
const tls13_full = @import("tls13_full");

const ErrorTag = enum(u8) {
    ok = 0,
    unexpected_message = 1,
    unsupported_version = 2,
    missing_key_share = 3,
    unsupported_key_share_group = 4,
    no_cipher_suite = 5,
    missing_transport_parameters = 6,
    alpn_negotiation_failed = 7,
    no_signature_scheme = 8,
    decrypt_error = 9,
    crypto_error = 10,
    internal_error = 11,
    out_of_memory = 12,
    duplicate_client_hello = 13,
    psk_related = 14,
    finished_verify_failed = 15,
    downgrade_attempt = 16,
    certificate_related = 17,
    other = 255,
};

fn tagFor(err: anyerror) ErrorTag {
    return switch (err) {
        error.UnexpectedMessage => .unexpected_message,
        error.UnsupportedVersion => .unsupported_version,
        error.MissingKeyShare => .missing_key_share,
        error.UnsupportedKeyShareGroup => .unsupported_key_share_group,
        error.NoCipherSuite => .no_cipher_suite,
        error.MissingTransportParameters => .missing_transport_parameters,
        error.AlpnNegotiationFailed => .alpn_negotiation_failed,
        error.NoSignatureScheme, error.UnsupportedSignatureAlgorithm => .no_signature_scheme,
        error.DecryptError => .decrypt_error,
        error.CryptoError => .crypto_error,
        error.InternalError => .internal_error,
        error.OutOfMemory => .out_of_memory,
        error.DuplicateClientHello => .duplicate_client_hello,
        error.MissingPskKeyExchangeModes,
        error.PskDheKeModeRequired,
        error.MissingResumptionTicket,
        error.UnexpectedPskExtension,
        error.PskIndexOutOfRange,
        => .psk_related,
        error.FinishedVerifyFailed => .finished_verify_failed,
        error.DowngradeAttempt => .downgrade_attempt,
        error.EmptyCertificateChain,
        error.MissingCertificate,
        error.CertificateValidationFailed,
        error.MissingOcspResponse,
        error.OcspValidationFailed,
        error.MissingSctList,
        error.SctParsingFailed,
        error.EmptySctList,
        error.SctCallbackRejected,
        error.InvalidSignature,
        => .certificate_related,
        else => .other,
    };
}

fn captureOne(buf: *std.ArrayList(u8), gpa: std.mem.Allocator, input: []const u8) !void {
    // u16 length (little-endian)
    const len: u16 = @intCast(input.len);
    try buf.append(gpa, @intCast(len & 0xff));
    try buf.append(gpa, @intCast((len >> 8) & 0xff));
    // raw input bytes
    try buf.appendSlice(gpa, input);

    // Bounded-cost allocator for the Context. We use a page_allocator-backed
    // arena so that Context internal allocations succeed but we can reclaim
    // the whole arena at once without chasing individual frees. SEC-018
    // processCrypto already caps CRYPTO buffer growth at 64 KiB.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Client role + insecure sentinel + zero-length transport_parameters gives
    // a Context that passes `init()` without needing a real cert/key.
    // SEC-077: sentinel value only; this harness never reaches cert validation,
    // so the -Dtls-insecure-testing build gate never trips. If a future
    // change drives processCrypto to Certificate handling, add a
    // build_options.tls_insecure_testing guard at harness entry.
    const tp_bytes: []const u8 = &[_]u8{};
    const config = tls13.Config{
        .allocator = alloc,
        .role = .Client,
        .supported_cipher_suites = &.{tls13_full.CipherSuite.TLS_AES_128_GCM_SHA256},
        .supported_groups = &.{tls13_full.NamedGroup.x25519},
        .supported_signature_schemes = &.{tls13_full.SignatureScheme.ed25519},
        .quic_transport_parameters = tp_bytes,
        .allow_insecure = .testing_only_i_know_what_i_am_doing,
    };

    var ctx = tls13.Context.init(config, .{}) catch |e| {
        try buf.append(gpa, @intFromEnum(tagFor(e)));
        return;
    };
    defer ctx.deinit();

    const outcome: ErrorTag = if (ctx.processCrypto(.Initial, input)) |_| .ok else |e| tagFor(e);
    try buf.append(gpa, @intFromEnum(outcome));
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    // Collect argv into a plain []const [:0]const u8 so we can index positionally.
    var args_list: std.ArrayList([:0]const u8) = .empty;
    defer args_list.deinit(gpa);
    var it = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer it.deinit();
    while (it.next()) |a| try args_list.append(gpa, a);

    if (args_list.items.len < 3) {
        std.debug.print(
            "usage: {s} <corpus_dir> <out_file>\n",
            .{if (args_list.items.len > 0) args_list.items[0] else "context_decomp_trace_capture"},
        );
        return error.BadUsage;
    }

    const corpus_path = args_list.items[1];
    const out_path = args_list.items[2];

    // Buffer entire capture output in memory, then write once via
    // Dir.writeFile. Keeps the harness stream-free and avoids Zig 0.16's
    // Io.File.Writer scaffolding.
    var out_buf: std.ArrayList(u8) = .empty;
    defer out_buf.deinit(gpa);

    var corpus = try std.Io.Dir.cwd().openDir(io, corpus_path, .{ .iterate = true });
    defer corpus.close(io);

    // Collect entry names first so iteration order is stable (sorted) across
    // different filesystems and runs. Dir.iterate() order is FS-defined.
    var names: std.ArrayList([]u8) = .empty;
    defer {
        for (names.items) |n| gpa.free(n);
        names.deinit(gpa);
    }

    var dir_it = corpus.iterate();
    while (try dir_it.next(io)) |entry| {
        if (entry.kind != .file) continue;
        // Ignore non-.bin files (e.g. README.md, collect_fixtures.sh) so the
        // oracle only reflects parser behavior on binary seeds.
        if (!std.mem.endsWith(u8, entry.name, ".bin")) continue;
        try names.append(gpa, try gpa.dupe(u8, entry.name));
    }

    std.mem.sort([]u8, names.items, {}, struct {
        fn lessThan(_: void, a: []u8, b: []u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);

    for (names.items) |name| {
        const input = try corpus.readFileAlloc(io, name, gpa, .limited(64 * 1024));
        defer gpa.free(input);

        try captureOne(&out_buf, gpa, input);
    }

    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = out_path,
        .data = out_buf.items,
    });
}
