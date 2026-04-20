// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
//
// QUAL-339: ClientHello parse error-trace oracle capture.
//
// Standalone executable that drives parseClientHello across a seed corpus plus
// deterministic single-bit-flip mutations and writes a binary error-trace file.
// The post-refactor build must produce a byte-identical file across the same
// inputs; any divergence indicates a security-invariant regression (SEC-054
// errdefer / SEC-057 enum guard / CWE-345 psk_seen ordering).
//
// Output record format (repeated, one per input):
//   u16 input_len (little-endian)
//   input bytes  (variable, input_len bytes)
//   u8 outcome_tag
//
// Outcome tag table (stable numeric values; never renumber existing entries):
//   0   = ok
//   1   = end_of_stream          (unused by current parser, reserved)
//   2   = invalid_extension_length (unused; reserved)
//   3   = unknown_extension      (unused; reserved)
//   4   = psk_not_last_extension (CWE-345)
//   5   = unsupported_signature_alg (unused; reserved)
//   6   = truncated_extension    (unused; reserved)
//   7   = duplicate_pre_shared_key (unused; reserved)
//   8   = out_of_memory
//   9   = too_short              (current parser's length-guard error)
//   255 = other
//
// Usage: client_hello_trace_capture <corpus_dir> <out_file>
//
// Zig 0.16 note: `std.testing.fuzz` is broken upstream (stdlib
// `test_runner.zig:566` compile error); this harness is a plain executable so
// it sidesteps that bug. Mutation is deterministic bit-flip enumeration.

const std = @import("std");
const ch = @import("client_hello");

const ErrorTag = enum(u8) {
    ok = 0,
    end_of_stream = 1,
    invalid_extension_length = 2,
    unknown_extension = 3,
    psk_not_last_extension = 4,
    unsupported_signature_alg = 5,
    truncated_extension = 6,
    duplicate_pre_shared_key = 7,
    out_of_memory = 8,
    too_short = 9,
    other = 255,
};

fn tagFor(err: anyerror) ErrorTag {
    return switch (err) {
        error.PskNotLastExtension => .psk_not_last_extension,
        error.OutOfMemory => .out_of_memory,
        error.TooShort => .too_short,
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

    // Drive parseClientHello. We use a 64 KiB fixed-buffer allocator so that
    // allocation pressure is deterministic and repeatable.
    var scratch: [64 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const alloc = fba.allocator();

    const parsed = ch.parseClientHello(alloc, input);
    const tag: ErrorTag = if (parsed) |_| .ok else |e| tagFor(e);
    try buf.append(gpa, @intFromEnum(tag));
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
            .{if (args_list.items.len > 0) args_list.items[0] else "client_hello_trace_capture"},
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
        // Ignore non-.bin files (e.g. README.md) so the oracle only reflects
        // parser behavior on binary seeds.
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

        // Capture the original input.
        try captureOne(&out_buf, gpa, input);

        // Deterministic single-bit-flip mutations at up to the first 128 bit
        // positions. This is bounded so the oracle stays compact and the
        // executable terminates quickly.
        const max_flips = @min(input.len * 8, 128);
        var idx: usize = 0;
        while (idx < max_flips) : (idx += 1) {
            const byte_idx = idx / 8;
            const bit_idx: u3 = @intCast(idx % 8);
            const mutated = try gpa.dupe(u8, input);
            defer gpa.free(mutated);
            mutated[byte_idx] ^= (@as(u8, 1) << bit_idx);
            try captureOne(&out_buf, gpa, mutated);
        }
    }

    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = out_path,
        .data = out_buf.items,
    });
}
