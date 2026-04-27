// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! PERF-209 reproducer: diagnostic bench for the page_allocator-backed
//! ThreadPool.
//!
//! Question: does swapping the ThreadPool's init allocator from
//! `std.heap.page_allocator` to `std.heap.smp_allocator` or
//! `std.heap.c_allocator` meaningfully change wall time, page-fault
//! counts, or peak RSS under a 10_000-job parallel workload?
//!
//! Workload: submit N tasks into a freshly-initialised ThreadPool per
//! allocator variant. Each task runs a small verify-like body
//! (SHA-256 of a fixed 256-byte buffer) without allocating from the
//! pool allocator after init. This isolates the ThreadPool's own
//! internal bookkeeping allocations.
//!
//! Metrics (all deltas over the submit+wait window):
//! - wall time via CLOCK_MONOTONIC (ns)
//! - getrusage(RUSAGE_SELF) majflt / minflt
//! - ru_maxrss delta (KB on Linux)
//!
//! Build: `zig build bench-threadpool -Doptimize=ReleaseFast`
//!
//! Decision gate (PERF-209):
//! - <5% wall delta across allocators and <100 extra page faults per
//!   1000 jobs => close PERF-209 as Won't-Do.
//! - >20% wall delta OR >100 extra faults per 1000 jobs => leave open
//!   and file an allocator-swap follow-up.

const std = @import("std");
const tp = @import("thread_pool");

const Sha256 = std.crypto.hash.sha2.Sha256;

const N_JOBS: usize = 10_000;
const PAYLOAD_BYTES: usize = 256;

const TaskCtx = struct {
    payload: *const [PAYLOAD_BYTES]u8,
    digest: *[Sha256.digest_length]u8,
};

fn workTask(ctx_ptr: *anyopaque, _: *tp.TaskContext) void {
    const ctx: *TaskCtx = @ptrCast(@alignCast(ctx_ptr));
    // Verify-like body: SHA-256 over 256 bytes. Matches the
    // order-of-magnitude work of a parallel signature verify without
    // pulling in any crypto key-parse allocation.
    Sha256.hash(ctx.payload, ctx.digest, .{});
}

fn nowMonotonicNs() ?u64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.system.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts) != 0) return null;
    const sec_ns = @as(u64, @intCast(ts.sec)) * std.time.ns_per_s;
    return sec_ns + @as(u64, @intCast(ts.nsec));
}

const RusageSample = struct {
    majflt: i64,
    minflt: i64,
    maxrss_kb: i64,
};

fn readRusage() RusageSample {
    const usage = std.posix.getrusage(std.posix.rusage.SELF);
    return .{
        .majflt = @intCast(usage.majflt),
        .minflt = @intCast(usage.minflt),
        .maxrss_kb = @intCast(usage.maxrss),
    };
}

const Result = struct {
    label: []const u8,
    wall_ns: u64,
    d_majflt: i64,
    d_minflt: i64,
    d_maxrss_kb: i64,
};

fn runVariant(label: []const u8, allocator: std.mem.Allocator, payload: *const [PAYLOAD_BYTES]u8, digests: []u8) !Result {
    // Fresh pool per run so the init-time bookkeeping shows up in the
    // measurement window.
    var pool = try tp.ThreadPool.init(allocator, .{});
    defer pool.deinit();

    // Stage all task contexts + batch entries. Allocated up front from the
    // same allocator used by the pool; each task's workTask body performs
    // no further allocation.
    var contexts = try allocator.alloc(TaskCtx, N_JOBS);
    defer allocator.free(contexts);
    var batch = try allocator.alloc(tp.BatchTask, N_JOBS);
    defer allocator.free(batch);

    for (0..N_JOBS) |i| {
        contexts[i] = .{
            .payload = payload,
            .digest = @ptrCast(digests[i * Sha256.digest_length ..][0..Sha256.digest_length]),
        };
        batch[i] = .{ .task_fn = &workTask, .ctx = @ptrCast(&contexts[i]) };
    }

    const ru0 = readRusage();
    const t0 = nowMonotonicNs() orelse return error.ClockReadFailed;

    var wg = pool.waitGroup();
    _ = try pool.submitBatch(batch, .{ .wait_group = &wg });
    wg.wait();

    const t1 = nowMonotonicNs() orelse return error.ClockReadFailed;
    const ru1 = readRusage();

    return .{
        .label = label,
        .wall_ns = t1 - t0,
        .d_majflt = ru1.majflt - ru0.majflt,
        .d_minflt = ru1.minflt - ru0.minflt,
        .d_maxrss_kb = ru1.maxrss_kb - ru0.maxrss_kb,
    };
}

pub fn main() !void {
    // Fixed payload; identical across variants so the workload difference
    // is zero and any delta is attributable to the ThreadPool's allocator.
    var payload: [PAYLOAD_BYTES]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @intCast(i & 0xff);

    // Digest output buffer: 10_000 * 32 = 320 KB. Allocated once from the
    // test's own GPA so it doesn't pollute the per-variant rusage delta.
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const digests = try gpa.allocator().alloc(u8, N_JOBS * Sha256.digest_length);
    defer gpa.allocator().free(digests);

    std.debug.print("# PERF-209 ThreadPool allocator reproducer\n", .{});
    std.debug.print("# N_JOBS={d} payload={d}B\n", .{ N_JOBS, PAYLOAD_BYTES });
    std.debug.print("# {s:<16} {s:>14} {s:>10} {s:>10} {s:>14}\n", .{ "allocator", "wall_ns", "d_majflt", "d_minflt", "d_maxrss_KB" });

    // page_allocator — kept as the historical baseline. PERF-237b
    // removed src/parallel.zig in 0.2.0; this bench remains a useful
    // standalone diagnostic of the upstream `thread_pool` package.
    {
        const r = try runVariant("page_allocator", std.heap.page_allocator, &payload, digests);
        std.debug.print("  {s:<16} {d:>14} {d:>10} {d:>10} {d:>14}\n", .{ r.label, r.wall_ns, r.d_majflt, r.d_minflt, r.d_maxrss_kb });
    }

    // smp_allocator — general-purpose thread-shard allocator designed for
    // concurrent workloads. Kept across Zig 0.16.
    {
        const r = try runVariant("smp_allocator", std.heap.smp_allocator, &payload, digests);
        std.debug.print("  {s:<16} {d:>14} {d:>10} {d:>10} {d:>14}\n", .{ r.label, r.wall_ns, r.d_majflt, r.d_minflt, r.d_maxrss_kb });
    }

    // c_allocator — malloc/free via libc. Build wires libc in for this bench.
    {
        const r = try runVariant("c_allocator", std.heap.c_allocator, &payload, digests);
        std.debug.print("  {s:<16} {d:>14} {d:>10} {d:>10} {d:>14}\n", .{ r.label, r.wall_ns, r.d_majflt, r.d_minflt, r.d_maxrss_kb });
    }
}
