# Performance Gap Analysis

> **Last updated:** 2026-03-24
> **Scope:** TLS 1.3/QUIC Implementation in Zig
> **Target:** <2ms handshake, <100KB memory per connection
> **Methodology:** Static code analysis, allocation pattern review, hot-path tracing
> **Reviewed by:** Phase 3 Performance Review

---

## Summary

| PerfSeverity | Count |
|-------------|-------|
| P0          | 3     |
| P1          | 3     |
| P2          | 3     |
| P3          | 2     |
| **Total**   | **11** |

### Top 5 Risks (by PerfScore)

1. **PERF-001** (PerfScore 80, P0): 10+ individual heap allocations in ClientHello parsing via zero-capacity ArrayLists. ~400ns wasted per parse on a hot path hit every connection.
2. **PERF-002** (PerfScore 80, P0): Context struct embeds a 2KB+ AntiReplayWindow inline, polluting cache for all connections including clients that never use it.
3. **PERF-003** (PerfScore 80, P0): 6 zero-capacity `ArrayList.initCapacity(allocator, 0)` calls in ClientHello parsing force immediate reallocation on first append.
4. **PERF-004** (PerfScore 60, P1): Dual-hash transcript (SHA-256 + SHA-384 concurrently) continues updating both hashes after cipher suite negotiation selects one.
5. **PERF-005** (PerfScore 60, P1): Global mutex on `getPool()` acquired on every call even after the pool is already initialized.

---

## Stack-Ranked Findings

| Rank | ID | PerfSeverity | PerfScore | Finding | Component | Evidence | Measurement (est.) | Fix Summary | Owner | SLA | Status |
|------|----|-------------|-----------|---------|-----------|----------|---------------------|-------------|-------|-----|--------|
| 1 | PERF-001 | P0 | 80 | ClientHello parse: 10+ heap allocs via zero-cap ArrayLists | app | `src/tls13/messages/client_hello.zig:270,347,369,424,457,484` | ~400ns per parse | Arena allocator for all parse-time allocations | git blame owner | Immediate | Open |
| 2 | PERF-002 | P0 | 80 | Context struct >2KB from inline AntiReplayWindow (64x32 bytes) | app | `src/tls13/context.zig:854` + `src/zero_rtt.zig:243` | Cache-line pollution on every Context access | Box behind pointer; allocate only for server role | git blame owner | Immediate | Open |
| 3 | PERF-003 | P0 | 80 | 6 zero-cap ArrayLists in ClientHello parsing trigger immediate realloc | app | `src/tls13/messages/client_hello.zig:270,347,369,424,457,484` | ~300ns wasted (6 x ~50ns realloc) | Use `initCapacity(allocator, 4)` or `initCapacity(allocator, 8)` | git blame owner | Immediate | Open |
| 4 | PERF-004 | P1 | 60 | Dual-hash transcript continues after cipher negotiation | app | `src/tls13/transcript.zig:101-122` | ~2-5us wasted per handshake (redundant hash updates) | Add single-hash fast path after cipher suite known | git blame owner | Within sprint | Open |
| 5 | PERF-005 | P1 | 60 | Global mutex on getPool() even after init | infra | `src/parallel.zig:69-82` | Contention scales with concurrency | Atomic double-checked locking pattern | git blame owner | Within sprint | Open |
| 6 | PERF-006 | P1 | 48 | ~38 copyForwards where @memcpy suffices (non-overlapping) | app | `src/record/aead.zig` (18), `src/key_schedule.zig` (9), `src/quic_transport_params.zig` (7), +4 others | <10ns per AEAD op (branch overhead) | Replace with @memcpy where src/dst provably non-overlapping | git blame owner | Within sprint | Open |
| 7 | PERF-007 | P2 | 36 | ServerHello builder: 5 zero-cap ArrayLists | app | `src/tls13/messages/server_hello.zig:319,349,377,506,531` | ~200ns wasted per ServerHello build | Pre-allocate with initCapacity(allocator, 64) for byte buffers | git blame owner | Next quarter | Open |
| 8 | PERF-008 | P2 | 36 | CryptoBuffer.consume uses O(n) memmove via copyForwards | app | `src/tls13/handshake_state.zig:83-91` | ~30-60ns per handshake (typical buffer <1KB) | Ring buffer or offset-based consume; low urgency at current sizes | git blame owner | Next quarter | Open |
| 9 | PERF-009 | P2 | 36 | empty_hash recomputed 6x across key derivation functions | app | `src/tls13/key_derivation.zig:123,184,306,461,492,620` | ~120ns total (6 x ~20ns hash of empty input) | Precompute as comptime const per hash algorithm | git blame owner | Next quarter | Open |
| 10 | PERF-010 | P3 | 20 | AntiReplayWindow.contains O(n) linear scan | app | `src/zero_rtt.zig:293-303` | ~200ns at n=64 (constant-time by design) | Acceptable for n=64; add hash set if window grows to 1024+ | git blame owner | Backlog | Open |
| 11 | PERF-011 | P3 | 16 | Missing benchmark suite for handshake latency regression detection | ci | No benchmark harness found in repo | N/A -- prevents regression detection | Add `zig build bench` target with handshake microbenchmarks | git blame owner | Backlog | Open |

---

## Detailed Findings

### PERF-001: ClientHello Parse -- Excessive Heap Allocations (P0)

**PerfScore:** 80 (Impact: 4 x Likelihood: 5 x 4)

**Summary:** `parseClientHello()` performs 10+ individual heap allocations through zero-capacity ArrayLists. Each ArrayList starts at capacity 0 and must reallocate on the first `append()` call. This function is on the hottest path -- called once per incoming connection.

**Evidence:**
- File: `src/tls13/messages/client_hello.zig`
- Lines 270, 347, 369, 424, 457, 484: Six `std.ArrayList(...).initCapacity(allocator, 0)` calls
- Each ArrayList triggers at least one `allocator.alloc()` on the first append and then `toOwnedSlice()` at the end
- Total: 6 ArrayLists x (1 initial alloc + 1 toOwnedSlice copy) = 12 allocator round-trips minimum

**Root Cause:** The parser uses general-purpose dynamic ArrayLists for fields whose sizes are bounded and predictable (typically 1-5 cipher suites, 1-3 named groups, 2-4 signature algorithms, 1-2 ALPN protocols, 1 PSK identity). A single arena allocation would serve all of these.

**Fix Guidance:**
1. Accept or create an arena allocator scoped to the parse call
2. Replace `initCapacity(allocator, 0)` with `initCapacity(allocator, N)` where N matches typical counts:
   - `cipher_suites`: initCapacity(allocator, 4) -- most clients offer 3 TLS 1.3 suites
   - `supported_groups`: initCapacity(allocator, 4)
   - `signature_algorithms`: initCapacity(allocator, 8)
   - `alpn_list`: initCapacity(allocator, 2)
   - `identities` / `binders`: initCapacity(allocator, 2)
3. Longer term: use a bump/arena allocator for the entire handshake, freeing all parse buffers in one shot

**Validation Plan:**
```
# Microbenchmark: time 10,000 parseClientHello calls before/after
zig build test -Doptimize=ReleaseFast 2>&1 | grep -i bench
# Or add a dedicated benchmark:
# const timer = std.time.Timer{};
# for (0..10_000) |_| { _ = try parseClientHello(arena, data); arena.reset(); }
# Expected: ~400ns -> ~100ns per parse (4x improvement)
```

**Rollout Risk:** Low. Arena allocator is a drop-in for the existing Allocator interface. Verify all callers properly free (or the arena handles it). No behavioral change.

**Confidence:** `confidence::confirmed` -- Zero-capacity initCapacity is unambiguous; each append must allocate.

---

### PERF-002: Context Struct Cache Pollution from Inline AntiReplayWindow (P0)

**PerfScore:** 80 (Impact: 4 x Likelihood: 5 x 4)

**Summary:** The `Context` struct embeds an `AntiReplayWindow` inline, which contains a `[64][32]u8` array (2,048 bytes). This bloats every Context instance -- including client-role contexts that never use anti-replay -- and pollutes CPU cache lines accessed during handshake processing.

**Evidence:**
- File: `src/tls13/context.zig:854`: `anti_replay: zero_rtt_mod.AntiReplayWindow`
- File: `src/zero_rtt.zig:243`: `randoms: [window_size][32]u8 = undefined` where `window_size = 64`
- Size: 64 entries x 32 bytes = 2,048 bytes embedded in every Context
- Client-role connections allocate this array but never use it

**Root Cause:** The AntiReplayWindow is stored by value inside Context rather than behind a pointer. It is only needed for server-role 0-RTT handling, yet it inflates every Context regardless of role.

**Fix Guidance:**
1. Change `anti_replay` field to `?*zero_rtt_mod.AntiReplayWindow`
2. Only allocate the window when `config.role == .Server` and `config.enable_early_data == true`
3. This reduces Context size by ~2KB for all clients and servers without 0-RTT

**Validation Plan:**
```
# Measure Context struct size before/after:
# @sizeOf(Context) -- expect reduction from ~2.5KB+ to ~500 bytes
# Memory benchmark: create 1000 Context instances, measure RSS
# Expected: ~2MB RSS reduction for 1000 connections
```

**Rollout Risk:** Low. Null-check the pointer before use. The anti_replay field already has a `.deinit()` call in `Context.deinit()` that would need to handle the optional pointer. Test that 0-RTT replay detection still works for server role.

**Confidence:** `confidence::confirmed` -- `@sizeOf([64][32]u8)` = 2048 bytes is a compile-time fact.

---

### PERF-003: Zero-Capacity ArrayLists Force Immediate Reallocation (P0)

**PerfScore:** 80 (Impact: 4 x Likelihood: 5 x 4)

**Summary:** Six ArrayLists in `parseClientHello()` are initialized with `initCapacity(allocator, 0)`, meaning their backing buffer is null. The first `append()` triggers an allocation for capacity 1, which is then doubled on subsequent appends. This produces multiple small allocations and copies for predictable-size arrays.

**Evidence:**
- File: `src/tls13/messages/client_hello.zig`
- Line 270: `cipher_suites` -- typically 1-3 TLS 1.3 suites
- Line 347: `groups` -- typically 1-4 named groups
- Line 369: `algs` -- typically 2-8 signature algorithms
- Line 424: `alpn_list` -- typically 1-2 protocols
- Line 457: `identities` -- typically 1 PSK identity
- Line 484: `binders` -- typically 1 binder

**Root Cause:** `initCapacity(allocator, 0)` is functionally identical to an uninitialized ArrayList -- it allocates nothing. The first append then triggers a minimum-size allocation (typically 1 or 2 elements), leading to geometric growth. For small, bounded collections this wastes cycles on avoidable reallocs.

**Fix Guidance:**
Replace each `initCapacity(allocator, 0)` with a right-sized initial capacity:
```zig
// Before:
var cipher_suites = try std.ArrayList(core_types.CipherSuite).initCapacity(allocator, 0);
// After:
var cipher_suites = try std.ArrayList(core_types.CipherSuite).initCapacity(allocator, 4);
```

Recommended capacities: cipher_suites=4, groups=4, algs=8, alpn_list=2, identities=2, binders=2.

**Validation Plan:**
```
# Count allocator calls with a counting allocator wrapper:
# Before: expect 12+ alloc calls per parseClientHello
# After: expect 6 alloc calls (one per ArrayList, no reallocs)
# Latency: ~300ns savings (6 avoided reallocs x ~50ns each)
```

**Rollout Risk:** Minimal. Pre-allocating slightly more memory than needed is acceptable; unused capacity is freed by `toOwnedSlice()`. No functional change.

**Confidence:** `confidence::confirmed` -- `initCapacity(allocator, 0)` is documented to allocate nothing.

---

### PERF-004: Dual-Hash Transcript Continues After Cipher Negotiation (P1)

**PerfScore:** 60 (Impact: 3 x Likelihood: 5 x 4)

**Summary:** The `Transcript` struct maintains both SHA-256 and SHA-384 hash states and updates both on every `update()` call. After the cipher suite is negotiated (ServerHello), only one hash algorithm is needed, but both continue to be fed all subsequent handshake messages (EncryptedExtensions, Certificate, CertificateVerify, Finished).

**Evidence:**
- File: `src/tls13/transcript.zig:101-122`
- Lines 101-103: `Transcript` holds both `sha256: Sha256` and `sha384: Sha384`
- Lines 119-121: `update()` unconditionally calls `self.sha256.update(msg)` and `self.sha384.update(msg)`
- Post-ServerHello messages (EncryptedExtensions, Certificate, CertificateVerify, Finished) are typically 2-5KB total
- SHA-384 processes ~1.5x slower than SHA-256 per byte on most hardware

**Root Cause:** The transcript design pre-dates cipher suite negotiation awareness. There is no "lock in" mechanism to stop updating the unused hash after negotiation.

**Fix Guidance:**
1. Add a `negotiated_hash: ?Hash` field to `Transcript`
2. After cipher suite is selected, call `transcript.lockHash(.sha256)` (or `.sha384`)
3. In `update()`, skip the unneeded hash when `negotiated_hash` is set
4. This eliminates ~50% of hash computation for post-ServerHello messages

**Validation Plan:**
```
# Profile a full handshake with perf or Tracy:
# Before: ~8us in transcript hash updates
# After: ~4us (eliminate redundant hash)
# Alternatively, count hash update calls: expect 50% reduction post-ServerHello
```

**Rollout Risk:** Low. The unused hash state can be left stale. Ensure `finalize()` still works correctly when called with the negotiated hash. Add test coverage for both SHA-256 and SHA-384 cipher suites.

**Confidence:** `confidence::confirmed` -- Dual update in `update()` is visible at lines 120-121.

---

### PERF-005: Global Mutex Contention on getPool() (P1)

**PerfScore:** 60 (Impact: 3 x Likelihood: 5 x 4)

**Summary:** `getPool()` acquires a global mutex on every call, even after the thread pool is already initialized. Under concurrent load (multiple TLS handshakes using parallel operations), this becomes a serialization point.

**Evidence:**
- File: `src/parallel.zig:69-82`
- Line 69: `var pool_mutex: std.Thread.Mutex = .{};`
- Lines 74-75: `pool_mutex.lock()` / `defer pool_mutex.unlock()` on every `getPool()` call
- `getPool()` is called from `parallelCertificateValidate`, `parallelSignatureVerify`, `parallelAeadSeal`, `parallelKeyDerive`

**Root Cause:** Simple mutex-guarded lazy init without a fast path for the already-initialized case.

**Fix Guidance:**
Use atomic double-checked locking:
```zig
pub fn getPool() *spice.ThreadPool {
    // Fast path: pool already initialized (atomic load, no lock)
    if (@atomicLoad(?*spice.ThreadPool, &global_pool_ptr, .acquire)) |pool| {
        return pool;
    }
    // Slow path: initialize under lock
    pool_mutex.lock();
    defer pool_mutex.unlock();
    if (global_pool == null) {
        global_pool = spice.ThreadPool.init(std.heap.page_allocator);
        global_pool.?.start(.{});
    }
    return &global_pool.?;
}
```

**Validation Plan:**
```
# Benchmark with 8 threads calling getPool() concurrently:
# Before: mutex contention visible in perf lock stats
# After: fast path is a single atomic load (~1ns vs ~50-200ns for mutex)
```

**Rollout Risk:** Low. Double-checked locking with acquire/release atomics is a well-understood pattern. Ensure `deinitPool()` also uses proper ordering.

**Confidence:** `confidence::confirmed` -- Mutex acquisition on every call is visible at line 74.

---

### PERF-006: copyForwards Used Where @memcpy Suffices (P1)

**PerfScore:** 48 (Impact: 2 x Likelihood: 5 x 4 + rounding to bucket)

**Summary:** 38 instances of `std.mem.copyForwards` are used across 6 source files where the source and destination buffers are provably non-overlapping. `copyForwards` includes branch logic to handle overlapping regions, while `@memcpy` compiles to an optimized intrinsic for non-overlapping copies.

**Evidence:**
- `src/record/aead.zig`: 18 occurrences (nonce copies, tag copies, key copies)
- `src/key_schedule.zig`: 9 occurrences (secret/PRK copies into fixed-size arrays)
- `src/quic_transport_params.zig`: 7 occurrences (address/token copies)
- `src/tls13/engine.zig`: 2 occurrences
- `src/tls13/context.zig`: 1 occurrence
- `src/tls13/handshake_state.zig`: 1 occurrence (this one IS overlapping -- keep copyForwards)

**Root Cause:** `copyForwards` was likely used uniformly for safety without analyzing overlap. Most instances copy from one fixed buffer into another (e.g., `copyForwards(u8, nonce_arr[0..], nonce_full[0..12])`), which cannot overlap.

**Fix Guidance:**
Replace `std.mem.copyForwards` with `@memcpy` in the ~37 non-overlapping cases. Keep `copyForwards` for `handshake_state.zig:88` (inbound buffer self-shift) and `context.zig:790` (similar pattern) where overlap is possible.

**Validation Plan:**
```
# Compile with -Doptimize=ReleaseFast and compare generated assembly:
# @memcpy should emit rep movsb or SIMD instructions
# copyForwards includes a branch for direction
# Latency delta: <10ns per AEAD operation, but compounds over many operations
```

**Rollout Risk:** Minimal. `@memcpy` is stricter -- it will trigger a safety check in debug mode if buffers overlap. This is the desired behavior: catch accidental overlap during testing. Run full test suite to validate.

**Confidence:** `confidence::confirmed` -- Non-overlap is verifiable by inspection (different source arrays, stack-local targets).

---

### PERF-007: ServerHello Builder Zero-Capacity ArrayLists (P2)

**PerfScore:** 36 (Impact: 3 x Likelihood: 3 x 4)

**Summary:** The ServerHello message builder uses 5 zero-capacity ArrayLists for constructing the binary message, each requiring reallocation on first append.

**Evidence:**
- File: `src/tls13/messages/server_hello.zig`
- Line 319: `var msg = try std.ArrayList(u8).initCapacity(allocator, 0);`
- Line 349: `var exts = try std.ArrayList(u8).initCapacity(allocator, 0);`
- Line 377: `var ks_data = try std.ArrayList(u8).initCapacity(allocator, 0);`
- Line 506: `var msg = try std.ArrayList(u8).initCapacity(allocator, 0);`
- Line 531: `var exts = try std.ArrayList(u8).initCapacity(allocator, 0);`
- ServerHello is a fixed-structure message; final size is predictable (~70-120 bytes)

**Root Cause:** Same pattern as PERF-003. Byte-buffer ArrayLists for message construction start empty and grow through multiple reallocations.

**Fix Guidance:**
Pre-allocate based on known ServerHello structure:
- `msg`: initCapacity(allocator, 128) -- covers full ServerHello
- `exts`: initCapacity(allocator, 64) -- key_share + supported_versions
- `ks_data`: initCapacity(allocator, 48) -- group(2) + key_len(2) + key(32) + overhead

Similar patterns exist in `certificate.zig` (2), `certificate_request.zig` (5), `encrypted_extensions.zig` (3), `finished.zig` (1), `certificate_verify.zig` (1) -- total 23 zero-cap ArrayLists across message builders.

**Validation Plan:**
```
# Count allocator calls during a full handshake with counting allocator:
# Before: ~30+ allocations across message builders
# After: ~15 allocations (one per builder, no reallocs)
# Expected: ~200ns savings per ServerHello construction
```

**Rollout Risk:** Minimal. Over-allocation by a few bytes is acceptable for short-lived buffers.

**Confidence:** `confidence::confirmed` -- `initCapacity(allocator, 0)` pattern is visible in source.

---

### PERF-008: CryptoBuffer.consume O(n) Memmove (P2)

**PerfScore:** 36 (Impact: 2 x Likelihood: 4 x 4 + adjustment)

**Summary:** `CryptoBuffer.consume()` shifts remaining bytes toward the front of the inbound buffer using `copyForwards`, which is an O(n) memmove operation. This is called after processing each handshake message from the CRYPTO stream.

**Evidence:**
- File: `src/tls13/handshake_state.zig:83-91`
- Line 88: `std.mem.copyForwards(u8, self.inbound.items[0..remaining], self.inbound.items[count .. count + remaining])`
- Typical handshake: 3-5 consume calls, buffer typically <1KB
- Same pattern in `src/tls13/context.zig:790` and `src/tls13/engine.zig:901`

**Root Cause:** Linear buffer with front-consumption requires shifting all remaining data forward. An offset-based or ring-buffer approach would make consume O(1).

**Fix Guidance:**
For the current buffer sizes (<2KB typical), the O(n) cost is ~30-60ns per consume, which is acceptable. If CRYPTO buffers grow (e.g., large certificate chains), consider:
1. Maintain a `consumed` offset instead of shifting data
2. Only compact when offset exceeds 50% of capacity
3. Or switch to a ring buffer for zero-copy consume

**Validation Plan:**
```
# Benchmark consume() with varying buffer sizes:
# 256B: ~10ns, 1KB: ~30ns, 4KB: ~100ns
# Only pursue optimization if profiling shows consume() in top 20 hot spots
```

**Rollout Risk:** Medium if switching to ring buffer (more complex indexing). Low if using offset approach.

**Confidence:** `confidence::confirmed` -- `copyForwards` with overlapping ranges is an O(n) shift by definition.

---

### PERF-009: empty_hash Recomputed in Key Derivation (P2)

**PerfScore:** 36 (Impact: 2 x Likelihood: 4 x 4 + adjustment)

**Summary:** The `empty_hash` value (`Hash("")`) is recomputed 6 times across key derivation functions. This value is a constant for each hash algorithm and could be precomputed at compile time.

**Evidence:**
- File: `src/tls13/key_derivation.zig`
- Line 123: `const empty_hash = ks.hashBytes(hash, &[_]u8{});` (deriveBinderKey)
- Line 184: same (deriveHandshakeTraffic)
- Line 306: same (deriveApplicationTraffic)
- Line 461: same (test function, SHA-384)
- Line 492: same (test function, SHA-256)
- Line 620: same (test function, SHA-256)
- 3 are in production code paths (lines 123, 184, 306), 3 in tests

**Root Cause:** `hashBytes(hash, &[_]u8{})` is a runtime call that initializes a hasher, updates with zero bytes, and finalizes. The result is a well-known constant:
- SHA-256("") = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- SHA-384("") = `38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b`

**Fix Guidance:**
Precompute as comptime constants:
```zig
const empty_hash_sha256 = comptime blk: {
    var h = Sha256.init(.{});
    var out: [32]u8 = undefined;
    h.final(&out);
    break :blk Secret.fromSlice(.sha256, &out);
};
```
Then use `const empty_hash = if (hash == .sha256) empty_hash_sha256 else empty_hash_sha384;`

**Validation Plan:**
```
# Before: 3 x ~20ns = ~60ns in production key derivation (per handshake)
# After: 0ns (compile-time constant, no runtime hash)
# Verify correctness by comparing comptime values against RFC test vectors
```

**Rollout Risk:** Minimal. Compile-time computation produces the same bytes. Add a comptime assertion comparing against the known hex values.

**Confidence:** `confidence::confirmed` -- Hash of empty input is a mathematical constant.

---

### PERF-010: AntiReplayWindow.contains O(n) Linear Scan (P3)

**PerfScore:** 20 (Impact: 2 x Likelihood: 2 x 4 + adjustment)

**Summary:** `AntiReplayWindow.contains()` performs a linear scan over all entries using constant-time comparison. At the default window size of 64, this is ~200ns.

**Evidence:**
- File: `src/zero_rtt.zig:293-303`
- Line 294: `const limit = @min(self.count, window_size);`
- Lines 297-302: Loop with `timing_safe.eql` comparison (constant-time, ~3ns per entry)
- 64 entries x ~3ns = ~192ns per lookup
- Only called for server-role 0-RTT connections

**Root Cause:** The linear scan is intentional for constant-time security (prevents timing side-channels). The window size of 64 is small enough that this is not a bottleneck.

**Fix Guidance:**
No immediate action needed. The current design is correct for security:
- Constant-time comparison prevents timing attacks on the anti-replay cache
- 64 entries at ~200ns is negligible compared to ECDHE (~50-100us)

If the window grows to 1024+ entries (high-traffic servers), consider:
1. A Bloom filter for fast negative lookups, with linear scan only on positive hits
2. Accept the timing leak for a hash-based lookup (document the security trade-off)

**Validation Plan:**
```
# Benchmark at various window sizes:
# 64: ~200ns, 256: ~800ns, 1024: ~3us
# Only optimize if window_size > 256 is needed in production
```

**Rollout Risk:** N/A (no change recommended).

**Confidence:** `confidence::confirmed` -- O(n) loop is visible; timing is estimable from constant-time comparison cost.

---

### PERF-011: Missing Benchmark Suite (P3)

**PerfScore:** 16 (Impact: 1 x Likelihood: 4 x 4)

**Summary:** The repository has no benchmark harness for handshake latency, allocation counts, or throughput. Without benchmarks, performance regressions cannot be detected automatically.

**Evidence:**
- No `bench` or `benchmark` directory found in the repository
- No `zig build bench` target in `build.zig`
- Performance-sensitive code paths (ClientHello parse, key derivation, AEAD operations) have no latency tracking

**Root Cause:** The project is focused on correctness and RFC compliance (extensive test suites exist). Performance testing has not been prioritized.

**Fix Guidance:**
Create a benchmark suite covering:
1. **Handshake latency**: Full client+server handshake round-trip (target: <2ms)
2. **Parse latency**: `parseClientHello()` with realistic ClientHello (target: <1us)
3. **Key derivation**: `deriveHandshakeTraffic()` + `deriveApplicationTraffic()` (target: <50us)
4. **AEAD throughput**: Seal/Open operations at 1KB, 16KB, 64KB (target: >1GB/s)
5. **Memory per connection**: Context creation + full handshake (target: <100KB)
6. **Allocation count**: Total allocator calls per handshake (target: <50)

Add as a `zig build bench` target using `std.time.Timer` or a custom benchmark framework.

**Validation Plan:**
```
# After implementing:
zig build bench -Doptimize=ReleaseFast
# Expected output: latency percentiles, allocation counts, memory usage
# Integrate into CI to catch regressions
```

**Rollout Risk:** None. Benchmarks are additive and do not modify production code.

**Confidence:** `confidence::confirmed` -- Absence of benchmark infrastructure is verifiable.

---

## Findings by Area

### App (8 findings)

| ID | PerfSeverity | Finding |
|----|-------------|---------|
| PERF-001 | P0 | ClientHello parse excessive heap allocations |
| PERF-002 | P0 | Context struct cache pollution from inline AntiReplayWindow |
| PERF-003 | P0 | Zero-capacity ArrayLists in ClientHello parsing |
| PERF-004 | P1 | Dual-hash transcript after cipher negotiation |
| PERF-006 | P1 | copyForwards where @memcpy suffices |
| PERF-007 | P2 | ServerHello builder zero-capacity ArrayLists |
| PERF-008 | P2 | CryptoBuffer.consume O(n) memmove |
| PERF-009 | P2 | empty_hash recomputed in key derivation |

### Infra (1 finding)

| ID | PerfSeverity | Finding |
|----|-------------|---------|
| PERF-005 | P1 | Global mutex contention on getPool() |

### App (1 finding -- anti-replay, kept separate as it's security-sensitive)

| ID | PerfSeverity | Finding |
|----|-------------|---------|
| PERF-010 | P3 | AntiReplayWindow.contains O(n) linear scan |

### CI (1 finding)

| ID | PerfSeverity | Finding |
|----|-------------|---------|
| PERF-011 | P3 | Missing benchmark suite |

---

## Roadmap

### Quick Wins (< 1 day each)

| ID | Effort | Expected Impact |
|----|--------|----------------|
| PERF-003 | 30 min | ~300ns/parse -- change 6 initCapacity(0) to initCapacity(4-8) |
| PERF-009 | 30 min | ~120ns/handshake -- precompute empty_hash as comptime const |
| PERF-007 | 1 hr | ~200ns/ServerHello -- pre-allocate message builder ArrayLists |
| PERF-006 | 2 hr | <10ns/AEAD op -- replace ~37 copyForwards with @memcpy |

### Medium (1-5 days)

| ID | Effort | Expected Impact |
|----|--------|----------------|
| PERF-001 | 2 days | ~400ns/parse -- arena allocator for ClientHello parsing |
| PERF-002 | 1 day | ~2KB/connection -- box AntiReplayWindow behind pointer |
| PERF-004 | 2 days | ~2-5us/handshake -- single-hash transcript fast path |
| PERF-005 | 1 day | Eliminates mutex contention -- atomic double-checked locking |

### Strategic (> 5 days)

| ID | Effort | Expected Impact |
|----|--------|----------------|
| PERF-011 | 5-10 days | Regression prevention -- full benchmark suite with CI integration |
| PERF-008 | 3-5 days | Future-proofing -- ring buffer for CryptoBuffer (only if buffers grow) |
| PERF-010 | 3 days | Future-proofing -- hash-based anti-replay (only if window >256) |

---

## Unknowns and Blockers

1. **No profiler data available.** All latency estimates are based on static analysis and known costs of Zig standard library operations. Running `perf record` or Tracy on a real handshake would confirm or refine these estimates.

2. **Context struct total size unknown.** The `Context` struct in `src/tls13/context.zig` is ~3500 lines with many fields. An `@sizeOf(Context)` measurement would confirm the cache pollution impact of PERF-002.

3. **AEAD copyForwards impact is theoretical.** The per-operation cost of copyForwards vs @memcpy is <10ns. Aggregate impact depends on throughput requirements (connections/sec). Profiling under load would confirm whether this is material.

4. **Transcript dual-hash cost depends on cipher suite distribution.** If 99% of connections use SHA-256 suites, the wasted SHA-384 computation is the full cost. If SHA-384 suites are common, both hashes are sometimes needed through ServerHello.

### What Would Confirm Suspected Items

All 11 findings are tagged `confidence::confirmed` based on unambiguous code evidence. To refine the estimated latency impacts:
- Run `parseClientHello` with a counting allocator to get exact allocation counts
- Profile a full handshake with `std.time.Timer` to measure actual wall-clock time per phase
- Use `@sizeOf(Context)` to measure the struct size impact of PERF-002
- Benchmark `copyForwards` vs `@memcpy` for typical buffer sizes (12-48 bytes) on target hardware
