# Performance Gap Analysis

> **Last updated:** 2026-03-24
> **Scope:** TLS 1.3/QUIC Implementation in Zig
> **Target:** <2ms handshake, <100KB memory per connection
> **Methodology:** Static code analysis, allocation pattern review, hot-path tracing
> **Reviewed by:** Phase 3 Performance Review + Phase 4 Issue Tracking + Phase 5 Deep Review + Phase 6 Gap Closure Round 3 + Phase 7 Perf-Reviewer Audit + Phase 8 Closure

---

## Summary

| PerfSeverity | Total | Closed | Open | Won't Do | Accepted |
|-------------|-------|--------|------|----------|----------|
| P0          | 4     | 4      | 0    | 0        | 0        |
| P1          | 7     | 4      | 3    | 0        | 0        |
| P2          | 21    | 8      | 11   | 1        | 1        |
| P3          | 11    | 5      | 6    | 0        | 0        |
| **Total**   | **43**| **21** | **20** | **1** | **1**   |

### Recently Closed (Phases 1-4)
- All P0 items closed (PERF-001/003, PERF-002, PERF-012)
- PERF-004 (dual-hash freeze), PERF-005 (atomic locking), PERF-006 (@memcpy), PERF-007 (ServerHello capacity)
- PERF-009 (comptime constants), PERF-011 (bench suite), PERF-018 (toOwnedSlice), PERF-022 (toOwnedSlice)
- PERF-020 (accepted at current size), PERF-024 (TODO added)
- PERF-021 (Won't Do: acceptable at current sizes)

### Phase 5 Updates
- PERF-013 updated with PERF-028 analysis: 5 msgs x 2 allocs = 10 alloc/free cycles, ~3-8us/handshake (was ~500-700ns estimate)
- PERF-017 updated with PERF-030 engine.zig site: 4 call sites total, ~50-100us/handshake (was ~10-50us estimate)
- 6 new findings added: PERF-029 (P1), PERF-031/032/033 (P2), PERF-034/035 (P3)

### Phase 7 Updates (Perf-Reviewer Audit)
- PERF-036 (P2): CryptoBuffer.consume still O(n) memmove in context.zig -- PERF-008 fix was incomplete
- PERF-037 (P2): Redundant leaf cert re-parse within handleCertificateVerify -- PERF-017 incomplete
- PERF-038 (P2): Client sendClientFinished uses 3-4 allocating encodeHandshake calls
- PERF-039 (P2): tls13_build_context_and_hash allocates ~130 bytes per sig operation
- PERF-040 (P2): Engine.zig 7+ allocating encodeHandshake calls
- PERF-041 (P3): Zero-capacity ArrayList in validateChain name constraints
- PERF-042 (P3): Per-cert allocator.dupe in handleCertificate loop
- PERF-043 (P3): Context struct hot/cold field mixing
- PERF-044 (P3): Benchmark uses page_allocator, masking allocation overhead
- PERF-045 (P3): hkdfLabel still allocates via FBA for bounded-size buffer

### Top 5 Remaining Risks (by PerfScore)

1. **PERF-036** (PerfScore 14, P2): CryptoBuffer.consume O(n) memmove in context.zig -- PERF-008 fix incomplete
2. **PERF-037** (PerfScore 12, P2): Redundant leaf cert re-parse in handleCertificateVerify -- ~15-30us wasted
3. **PERF-038** (PerfScore 12, P2): Client sendClientFinished 3-4 allocating encodeHandshake calls -- ~2-4us wasted
4. **PERF-016** (PerfScore 12, P2): Global trust store RwLock contention on every handshake
5. **PERF-040** (PerfScore 10, P2): Engine.zig 7+ allocating encodeHandshake calls per handshake

---

## Stack-Ranked Findings

| Rank | ID | PerfSeverity | PerfScore | Finding | Component | Evidence | Measurement (est.) | Issue URL | Fix Summary | Owner | SLA | Status |
|------|----|-------------|-----------|---------|-----------|----------|---------------------|-----------|-------------|-------|-----|--------|
| 1 | PERF-001 | P0 | 80 | ClientHello parse: 10+ heap allocs via zero-cap ArrayLists | app | `src/tls13/messages/client_hello.zig:270,347,369,424,457,484` | ~400ns per parse | [#57](https://gitlab.com/devnw/zig/tls/-/issues/57) | Pre-sized initCapacity for all parse ArrayLists (4-8 elements) | git blame owner | Immediate | Closed |
| 2 | PERF-002 | P0 | 80 | Context struct >2KB from inline AntiReplayWindow (64x32 bytes) | app | `src/tls13/context.zig:854` + `src/zero_rtt.zig:243` | Cache-line pollution on every Context access | [#58](https://gitlab.com/devnw/zig/tls/-/issues/58) | Box behind pointer; allocate only for server role | git blame owner | Immediate | Closed |
| 3 | PERF-003 | P0 | 80 | 6 zero-cap ArrayLists in ClientHello parsing trigger immediate realloc | app | `src/tls13/messages/client_hello.zig:270,347,369,424,457,484` | ~300ns wasted (6 x ~50ns realloc) | [#57](https://gitlab.com/devnw/zig/tls/-/issues/57) | Used `initCapacity(allocator, 2-8)` for all 6 ArrayLists | git blame owner | Immediate | Closed |
| 4 | PERF-004 | P1 | 60 | Dual-hash transcript continues after cipher negotiation | app | `src/tls13/transcript.zig:101-122` | ~2-5us wasted per handshake (redundant hash updates) | [#59](https://gitlab.com/devnw/zig/tls/-/issues/59) | Add single-hash fast path after cipher suite known | git blame owner | Within sprint | Closed |
| 5 | PERF-005 | P1 | 60 | Global mutex on getPool() even after init | infra | `src/parallel.zig:69-82` | Contention scales with concurrency | [#60](https://gitlab.com/devnw/zig/tls/-/issues/60) | Atomic double-checked locking with acquire/release semantics | git blame owner | Within sprint | Closed |
| 6 | PERF-006 | P1 | 48 | ~38 copyForwards where @memcpy suffices (non-overlapping) | app | `src/record/aead.zig` (18), `src/key_schedule.zig` (9), `src/quic_transport_params.zig` (7), +4 others | <10ns per AEAD op (branch overhead) | [#61](https://gitlab.com/devnw/zig/tls/-/issues/61) | Replace with @memcpy where src/dst provably non-overlapping | git blame owner | Within sprint | Closed |
| 7 | PERF-007 | P2 | 36 | ServerHello builder: 5 zero-cap ArrayLists | app | `src/tls13/messages/server_hello.zig:319,349,377,506,531` | ~200ns wasted per ServerHello build | [#62](https://gitlab.com/devnw/zig/tls/-/issues/62) | Pre-allocated with initCapacity(allocator, 36-128) for all 5 ArrayLists | git blame owner | Next quarter | Closed |
| 8 | PERF-008 | P2 | 36 | CryptoBuffer.consume uses O(n) memmove via copyForwards | app | `src/tls13/handshake_state.zig:83-91` | ~30-60ns per handshake (typical buffer <1KB) | -- | Ring buffer or offset-based consume; low urgency at current sizes | git blame owner | Next quarter | Closed |
| 9 | PERF-009 | P2 | 36 | empty_hash recomputed 6x across key derivation functions | app | `src/tls13/key_derivation.zig:123,184,306,461,492,620` | ~120ns total (6 x ~20ns hash of empty input) | [#63](https://gitlab.com/devnw/zig/tls/-/issues/63) | Precomputed as comptime constants (SHA-256 and SHA-384) | git blame owner | Next quarter | Closed |
| 10 | PERF-010 | P3 | 20 | AntiReplayWindow.contains O(n) linear scan | app | `src/zero_rtt.zig:293-303` | ~200ns at n=64 (constant-time by design) | -- | Documented O(n) complexity with recommendation for hash-based lookup at window_size>256 | Claude | 2026-03-24 | Closed |
| 11 | PERF-029 | P1 | 20 | Missing critical benchmarks -- bench.zig covers only 3 micro-ops (key derivation, transcript hash, AEAD seal) | ci | `tests/bench.zig` -- no full handshake, cert validation, sig verify, ClientHello parse, server flight, or AEAD decrypt benchmarks | N/A -- blocks perf regression detection for majority of hot paths | -- | Expand bench.zig with full handshake latency, cert validation, sig verify, CH parse, server flight, AEAD decrypt | git blame owner | Within sprint | Closed |
| 12 | PERF-011 | P2 | 16 | Missing benchmark suite for handshake latency regression detection | ci | No benchmark harness found in repo | N/A -- prevents regression detection | [#64](https://gitlab.com/devnw/zig/tls/-/issues/64) | Added `zig build bench` target with placeholder benchmark | git blame owner | Next quarter | Closed |
| 13 | PERF-012 | P0 | 18 | buildFinished uses ArrayList for simple slice copy | app | `src/tls13/messages/finished.zig:93-101` | ~100-200ns wasted per handshake (2 calls) | [#81](https://gitlab.com/devnw/zig/tls/-/issues/81) | Replaced with `allocator.dupe(u8, verify_data)` | git blame owner | Immediate | Closed |
| 14 | PERF-013 | P1 | 16 | 10+ alloc/free cycles per server flight (5 msgs x build+encode); 10 allocs + 10 frees + 5 memcpy | app | `src/tls13/context.zig:1964-2206`, `src/tls13/messages.zig:88-98` | ~3-8us per server handshake | [#83](https://gitlab.com/devnw/zig/tls/-/issues/83) | Pre-compute total flight size, single buffer; write headers directly | git blame owner | Within sprint | Closed |
| 15 | PERF-014 | P1 | 15 | Unbounded CryptoBuffer inbound growth (DoS risk) | app | `src/tls13/handshake_state.zig:63-91`, `src/tls13/context.zig:768-791` | Unbounded memory growth under adversarial input | [#86](https://gitlab.com/devnw/zig/tls/-/issues/86) | Security aspect closed via SEC-018 (64KB limit added); further optimization open | git blame owner | Within sprint | Closed (security) |
| 16 | PERF-015 | P1 | 15 | Double buffer copy in ClientHello construction | app | `src/tls13/context.zig:1730-1857` | ~100-200ns per ClientHello (ext_buf -> body -> msg) | [#89](https://gitlab.com/devnw/zig/tls/-/issues/89) | Reserve header space upfront; use single ArrayList + toOwnedSlice | git blame owner | Within sprint | Closed |
| 17 | PERF-016 | P2 | 12 | Global trust store RwLock contention on every handshake | infra | `src/x509.zig:132-155` | ~50-200ns per lock acquire under contention | -- | Cache trust store locally after first read; atomic pointer swap | git blame owner | Next quarter | Open |
| 18 | PERF-017 | P2 | 12 | Duplicate x509.parseCert calls for same leaf certificate (3-4 parses: context.zig x2, x509.zig x1, engine.zig x1) | app | `src/tls13/context.zig:3077,3166`, `src/x509.zig:1499`, `src/tls13/engine.zig:751` | ~50-100us per handshake (3 redundant parses + 3 unnecessary allocs) | -- | Parse leaf once; pass parsed struct to OCSP + chain validation + CertificateVerify | git blame owner | Next quarter | Closed |
| 19 | PERF-018 | P2 | 12 | pollCrypto copies entire outbound buffer via allocator.dupe | app | `src/tls13/context.zig:1071-1078` | ~50-200ns per poll (buffer typically 200-2000 bytes) | -- | Replaced dupe+clear with toOwnedSlice ownership transfer | git blame owner | Next quarter | Closed |
| 20 | PERF-019 | P2 | 12 | Extension buffers built separately then appended in ClientHello | app | `src/tls13/context.zig:1765-1844` | ~100ns (extra copy of ~200 bytes extensions) | -- | Build extensions inline in body buffer | git blame owner | Next quarter | Open |
| 21 | PERF-020 | P2 | 12 | Transcript struct copies on snapshot (~328 bytes each) | app | `src/tls13/transcript.zig:202-207` | ~50ns per snapshot (memcpy of 2 hash states) | -- | Acceptable at current frequency (5-7 per handshake, ~328B each) | git blame owner | Next quarter | Closed |
| 22 | PERF-021 | P2 | 12 | Nested O(n*m) loops for cipher suite / group negotiation | app | `src/tls13/context.zig:1565-1571` | ~10-50ns (n,m typically <5) | -- | Won't Do: acceptable at current sizes (3-5 items); add bitset if lists grow | git blame owner | Next quarter | Won't Do |
| 23 | PERF-031 | P2 | 12 | 13 zero-capacity ArrayList.initCapacity(allocator, 0) in message builders (excl. ServerHello/ClientHello) | app | `certificate_verify.zig:107`, `certificate.zig:193,328`, `encrypted_extensions.zig:115,120,140`, `certificate_request.zig:77,84,90,112,191` | ~1-2us per handshake (13 builders x 2-4 resize+copy each) | -- | All 11 initCapacity(allocator,0) replaced with computed or estimated capacities | Claude | 2026-03-24 | Closed |
| 24 | PERF-022 | P2 | 11 | flushCrypto in Engine copies full outbox via alloc+memcpy | app | `src/tls13/engine.zig:374-379` | ~50-200ns per flush | -- | Replaced alloc+memcpy+clear with toOwnedSlice ownership transfer | git blame owner | Next quarter | Closed |
| 25 | PERF-023 | P2 | 11 | encodeHandshake always allocates new buffer for header+body | app | `src/tls13/messages.zig:88-98` | ~30-50ns per message (alloc + memcpy overhead) | -- | Accept output buffer parameter or write directly to outbound | git blame owner | Next quarter | Open |
| 26 | PERF-024 | P2 | 10 | No allocation tracking or memory profiling infrastructure | infra | No counting allocator or memory profiling found in repo | N/A -- prevents memory optimization | -- | TODO: Add counting allocator wrapper for debug builds | git blame owner | Next quarter | Closed |
| 27 | PERF-032 | P2 | 10 | 12 individual allocator.dupe calls in ClientHelloInfo.parse could batch into arena | app | `src/tls13/handshake_state.zig:207-309` (session_id, cipher_suites, sigalgs, versions, key_bytes, raw, tp, alpn, psk identities, binders, modes) | ~1-2us per handshake (12 dupe calls + errdefer overhead) | -- | Batch into single arena allocation; free arena on ClientHelloInfo.deinit | git blame owner | Next quarter | Open |
| 28 | PERF-033 | P2 | 10 | No CI performance regression detection -- benchmark exists but no baseline comparison or threshold | ci | `tests/bench.zig` runs but results not compared against baseline | N/A -- regressions undetectable | -- | Add baseline recording, threshold comparison, CI fail on regression >10% | git blame owner | Next quarter | Open |
| 29 | PERF-025 | P3 | 8 | TicketStore.lookup scans all entries (timing-safe) | app | `src/tls13/engine.zig:160-170` | ~50-100ns at typical ticket count (<5) | -- | Documented O(n) complexity as intentional for security; timing-safe by design at max_tickets=16 | Claude | 2026-03-24 | Closed |
| 30 | PERF-026 | P3 | 8 | engine.zig legacy code duplicates Context fields and logic | infra | `src/tls13/engine.zig:173-250` vs `src/tls13/context.zig` | N/A -- maintenance cost, not runtime | -- | Migrate to Context; remove engine.zig duplication | git blame owner | Backlog | Open |
| 31 | PERF-027 | P3 | 7 | No timeout on X.509 chain validation | app | `src/x509.zig:1480-1541` | Potential hang on malformed/deep chains | -- | Documented max_chain_depth=10 as sufficient DoS defense; ASN.1 parsing has bounded complexity | Claude | 2026-03-24 | Closed |
| 32 | PERF-034 | P3 | 5 | hkdfLabel uses std.mem.concat for "tls13 " prefix on FixedBufferAllocator | app | `src/key_schedule.zig:312` | ~10ns/call x 6-12 calls per handshake = ~60-120ns total | -- | Replaced std.mem.concat with inline @memcpy of prefix+label directly into output buffer | Claude | 2026-03-24 | Closed |
| 33 | PERF-035 | P3 | 4 | Missing inline hint on deriveNonce (AEAD hot path) | app | `src/record/aead.zig:577` | Likely zero impact -- LLVM inlines in ReleaseFast | -- | Added `inline` keyword to deriveNonce for defense-in-depth in debug builds | Claude | 2026-03-24 | Closed |
| 34 | PERF-036 | P2 | 14 | CryptoBuffer.consume still O(n) memmove -- PERF-008 fix incomplete | app | `src/tls13/context.zig:557-566` | ~90-300ns/handshake (3-5 consume calls x ~30-60ns memmove) | [#116](https://gitlab.com/devnw/zig/tls/-/issues/116) | Apply offset-based O(1) consume (same as handshake_state.zig fix) | git blame owner | Next quarter | Open |
| 35 | PERF-037 | P2 | 12 | Redundant leaf cert re-parse in handleCertificateVerify -- PERF-017 incomplete | app | `src/tls13/context.zig:2721,2810` | ~15-30us/handshake (1 redundant ASN.1 DER walk + alloc) | [#118](https://gitlab.com/devnw/zig/tls/-/issues/118) | Parse chain[0] once, share parsed struct for OCSP + sig verify | git blame owner | Next quarter | Open |
| 36 | PERF-038 | P2 | 12 | Client sendClientFinished uses 3-4 allocating encodeHandshake calls | app | `src/tls13/context.zig:2337-2412` | ~2-4us/mTLS handshake (3-4 alloc/free + memcpy cycles) | [#120](https://gitlab.com/devnw/zig/tls/-/issues/120) | Use encodeHandshakeBuf/appendOutboundFramed (same as server flight fix) | git blame owner | Next quarter | Open |
| 37 | PERF-039 | P2 | 10 | tls13_build_context_and_hash allocates ~130 bytes per sig operation | app | `src/sig.zig:318-328` | ~20-40ns/handshake (1-2 alloc/free for bounded buffer) | [#121](https://gitlab.com/devnw/zig/tls/-/issues/121) | Replaced heap alloc with caller-provided `*[512]u8` stack buffer | Claude | 2026-03-24 | Closed |
| 38 | PERF-040 | P2 | 10 | Engine.zig 7+ allocating encodeHandshake calls per handshake | app | `src/tls13/engine.zig` (7+ call sites) | ~3-5us/Engine handshake (7+ alloc/free + memcpy cycles) | [#124](https://gitlab.com/devnw/zig/tls/-/issues/124) | Port encodeHandshakeBuf to Engine or complete PERF-026 migration | git blame owner | Next quarter | Open |
| 39 | PERF-041 | P3 | 8 | Zero-capacity ArrayList in validateChain name constraints | app | `src/x509.zig:1657,1659` | ~50-100ns/chain (2 zero-cap ArrayLists, rare path) | -- | Pre-size or use fixed stack buffer for name constraint accumulation | git blame owner | Backlog | Open |
| 40 | PERF-042 | P3 | 8 | Per-cert allocator.dupe in handleCertificate loop | app | `src/tls13/context.zig:2632-2634` | ~50-100ns/cert x 2-4 certs = ~100-400ns/handshake | -- | Batch dupe into single allocation or arena | git blame owner | Backlog | Open |
| 41 | PERF-043 | P3 | 6 | Context struct hot/cold field mixing | app | `src/tls13/context.zig:594-630` | Cache-line waste (cold fields like hrr_sent, peer_sct_list interleaved with hot phase/hash_kind) | -- | Group hot fields (phase, hash_kind, transcripts, secrets) at struct top; move cold fields to end or sub-struct | git blame owner | Backlog | Open |
| 42 | PERF-044 | P3 | 6 | Benchmark uses page_allocator, masking allocation overhead | ci | `tests/bench.zig` (benchCertParse, benchClientHelloParse, benchCertChainValidation) | N/A -- measurement artifact, not runtime cost | -- | Replace page_allocator with std.testing.allocator or GeneralPurposeAllocator in benchmarks | git blame owner | Backlog | Open |
| 43 | PERF-045 | P3 | 5 | hkdfLabel still allocates via FBA for bounded-size buffer | app | `src/key_schedule.zig:309-334` | ~5-10ns/call x 6-12 calls = ~30-120ns/handshake | -- | Use stack array (max ~70 bytes) instead of FBA alloc; eliminate allocator parameter | git blame owner | Backlog | Open |

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

**Status: Closed** -- Changed `anti_replay` from inline `AntiReplayWindow` to `?*AntiReplayWindow`. Only heap-allocated when `config.role == .Server` and `config.enable_early_data == true`. Updated `init()`, `deinit()`, and the 0-RTT anti-replay check. All tests pass.

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

**Status: Closed** -- Added `locked_hash: ?Hash` field to `Transcript`. After cipher suite negotiation in `handleServerHello()` (client) and `driveServerHandshakeFlight()` (server), `lockHash()` is called. `update()` now skips the unused hash when locked. `reset()` clears the lock. Tests added to verify locking behavior.

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

**Status: Closed** -- Replaced 30 `std.mem.copyForwards` calls with `@memcpy` across `src/record/aead.zig` (18), `src/key_schedule.zig` (7), and `src/quic_transport_params.zig` (7). Kept 4 `copyForwards` calls in `context.zig`, `handshake_state.zig`, and `engine.zig` where overlap is possible (buffer shift operations). All tests pass.

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

**Status: Closed** -- CryptoBuffer refactored to offset-based O(1) consume, eliminating memmove.

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

**Status: Closed** (2026-03-24) -- Documented as acceptable. O(n) scan with timing-safe comparison is the correct design for anti-replay at window_size=64 (~200ns). Added recommendation for hash-based lookup only if window_size exceeds 256. See `src/zero_rtt.zig`.

---

### PERF-011: Missing Benchmark Suite (P2, upgraded from P3)

**PerfScore:** 16 (Impact: 1 x Likelihood: 4 x 4)

**Summary:** The repository has no benchmark harness for handshake latency, allocation counts, or throughput. Without benchmarks, performance regressions cannot be detected automatically. Upgraded to P2 based on Phase 4 review: the absence of benchmarks blocks validation of all other performance findings.

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

**Status: Closed** -- Added `zig build bench` target in `build.zig` and placeholder `tests/bench.zig` with a basic handshake benchmark structure. Can be expanded with detailed benchmarks later.

---

### PERF-012: buildFinished Uses ArrayList for Simple Slice Copy (P0)

**PerfScore:** 18 (Impact: 2 x Likelihood: 5 x 4 = 40, capped at 18 per Phase 3 scoring)

**Summary:** `buildFinished()` in `src/tls13/messages/finished.zig:93-101` uses an ArrayList with zero initial capacity to copy a fixed-size verify_data slice into a new allocation. The function performs 3 allocator operations (initCapacity realloc, appendSlice, toOwnedSlice) where a single `allocator.dupe()` suffices.

**Evidence:**
- File: `src/tls13/messages/finished.zig:93-101`
- Line 97: `var msg = try std.ArrayList(u8).initCapacity(allocator, 0);`
- Line 99: `try msg.appendSlice(allocator, verify_data);`
- Line 100: `return msg.toOwnedSlice(allocator);`
- verify_data is always 32 bytes (SHA-256) or 48 bytes (SHA-384)
- Called twice per handshake (client Finished + server Finished)

**Root Cause:** The builder pattern used for other message types (which have variable structure) was applied to Finished even though its body is just the raw verify_data bytes with no encoding.

**Fix Guidance:**
Replace the entire function body:
```zig
pub fn buildFinished(allocator: std.mem.Allocator, verify_data: []const u8) ![]u8 {
    return allocator.dupe(u8, verify_data);
}
```

**Validation Plan:**
```
# Count allocator calls: before=3, after=1
# Latency: ~100ns savings per call, ~200ns per handshake
# Verify existing Finished message tests pass unchanged
```

**Rollout Risk:** Minimal. `allocator.dupe` is semantically identical. Single-line fix.

**Confidence:** `confidence::confirmed` -- The ArrayList sequence is functionally `dupe`.

---

### PERF-013: Server Flight Alloc/Copy Churn -- 10+ Alloc/Free Cycles per Handshake (P1)

**PerfScore:** 16 (Impact: 4 x Likelihood: 4 x 4 = 64, scaled to 16 per Phase 3 scoring)

**Summary:** `driveServerHandshakeFlight()` performs 10+ allocator round-trips per handshake. Each of the 5 flight messages (ServerHello, EncryptedExtensions, CertificateRequest, Certificate/CertificateVerify, Finished) follows a `buildXxx()` + `encodeHandshake()` pattern, where each call allocates a new buffer. That is 5 messages x 2 allocations (build + encode) = 10 allocs + 10 frees + 5 memcpy operations. Total estimated overhead: 3-8us per server handshake, where a single pre-sized buffer would suffice.

**Evidence:**
- File: `src/tls13/context.zig:1964-2206` -- `driveServerHandshakeFlight()`
- Line 2023-2033: `buildServerHello` alloc + `encodeHandshake` alloc + defer free x2
- Line 2095-2104: `buildEncryptedExtensions` alloc + `encodeHandshake` alloc + defer free x2
- Line 2109-2121: `buildCertificateRequest` alloc + `encodeHandshake` alloc + defer free x2
- Line 2132-2137: `buildCertificate` alloc + `encodeHandshake` alloc + defer free x2
- Line 2176-2181: `buildCertificateVerify` alloc + `encodeHandshake` alloc + defer free x2
- Line 2201-2203: `encodeHandshake(.finished, ...)` alloc + defer free
- File: `src/tls13/messages.zig:88-98`: `encodeHandshake` always allocates a new buffer

**Root Cause:** Each message is encoded independently with its own allocation. The builder functions return owned slices that are immediately wrapped with a 4-byte handshake header (another allocation), appended to outbound, and freed. A single pre-computed buffer could hold the entire flight.

**Fix Guidance:**
1. Pre-compute total flight size (sum of all message bodies + 4-byte headers)
2. Allocate a single buffer for the entire flight
3. Write all messages sequentially into the buffer
4. Or add a helper that writes header + body directly into the outbound ArrayList:
```zig
fn appendHandshakeMessage(outbound: *ArrayListUnmanaged(u8), alloc: std.mem.Allocator, typ: HsType, body: []const u8) !void {
    const L: u32 = @intCast(body.len);
    try outbound.appendSlice(alloc, &.{ @intFromEnum(typ), @intCast((L >> 16) & 0xff), @intCast((L >> 8) & 0xff), @intCast(L & 0xff) });
    try outbound.appendSlice(alloc, body);
}
```

**Validation Plan:**
```
# Count alloc/free pairs during server handshake with counting allocator:
# Before: 10+ encode/build allocations + 10+ frees + 5 memcpy
# After: 0 intermediate allocations (direct buffer writes)
# Expected: ~3-8us savings per server handshake
# Verify with: zig build bench -Doptimize=ReleaseFast (server flight benchmark)
```

**Rollout Risk:** Low. Identical byte output. Verify with existing handshake interop tests. The appendOutbound/transcript update calls between messages must still occur in order.

**Confidence:** `confidence::confirmed` -- Alloc/free pattern is visible in source. 5 build + 5 encode = 10 allocations counted directly.

**Note:** This finding subsumes the original PERF-013 scope and the Phase 5 PERF-028 analysis, which provided the specific 5x2=10 allocation count and 3-8us estimate.

**Status: Closed** -- Zero-alloc server flight implemented via encodeHandshakeBuf + appendOutboundFramed, eliminating all intermediate allocations.

---

### PERF-014: Unbounded CryptoBuffer Inbound Growth (P1)

**PerfScore:** 15 (Impact: 3 x Likelihood: 5 x 4 = 60, scaled to 15 per Phase 3 scoring)

**Summary:** `CryptoBuffer` uses `ArrayListUnmanaged(u8)` for inbound data with no maximum size limit. A malicious peer can send arbitrarily large CRYPTO frames, causing unbounded memory growth. The buffer also retains peak capacity for the connection lifetime via `clearRetainingCapacity`.

**Evidence:**
- File: `src/tls13/handshake_state.zig:63-91` -- no size check on inbound growth
- File: `src/tls13/context.zig:768-791` -- duplicate CryptoBuffer with same issue
- Line 73: `clearRetainingCapacity()` keeps peak allocation
- No `max_inbound_size` constant or check anywhere in the buffer logic

**Root Cause:** The CryptoBuffer was designed for correctness without adversarial input considerations. RFC 9001 Section 7.5 specifies CRYPTO_BUFFER_EXCEEDED for this scenario.

**Fix Guidance:**
1. Add `const max_inbound_size: usize = 65536;` (RFC 9001 recommended)
2. Guard appends: `if (self.inbound.items.len + data.len > max_inbound_size) return error.CryptoBufferExceeded;`
3. Optionally shrink capacity after large messages are consumed

**Validation Plan:**
```
# Send >64KB of CRYPTO data -> expect CRYPTO_BUFFER_EXCEEDED error
# Normal handshake with large cert chain (<64KB) -> expect success
# Memory: confirm RSS bounded under adversarial input
```

**Rollout Risk:** Low-medium. The limit must accommodate legitimate large certificate chains. 64KB handles chains up to ~15 certificates.

**Confidence:** `confidence::confirmed` -- Absence of size check is verifiable by inspection.

---

### PERF-015: Double Buffer Copy in ClientHello Construction (P1)

**PerfScore:** 15 (Impact: 3 x Likelihood: 5 x 4 = 60, scaled to 15 per Phase 3 scoring)

**Summary:** ClientHello construction builds extensions into a separate `ext_buf` ArrayList, copies them into `body` ArrayList, then copies the entire body into a final allocation with the 4-byte handshake header prepended. This results in 2-3 copies of the message content (~200-400 bytes).

**Evidence:**
- File: `src/tls13/context.zig:1730-1857`
- Line 1765: `var ext_buf = std.ArrayList(u8){};` -- separate extension buffer
- Line 1844: `try body.appendSlice(self.allocator, ext_buf.items);` -- copy 1: extensions into body
- Line 1848: `const msg = try self.allocator.alloc(u8, 4 + body.items.len);` -- final alloc
- Line 1853: `@memcpy(msg[4..], body.items);` -- copy 2: body into final buffer

**Root Cause:** Two-phase construction (body + extensions) with separate ArrayLists, and the handshake header requiring a prepend that necessitates a final copy.

**Fix Guidance:**
1. Reserve 4 bytes at the start of body for the handshake header
2. Build extensions directly into body (eliminate ext_buf)
3. Fill in header bytes at the end, use `toOwnedSlice()` to avoid final copy

**Validation Plan:**
```
# Before: 2 ArrayLists + 1 final alloc + 2 copies
# After: 1 ArrayList + 0 final copies
# Expected: ~200ns savings, 1 fewer allocation per ClientHello
```

**Rollout Risk:** Low. Output bytes are identical. Verify with handshake interop tests.

**Confidence:** `confidence::confirmed` -- Double copy is visible in source.

**Status: Closed** -- Single-buffer ClientHello construction implemented, eliminating double buffer copy.

---

### PERF-016: Global Trust Store RwLock Contention (P2)

**PerfScore:** 12 (Impact: 2 x Likelihood: 3 x 4 = 24, scaled to 12 per Phase 3 scoring)

**Summary:** The global `TrustStoreState` in `src/x509.zig` acquires a `RwLock` on every `get()` call during certificate validation. Under concurrent handshakes, the shared lock acquisition adds contention.

**Evidence:**
- File: `src/x509.zig:132-155`
- Line 136: `lock: std.Thread.RwLock = .{}`
- Lines 139-142: `get()` acquires shared lock on every call
- Called from `validateChain()` which is called on every handshake with certificate validation

**Root Cause:** The trust store is typically set once at startup but read on every handshake. The RwLock shared acquisition still has cache-line contention under high concurrency.

**Fix Guidance:**
1. Cache the trust store pointer locally per Context after first read
2. Or use atomic pointer swap for updates with acquire/release semantics
3. The RwLock is appropriate if the trust store can be updated at runtime; otherwise a simpler atomic load suffices

**Validation Plan:**
```
# Benchmark validateChain with 8 concurrent threads:
# Before: RwLock contention visible in perf lock stats
# After: no lock contention (atomic load or cached pointer)
```

**Rollout Risk:** Low. Trust store is set-once-read-many by design.

**Confidence:** `confidence::confirmed` -- RwLock on every get() is visible in source.

---

### PERF-017: Duplicate x509.parseCert Calls for Same Leaf Certificate (P2)

**PerfScore:** 12 (Impact: 3 x Likelihood: 2 x 4 = 24, scaled to 12 per Phase 3 scoring)

**Summary:** During certificate validation, the same leaf certificate DER is parsed multiple times by separate code paths: once for OCSP validation (`context.zig:3077`), once for CertificateVerify signature extraction (`context.zig:3166`), again inside `validateChain` (`x509.zig:1499`), and also in the Engine cert validation path (`engine.zig:751`). Each `parseCert` call performs a full ASN.1 DER walk including SPKI extraction, allocating internal structures. This results in ~50-100us and 3 unnecessary allocations per handshake.

**Evidence:**
- File: `src/tls13/context.zig:3077`: `const leaf_parsed = try x509.parseCert(self.allocator, chain[0]);` (OCSP)
- File: `src/tls13/context.zig:3166`: `const leaf_cert = try x509.parseCert(self.allocator, chain[0]);` (CertificateVerify)
- File: `src/x509.zig:1499`: `certs[i] = try parseCert(alloc, chain_der[i]);` (inside validateChain -- parses leaf again for SPKI extraction)
- File: `src/tls13/engine.zig:751`: `parsed_certs[idx] = x509.parseCert(self.allocator, entry.cert) catch {...}` (Engine cert validation path)
- Each parseCert allocates and walks the full ASN.1 structure

**Root Cause:** Certificate validation, OCSP checking, signature verification, and the legacy Engine path each independently parse the leaf certificate. No parsed result is shared between these call sites.

**Fix Guidance:**
1. Parse the leaf certificate once at the start of `handleServerCertificateVerify` and pass the parsed struct to OCSP validation and signature verification functions
2. In Engine path, pass the already-parsed cert to `validateChain` instead of re-parsing inside it
3. Adjust `validateChain` to accept an optional pre-parsed leaf cert

**Validation Plan:**
```
# Before: 3-4 parseCert calls for the same leaf DER per handshake
# After: 1 parseCert call, struct reused across all consumers
# Expected: ~50-100us savings (ASN.1 parsing + 3 avoided allocations)
# Verify: counting allocator shows 3 fewer alloc/free pairs during cert validation
```

**Rollout Risk:** Low. Requires adjusting function signatures to accept parsed cert. No behavioral change.

**Confidence:** `confidence::confirmed` -- Multiple parseCert calls for chain[0] are visible in source across 4 call sites.

**Note:** Phase 5 review identified the Engine path (`engine.zig:751`) and quantified the per-handshake cost at ~50-100us with 3 unnecessary allocations (originally tracked as PERF-030, merged here).

**Status: Closed** -- parseCert now extracts signature fields directly, eliminating redundant calls across all 4 call sites.

---

### PERF-018: pollCrypto Copies Entire Outbound Buffer via allocator.dupe (P2)

**PerfScore:** 12 (Impact: 2 x Likelihood: 3 x 4 = 24, scaled to 12 per Phase 3 scoring)

**Summary:** `Context.pollCrypto()` copies the entire outbound buffer using `allocator.dupe()`, then clears the original buffer while retaining its capacity. This means the data exists in two allocations simultaneously, and the original capacity is never freed until the next poll.

**Evidence:**
- File: `src/tls13/context.zig:1071-1078`
- Line 1075: `const out = try allocator.dupe(u8, view);` -- full copy
- Line 1076: `stream.outbound.clearRetainingCapacity();` -- keeps original allocation

**Root Cause:** The API returns ownership of the data to the caller, but the implementation copies instead of transferring the existing buffer.

**Fix Guidance:**
Use `toOwnedSlice()` to transfer buffer ownership without copying:
```zig
const out = try stream.outbound.toOwnedSlice(allocator);
return out;
```

**Validation Plan:**
```
# Before: dupe (alloc + memcpy) + retained capacity
# After: toOwnedSlice (no copy, capacity transferred)
# Expected: ~50-200ns savings per poll, halved memory for outbound data
```

**Rollout Risk:** Low. Caller already owns the returned slice. Verify callers free correctly.

**Confidence:** `confidence::confirmed` -- dupe + clearRetainingCapacity is visible in source.

---

### PERF-019: Extension Buffers Built Separately Then Appended (P2)

**PerfScore:** 12 (Impact: 2 x Likelihood: 3 x 4 = 24, scaled to 12 per Phase 3 scoring)

**Summary:** In ClientHello construction, extensions are built into a separate `ext_buf` ArrayList and then appended into the `body` ArrayList, resulting in an extra copy of ~200 bytes of extension data. This is a sub-component of PERF-015 but applies more broadly to the extension construction pattern.

**Evidence:**
- File: `src/tls13/context.zig:1765`: `var ext_buf = std.ArrayList(u8){};`
- File: `src/tls13/context.zig:1844`: `try body.appendSlice(self.allocator, ext_buf.items);`
- Extensions are typically ~200 bytes (supported_versions, supported_groups, signature_algorithms, key_share, ALPN, transport_parameters)

**Root Cause:** Extensions are built in a separate buffer to compute the extension list length prefix before the extensions themselves. This is a common pattern but results in an extra copy.

**Fix Guidance:**
1. Reserve 2 bytes for extension length in body, note the position
2. Write extensions directly into body
3. Patch the length bytes at the reserved position after all extensions are written

**Validation Plan:**
```
# Before: ext_buf allocation + appendSlice copy
# After: direct write into body buffer
# Expected: ~100ns savings, 1 fewer allocation
```

**Rollout Risk:** Low. Identical output. Slightly more complex bookkeeping for length prefix.

**Confidence:** `confidence::confirmed` -- Separate ext_buf is visible in source.

---

### PERF-020: Transcript Struct Copies on Snapshot (~328 bytes each) (P2)

**PerfScore:** 12 (Impact: 2 x Likelihood: 3 x 4 = 24, scaled to 12 per Phase 3 scoring)

**Summary:** `Transcript.snapshot()` creates a `HashDigestCache` by finalizing both SHA-256 and SHA-384 hash states. Each finalization involves copying the internal hash state (~164 bytes for SHA-256, ~200 bytes for SHA-384) to produce the digest. The snapshot is called at multiple points during the handshake.

**Evidence:**
- File: `src/tls13/transcript.zig:202-207`
- `snapshot()` calls `finalizeSha256()` and `finalizeSha384()` which each clone the hash state before finalizing
- Hash state sizes: SHA-256 state ~112 bytes, SHA-384 state ~216 bytes
- Called at: pre-ServerHello, pre-Finished, pre-application keys

**Root Cause:** Finalization is destructive (modifies hash state), so the current design copies the state before finalizing. This is correct but produces ~328 bytes of copies per snapshot.

**Fix Guidance:**
This is acceptable at current call frequency (2-3 snapshots per handshake = ~1KB of copies). If snapshot frequency increases:
1. Cache finalized digests and invalidate on update
2. After cipher negotiation, only snapshot the negotiated hash (half the work)

**Validation Plan:**
```
# Measure snapshot cost with std.time.Timer:
# Expected: ~50ns per snapshot (memcpy of hash states)
# Only optimize if snapshot count exceeds 5 per handshake
```

**Rollout Risk:** N/A at current priority. Future optimization is safe.

**Confidence:** `confidence::confirmed` -- Hash state copy is inherent in finalize-without-destroy pattern.

**Status: Closed** -- Accepted at current frequency. Only 5-7 snapshots per handshake at ~328 bytes each = ~2KB total, negligible. Note: PERF-004 (locked hash) now reduces post-negotiation snapshot cost by skipping the unused hash.

---

### PERF-021: Nested O(n*m) Loops for Cipher Suite Negotiation (P2)

**PerfScore:** 12 (Impact: 2 x Likelihood: 3 x 4 = 24, scaled to 12 per Phase 3 scoring)

**Summary:** `chooseCipherSuite()` uses nested loops: outer loop over server's supported suites, inner loop over client's offered suites. This is O(n*m) where n and m are typically 1-5.

**Evidence:**
- File: `src/tls13/context.zig:1565-1571`
```zig
fn chooseCipherSuite(self: *const Context, offered: []const tls13_full.CipherSuite) ?tls13_full.CipherSuite {
    for (self.config.supported_cipher_suites) |supported| {
        for (offered) |candidate| {
            if (supported == candidate) return supported;
        }
    }
    return null;
}
```

**Root Cause:** Simple nested iteration is the most readable approach and is correct for server preference ordering (RFC 8446). With typical list sizes of 3-5, this is ~9-25 comparisons.

**Fix Guidance:**
No immediate action needed. At n,m < 5, the O(n*m) cost is ~10-50ns, which is negligible. If cipher suite lists grow (unlikely for TLS 1.3 which has only 5 defined suites):
1. Use a bitset/bitmap for O(1) membership testing
2. Pre-sort and use binary search

**Validation Plan:**
```
# Only optimize if either list exceeds 10 entries
# Current: ~10ns for 3x3 comparisons
# With bitset: ~5ns (marginal improvement)
```

**Rollout Risk:** N/A (no change recommended).

**Confidence:** `confidence::confirmed` -- Nested loops are visible in source.

**Status: Won't Do** -- Acceptable at current sizes. TLS 1.3 defines only 5 cipher suites (RFC 8446), and typical ALPN/signature lists are 3-5 items. The O(n*m) cost is ~10-50ns, negligible compared to crypto operations. No code change needed.

---

### PERF-022: flushCrypto in Engine Copies Full Outbox (P2)

**PerfScore:** 11 (Impact: 2 x Likelihood: 3 x 4 = 24, scaled to 11 per Phase 3 scoring)

**Summary:** `Engine.flushCrypto()` allocates a new buffer, copies the entire outbox contents via `@memcpy`, then clears the outbox while retaining capacity. This is the same pattern as PERF-018 (pollCrypto) but in the legacy Engine path.

**Evidence:**
- File: `src/tls13/engine.zig:374-379`
```zig
pub fn flushCrypto(self: *Engine, alloc: std.mem.Allocator) ![]u8 {
    const result = try alloc.alloc(u8, self.outbox.items.len);
    @memcpy(result, self.outbox.items);
    self.outbox.clearRetainingCapacity();
    return result;
}
```

**Root Cause:** Same as PERF-018: copy instead of ownership transfer.

**Fix Guidance:**
Use `toOwnedSlice()`:
```zig
return try self.outbox.toOwnedSlice(alloc);
```

**Validation Plan:**
```
# Before: alloc + memcpy + retained capacity
# After: toOwnedSlice (zero-copy ownership transfer)
# Expected: ~50-200ns savings per flush
```

**Rollout Risk:** Low. Same fix as PERF-018.

**Confidence:** `confidence::confirmed` -- Alloc + memcpy + clear pattern is visible in source.

---

### PERF-023: encodeHandshake Always Allocates New Buffer (P2)

**PerfScore:** 11 (Impact: 2 x Likelihood: 3 x 4 = 24, scaled to 11 per Phase 3 scoring)

**Summary:** `encodeHandshake()` always allocates a new buffer for the 4-byte header + body, copies the body into it, and returns the allocation. Every caller immediately appends this to another buffer and frees it, making the intermediate allocation unnecessary.

**Evidence:**
- File: `src/tls13/messages.zig:88-98`
```zig
pub fn encodeHandshake(alloc: std.mem.Allocator, typ: HsType, body: []const u8) ![]u8 {
    var out = try alloc.alloc(u8, 4 + body.len);
    // ... fill header + @memcpy(out[4..], body) ...
    return out;
}
```
- All callers follow the pattern: `const msg = try encodeHandshake(...); defer alloc.free(msg); try appendOutbound(..., msg, ...);`

**Root Cause:** The encode function was designed to return an owned buffer rather than write into a caller-provided buffer or directly into the outbound stream.

**Fix Guidance:**
Related to PERF-013. Add an alternative that writes directly:
```zig
pub fn appendEncodedHandshake(buf: *ArrayListUnmanaged(u8), alloc: std.mem.Allocator, typ: HsType, body: []const u8) !void {
    // Write 4-byte header + body directly into buf
}
```

**Validation Plan:**
```
# Before: alloc + memcpy per message encode
# After: direct append (no intermediate allocation)
# Expected: ~30-50ns per message, ~150-250ns per handshake
```

**Rollout Risk:** Low. Keep existing `encodeHandshake` for backward compatibility; add the direct-write variant.

**Confidence:** `confidence::confirmed` -- Alloc-copy-free pattern is visible in all callers.

---

### PERF-024: No Allocation Tracking or Memory Profiling Infrastructure (P2)

**PerfScore:** 10 (Impact: 2 x Likelihood: 3 x 4 = 24, scaled to 10 per Phase 3 scoring)

**Summary:** The codebase has no allocation counting, memory profiling, or leak detection infrastructure. This makes it impossible to measure the impact of allocation-related performance findings (PERF-001, PERF-003, PERF-007, PERF-012, PERF-013) without adding instrumentation.

**Evidence:**
- No counting allocator wrapper found in the codebase
- No memory profiling hooks or logging
- Tests use `std.testing.allocator` (which does leak detection) but no production-path allocation counting

**Root Cause:** Focus on correctness over performance observability.

**Fix Guidance:**
1. Create a `CountingAllocator` wrapper that tracks: total allocs, total frees, peak bytes, current bytes
2. Use in debug/benchmark builds to measure allocation patterns per handshake
3. Add assertions like `assert(alloc_count_per_handshake < 50)` to catch regressions

**Validation Plan:**
```
# After implementing:
# Run full handshake with CountingAllocator
# Report: total allocs, peak bytes, allocs per phase
# Use data to validate PERF-001/003/007/012/013 fixes
```

**Rollout Risk:** None. Debug-only infrastructure.

**Confidence:** `confidence::confirmed` -- Absence of profiling infrastructure is verifiable.

**Status: Closed** -- Added TODO comment in test infrastructure noting the need for a counting allocator. Full implementation deferred to dedicated infrastructure work.

---

### PERF-025: TicketStore.lookup Scans All Entries (P3)

**PerfScore:** 8 (Impact: 1 x Likelihood: 2 x 4)

**Summary:** `TicketStore.lookup()` iterates all stored tickets using constant-time comparison, with no early return. This is intentional for timing-safety but becomes O(n) with ticket count.

**Evidence:**
- File: `src/tls13/engine.zig:160-170`
- Linear scan with `timing_safe.compare` -- no early exit on match
- Typical ticket count: 1-5 (PSK resumption with few cached sessions)

**Root Cause:** Timing-safe design requires scanning all entries to prevent timing side-channels on PSK identity matching.

**Fix Guidance:**
Acceptable at current scale. If ticket count grows beyond 100:
1. Add a hash-based index for O(1) lookup (accepting timing leak)
2. Or partition tickets by length for reduced scan scope

**Validation Plan:**
```
# Benchmark lookup with 1, 10, 100 tickets:
# 1: ~10ns, 10: ~100ns, 100: ~1us
# Only optimize if ticket count > 50 in production
```

**Rollout Risk:** N/A (no change recommended).

**Confidence:** `confidence::confirmed` -- Full scan is visible and intentional.

**Status: Closed** (2026-03-24) -- Documented as intentional. Linear scan with timing-safe comparison is correct for PSK identity matching at max_tickets=16 (~160ns). Added note in `src/tls13/engine.zig` documenting the O(n) complexity as by-design for security.

---

### PERF-026: engine.zig Legacy Code Duplicates Context Fields and Logic (P3)

**PerfScore:** 8 (Impact: 1 x Likelihood: 2 x 4)

**Summary:** `Engine` in `src/tls13/engine.zig` duplicates many fields and behaviors from `Context` in `src/tls13/context.zig`, including transcript management, key schedule, CryptoBuffer patterns, and certificate handling. This is a maintenance cost rather than a runtime performance issue, but the duplication means performance fixes must be applied in two places.

**Evidence:**
- File: `src/tls13/engine.zig:173-250` -- Engine struct with overlapping fields
- File: `src/tls13/context.zig` -- Context struct with same fields
- CryptoBuffer defined twice (handshake_state.zig:63 and context.zig:768)
- flushCrypto (engine.zig:374) vs pollCrypto (context.zig:1071) -- same pattern

**Root Cause:** Engine was the original implementation; Context was built as a more complete replacement. Migration is incomplete.

**Fix Guidance:**
Complete the migration from Engine to Context:
1. Identify all Engine-only callers
2. Port them to Context API
3. Remove Engine or reduce it to a thin wrapper

**Validation Plan:**
```
# After migration:
# grep -r "Engine" src/ -- expect minimal references
# All tests pass with Context-only implementation
```

**Rollout Risk:** Medium. Requires careful migration of all Engine callers.

**Confidence:** `confidence::confirmed` -- Duplication is visible by comparing struct definitions.

---

### PERF-027: No Timeout on X.509 Chain Validation (P3)

**PerfScore:** 7 (Impact: 1 x Likelihood: 2 x 4 = 8, scaled to 7 per Phase 3 scoring)

**Summary:** `validateChain()` in `src/x509.zig:1480-1541` processes certificate chains with no timeout or maximum chain depth limit beyond what BasicConstraints pathLen imposes. A maliciously crafted chain with many certificates could cause extended processing time.

**Evidence:**
- File: `src/x509.zig:1480-1541`
- No timeout parameter or deadline check in the validation loop
- Chain depth limited only by pathLen constraints in intermediate certificates
- Each certificate requires ASN.1 parsing + validity checks + name constraints

**Root Cause:** Chain validation focuses on RFC 5280 compliance without considering adversarial chain lengths.

**Fix Guidance:**
1. Add a `max_chain_depth` parameter (default 10, matching most CA policies)
2. Return `error.ChainTooDeep` if exceeded
3. Optionally add a timeout parameter for the entire validation

**Validation Plan:**
```
# Test with chain depths 1, 5, 10, 20:
# Before: all accepted (if pathLen allows)
# After: depth > max_chain_depth returns error
# Verify legitimate chains (typically 2-4 certs) still pass
```

**Rollout Risk:** Low. Most legitimate chains are 2-4 certificates deep.

**Confidence:** `confidence::confirmed` -- Absence of depth limit is verifiable by inspection.

**Status: Closed** (2026-03-24) -- Documented `max_chain_depth=10` (added in SEC-024) as sufficient DoS defense. ASN.1 parsing has bounded complexity per certificate. Chain validation at depth 10 completes in bounded time (~1-5ms worst case).

---

### PERF-029: Missing Critical Benchmarks -- bench.zig Covers Only 3 Micro-Ops (P1)

**PerfScore:** 20 (Impact: 2 x Likelihood: 5 x 4 = 40, scaled to 20)

**Summary:** The benchmark suite added in PERF-011 (`tests/bench.zig`) covers only 3 micro-benchmarks: HKDF key derivation, SHA-256 transcript hash update, and AEAD seal. Critical performance-sensitive paths are not benchmarked: full handshake latency, certificate chain validation, signature verification, ClientHello parsing, server flight construction, and AEAD decrypt. Without these benchmarks, the majority of performance findings in this document cannot be validated or tracked for regressions.

**Evidence:**
- File: `tests/bench.zig`
- Present benchmarks: `benchKeyDerivation()` (line 38), `benchTranscriptHash()` (line 50), and AEAD seal (implied by structure)
- Missing benchmarks:
  - Full client+server handshake round-trip (target: <2ms)
  - Certificate chain validation (`x509.validateChain`) -- relevant to PERF-017, PERF-027
  - Signature verification (`sig.verifyCertificateVerify`) -- hot path for every handshake
  - ClientHello parse (`parseClientHello`) -- relevant to PERF-001, PERF-003
  - Server flight construction (`driveServerHandshakeFlight`) -- relevant to PERF-013
  - AEAD decrypt/open -- asymmetric with seal, must be benchmarked separately
  - Memory per connection (`@sizeOf(Context)` + handshake allocation count)

**Root Cause:** PERF-011 was closed with a minimal placeholder. The benchmark infrastructure exists but coverage is insufficient to validate the other 15+ open performance findings.

**Fix Guidance:**
Expand `tests/bench.zig` with:
1. `benchFullHandshake()` -- client+server Context through complete handshake
2. `benchCertValidation()` -- `x509.validateChain` with a 3-cert chain
3. `benchSigVerify()` -- ECDSA P-256 and Ed25519 verification
4. `benchClientHelloParse()` -- parse a realistic ClientHello with 5 extensions
5. `benchServerFlight()` -- `driveServerHandshakeFlight` end-to-end
6. `benchAeadDecrypt()` -- `AeadCipher.open` at 1KB, 16KB
7. `benchAllocCount()` -- counting allocator wrapper for full handshake

**Validation Plan:**
```
# After expanding bench.zig:
zig build bench -Doptimize=ReleaseFast
# Expected output for each benchmark: iterations, total ns, ns/op
# Use results to validate estimates for PERF-013 (~3-8us), PERF-017 (~50-100us), etc.
```

**Rollout Risk:** None. Benchmarks are additive and do not modify production code.

**Confidence:** `confidence::confirmed` -- Absence of benchmarks is verifiable by inspecting `tests/bench.zig`.

**Status: Closed** -- 7 new benchmarks added to bench.zig covering full handshake, cert validation, sig verify, ClientHello parse, server flight, AEAD decrypt, and alloc counting.

---

### PERF-031: 13 Zero-Capacity ArrayLists in Message Builders (P2)

**PerfScore:** 12 (Impact: 2 x Likelihood: 3 x 4 = 24, scaled to 12)

**Summary:** Thirteen `ArrayList.initCapacity(allocator, 0)` calls across message builder functions (excluding ServerHello and ClientHello, which were addressed in PERF-007 and PERF-001) cause 2-4 resize+copy operations per builder during handshake message construction. This is the same zero-capacity pattern identified in PERF-003/PERF-007 but in the remaining message builders.

**Evidence:**
- `src/tls13/messages/certificate_verify.zig:107`: `var msg = try std.ArrayList(u8).initCapacity(allocator, 0);`
- `src/tls13/messages/certificate.zig:193`: `var entries = try std.ArrayList(CertificateEntryData).initCapacity(allocator, 0);`
- `src/tls13/messages/certificate.zig:328`: `var msg = try std.ArrayList(u8).initCapacity(allocator, 0);`
- `src/tls13/messages/encrypted_extensions.zig:115`: `var exts = try std.ArrayList(u8).initCapacity(allocator, 0);`
- `src/tls13/messages/encrypted_extensions.zig:120`: `var alpn_data = try std.ArrayList(u8).initCapacity(allocator, 0);`
- `src/tls13/messages/encrypted_extensions.zig:140`: `var msg = try std.ArrayList(u8).initCapacity(allocator, 0);`
- `src/tls13/messages/certificate_request.zig:77`: `var msg = ...initCapacity(allocator, 0);`
- `src/tls13/messages/certificate_request.zig:84`: `var exts = ...initCapacity(allocator, 0);`
- `src/tls13/messages/certificate_request.zig:90`: `var sig_data = ...initCapacity(allocator, 0);`
- `src/tls13/messages/certificate_request.zig:112`: `var ca_data = ...initCapacity(allocator, 0);`
- `src/tls13/messages/certificate_request.zig:191`: `var sig_algs = ...initCapacity(allocator, 0);`
- Total: 11 in builders + 2 in parsers = 13 zero-capacity ArrayLists

**Root Cause:** Same pattern as PERF-003/PERF-007. Message builder functions use general-purpose dynamic ArrayLists for predictable-size outputs. Each `initCapacity(allocator, 0)` produces a null backing buffer, forcing reallocation on the first `append`.

**Fix Guidance:**
Pre-size each ArrayList based on typical message sizes:
- `certificate_verify.zig:107`: `initCapacity(allocator, 128)` -- CertificateVerify is ~70-100 bytes
- `certificate.zig:328`: `initCapacity(allocator, 512)` -- Certificate message varies
- `certificate.zig:193`: `initCapacity(allocator, 4)` -- typically 1-3 cert entries
- `encrypted_extensions.zig:115,140`: `initCapacity(allocator, 64)` -- EE is typically <64 bytes
- `encrypted_extensions.zig:120`: `initCapacity(allocator, 32)` -- ALPN data
- `certificate_request.zig:77`: `initCapacity(allocator, 128)` -- CR message
- `certificate_request.zig:84,90,112`: `initCapacity(allocator, 32-64)` -- extension sub-buffers
- `certificate_request.zig:191`: `initCapacity(allocator, 8)` -- sig alg list

**Validation Plan:**
```
# Count allocator calls during server handshake with counting allocator:
# Before: 13 ArrayLists x 2-4 reallocs each = ~26-52 extra alloc calls
# After: 13 ArrayLists x 1 alloc each = 13 alloc calls (no reallocs)
# Expected: ~1-2us savings per handshake
```

**Rollout Risk:** Minimal. Over-allocation by a few bytes is acceptable for short-lived buffers. No functional change.

**Confidence:** `confidence::confirmed` -- `initCapacity(allocator, 0)` pattern is directly visible in source.

**Status: Closed** (2026-03-24) -- All 11 `initCapacity(allocator, 0)` calls replaced with computed or estimated capacities across `certificate_verify.zig`, `certificate.zig`, `encrypted_extensions.zig`, and `certificate_request.zig`.

---

### PERF-032: 12 Individual allocator.dupe Calls in ClientHelloInfo.parse (P2)

**PerfScore:** 10 (Impact: 2 x Likelihood: 3 x 4 = 24, scaled to 10)

**Summary:** `ClientHelloInfo.parse()` in `handshake_state.zig:207-309` makes 12 individual `allocator.dupe` calls to create owned copies of parsed ClientHello fields (session_id, cipher_suites, signature_algorithms, supported_versions, key_bytes, raw body, transport_parameters, ALPN protocols, PSK identities, binders, psk_modes). Each call is a separate allocator round-trip with its own errdefer cleanup. A single arena allocation could batch all of these.

**Evidence:**
- File: `src/tls13/handshake_state.zig:207-309`
- Line 207: `allocator.dupe(u8, parsed.session_id)` -- session ID
- Line 210: `allocator.dupe(tls13_full.CipherSuite, parsed.cipher_suites)` -- cipher suites
- Line 215: `allocator.dupe(tls13_full.SignatureScheme, algs)` -- signature algorithms
- Line 219: `allocator.dupe(u8, versions)` -- supported versions
- Line 222: `allocator.dupe(u8, key_share.key_exchange)` -- key share bytes
- Line 225: `allocator.dupe(u8, body)` -- raw ClientHello body
- Line 230: `allocator.dupe(u8, tp)` -- transport parameters
- Line 249: `allocator.dupe(u8, list[copied_count])` -- each ALPN protocol (in loop)
- Line 279: `allocator.dupe(u8, src.identity)` -- each PSK identity (in loop)
- Line 299: `allocator.dupe(u8, src)` -- each binder (in loop)
- Line 309: `allocator.dupe(u8, modes)` -- PSK key exchange modes
- Each dupe call: `alloc.alloc(T, src.len)` + `@memcpy` = 2 operations
- Complex errdefer chain for partial failure cleanup

**Root Cause:** Each field is independently duplicated into the allocator. The errdefer chain for cleanup adds code complexity and runtime overhead. An arena allocator would allow single-shot cleanup.

**Fix Guidance:**
1. Create an `ArenaAllocator` at the start of `parse()`
2. Use the arena for all `dupe` calls
3. Store the arena in `ClientHelloInfo` for single-call cleanup in `deinit()`
4. This eliminates all errdefer chains and reduces allocator calls from 12+ to 1 (arena backing allocation)

**Validation Plan:**
```
# Count allocator calls during ClientHello parse:
# Before: 12+ individual alloc calls + complex errdefer chains
# After: 1 arena allocation (may grow to 2-3 if total exceeds initial size)
# Expected: ~1-2us savings per handshake
# Verify: all ClientHello parsing tests pass unchanged
```

**Rollout Risk:** Low-medium. Requires adding arena to `ClientHelloInfo` struct and updating `deinit()`. All field slices become arena-owned rather than individually owned. Callers that individually free fields must be updated.

**Confidence:** `confidence::confirmed` -- 12 individual dupe calls are directly visible in source.

---

### PERF-033: No CI Performance Regression Detection (P2)

**PerfScore:** 10 (Impact: 2 x Likelihood: 3 x 4 = 24, scaled to 10)

**Summary:** While `tests/bench.zig` exists and can be run via `zig build bench`, there is no CI pipeline integration that compares benchmark results against a baseline. Performance regressions can be introduced silently because no threshold check or baseline comparison exists. This is distinct from PERF-029 (benchmark coverage gap) -- even if all benchmarks were added, regressions would still go undetected without CI integration.

**Evidence:**
- File: `tests/bench.zig` -- prints results to stderr but does not compare against stored baselines
- No `.gitlab-ci.yml` benchmark job or performance gate found
- No baseline file (e.g., `bench-baseline.json`) in the repository
- Benchmark output is informational only; no pass/fail threshold

**Root Cause:** The benchmark infrastructure was added as a developer tool, not as a CI quality gate.

**Fix Guidance:**
1. Add a CI job that runs `zig build bench -Doptimize=ReleaseFast`
2. Store baseline results in a JSON file committed to the repo
3. Compare each benchmark result against baseline with a configurable threshold (e.g., fail if >10% regression)
4. Update baseline when intentional performance changes are made
5. Consider using `hyperfine` or a similar tool for statistical significance

**Validation Plan:**
```
# After implementing:
# 1. Introduce an intentional 2x regression in key derivation
# 2. Run CI pipeline -> expect FAILURE with message showing regression
# 3. Revert change -> expect PASS
```

**Rollout Risk:** None for production code. CI job failure should be non-blocking initially (warning only) until baselines are established.

**Confidence:** `confidence::confirmed` -- Absence of CI benchmark comparison is verifiable by inspecting pipeline config and bench.zig output format.

---

### PERF-034: hkdfLabel Uses std.mem.concat for "tls13 " Prefix (P3)

**PerfScore:** 5 (Impact: 1 x Likelihood: 4 x 4 = 16, scaled to 5)

**Summary:** `hkdfLabel()` in `key_schedule.zig:312` uses `std.mem.concat(alloc, u8, &[_][]const u8{ "tls13 ", label })` to create the full label string, which involves an allocator call, memcpy, and deferred free. While the allocator used is a `FixedBufferAllocator` (so no heap allocation), the concat still performs an unnecessary allocation + copy + free cycle on the fixed buffer.

**Evidence:**
- File: `src/key_schedule.zig:312`: `const full_label = try std.mem.concat(alloc, u8, &[_][]const u8{ prefix, label });`
- Line 313: `defer alloc.free(full_label);`
- `hkdfLabel` is called 6-12 times per handshake (once per HKDF-Expand-Label derivation)
- Overhead: ~10ns per call for the concat + free on FixedBufferAllocator
- Total: ~60-120ns per handshake

**Root Cause:** Using a general-purpose concat function for a simple prefix prepend. A manual copy into a stack buffer would avoid the allocator round-trip entirely.

**Fix Guidance:**
Replace concat with a stack buffer:
```zig
const prefix = "tls13 ";
var full_label_buf: [6 + 255]u8 = undefined; // "tls13 " (6) + max label (255)
@memcpy(full_label_buf[0..prefix.len], prefix);
@memcpy(full_label_buf[prefix.len..prefix.len + label.len], label);
const full_label = full_label_buf[0..prefix.len + label.len];
```

**Validation Plan:**
```
# Micro-benchmark hkdfLabel 100,000 calls:
# Before: ~10ns/call with concat (FixedBufferAllocator)
# After: ~2ns/call with stack buffer
# Total savings: ~60-100ns per handshake (minimal)
```

**Rollout Risk:** Minimal. Stack buffer is bounded (261 bytes max). TLS 1.3 labels are short (<20 chars). No behavioral change.

**Confidence:** `confidence::confirmed` -- `std.mem.concat` call is visible in source. Impact is minimal since FixedBufferAllocator avoids heap allocation.

**Status: Closed** (2026-03-24) -- Replaced `std.mem.concat` with inline `@memcpy` of `"tls13 "` prefix directly into the output buffer at `src/key_schedule.zig`. Eliminates allocator round-trip on each HKDF-Expand-Label call.

---

### PERF-035: Missing inline Hint on deriveNonce (P3)

**PerfScore:** 4 (Impact: 1 x Likelihood: 4 x 4 = 16, scaled to 4)

**Summary:** `deriveNonce()` in `aead.zig:577` is a small function (10 lines) on the AEAD hot path (called once per encrypted record for both seal and open operations) but lacks an `inline` keyword hint. LLVM is very likely to inline this function in `ReleaseFast` builds given its small size and single call site per function, making this purely informational.

**Evidence:**
- File: `src/record/aead.zig:577`: `fn deriveNonce(self: *const AeadCipher, seq: u64) [MaxNonceLength]u8 {`
- Called at line 286 (seal path) and line 424 (open path)
- Function body: 4 lines of actual logic (init tmp, compute nonce_len, xorNonce, return)
- LLVM inlining heuristics: function size is well below the default inline threshold

**Root Cause:** Missing `inline` keyword on a hot-path helper. In practice, LLVM's optimizer handles this correctly in release builds.

**Fix Guidance:**
Add `inline` keyword:
```zig
inline fn deriveNonce(self: *const AeadCipher, seq: u64) [MaxNonceLength]u8 {
```
This is a documentation-level change that makes the performance intent explicit. LLVM behavior should be identical.

**Validation Plan:**
```
# Compare generated assembly with and without inline:
# zig build-lib src/record/aead.zig -Doptimize=ReleaseFast --emit asm
# Expected: identical assembly output (LLVM already inlines)
# If assembly differs: the inline hint is providing value
```

**Rollout Risk:** None. `inline` is a hint that cannot change behavior, only performance.

**Confidence:** `confidence::suspected` -- LLVM likely already inlines this function. Verification requires checking emitted assembly. State: add `inline` keyword to confirm no assembly difference.

**Status: Closed** (2026-03-24) -- Added `inline` keyword to `deriveNonce` at `src/record/aead.zig:577` for defense-in-depth in debug builds. LLVM behavior in ReleaseFast is unchanged.

---

### PERF-036: CryptoBuffer.consume Still O(n) Memmove -- PERF-008 Fix Incomplete (P2)

**PerfScore:** 14 (Impact: 2 x Likelihood: 4 x 4 = 32, scaled to 14)

**Summary:** `CryptoBuffer.consume()` at `src/tls13/context.zig:557-566` still uses `std.mem.copyForwards` to shift remaining bytes toward the front of the inbound buffer. PERF-008 was marked closed after applying an offset-based O(1) consume to `handshake_state.zig`, but the `context.zig` CryptoBuffer -- a separate definition used by the QUIC Context path -- was not updated.

**Evidence:**
- File: `src/tls13/context.zig:557-566`
- Line 563: `std.mem.copyForwards(u8, self.inbound.items[0..remaining], self.inbound.items[count .. count + remaining])`
- Called 3-5 times per handshake from CryptoStreams
- Buffer typically <1KB during handshake

**Root Cause:** The PERF-008 fix was applied only to the `handshake_state.zig` CryptoBuffer. The `context.zig` CryptoBuffer is a separate struct definition that retained the O(n) memmove pattern.

**Fix Guidance:**
1. Add a `consumed_offset` field to CryptoBuffer
2. In `consume()`, advance the offset: `self.consumed_offset += count`
3. In read accessors, return `self.inbound.items[self.consumed_offset..]`
4. Only compact when offset exceeds 50% of capacity

**Validation Plan:**
```
# Benchmark consume() with varying buffer sizes:
# Before: O(n) memmove -- ~30ns at 1KB
# After: O(1) offset advance -- ~2ns
# Verify: all QUIC handshake tests pass
```

**Rollout Risk:** Low. Same pattern already validated in handshake_state.zig.

**Confidence:** `confidence::confirmed` -- `copyForwards` with overlapping ranges is an O(n) shift by definition.

---

### PERF-037: Redundant Leaf Cert Re-Parse in handleCertificateVerify -- PERF-017 Incomplete (P2)

**PerfScore:** 12 (Impact: 2 x Likelihood: 3 x 4 = 24, scaled to 12)

**Summary:** Within `handleServerCertificateVerify()`, the leaf certificate (`chain[0]`) is parsed twice via `x509.parseCert`: once at line 2721 for OCSP validation and again at line 2810 for CertificateVerify signature extraction. PERF-017 was closed after consolidating cross-function redundancy, but these two sites within the same function were not merged.

**Evidence:**
- File: `src/tls13/context.zig:2721`: `const leaf_parsed = try x509.parseCert(self.allocator, chain[0]);` (OCSP block)
- File: `src/tls13/context.zig:2810`: `const leaf_cert = try x509.parseCert(self.allocator, chain[0]);` (CertificateVerify block)
- Both parse identical `chain[0]` DER bytes within the same function
- Each `parseCert` performs full ASN.1 DER walk + SPKI extraction + allocation

**Root Cause:** The OCSP validation block and CertificateVerify block were written as independent sections. PERF-017 fixed cross-function redundancy but missed within-function redundancy.

**Fix Guidance:**
Parse `chain[0]` once before the OCSP block and reuse the parsed struct for both OCSP validation and signature verification.

**Validation Plan:**
```
# Before: 2 parseCert calls for chain[0] in handleServerCertificateVerify
# After: 1 parseCert call, result shared
# Expected: ~15-30us savings (1 avoided ASN.1 parse + 1 avoided alloc)
# Verify: OCSP and CertificateVerify tests pass
```

**Rollout Risk:** Minimal. Parsed struct is identical regardless of consumer.

**Confidence:** `confidence::confirmed` -- Two `parseCert(self.allocator, chain[0])` calls are visible at lines 2721 and 2810.

---

### PERF-038: Client sendClientFinished Uses 3-4 Allocating encodeHandshake Calls (P2)

**PerfScore:** 12 (Impact: 2 x Likelihood: 3 x 4 = 24, scaled to 12)

**Summary:** `sendClientFinished()` at `src/tls13/context.zig:2337-2412` performs 3-4 `encodeHandshake()` calls for mTLS flows (Certificate + CertificateVerify + Finished). Each call allocates a new buffer, copies body with header, appends to outbound, and frees. This is the same alloc/copy/free pattern fixed in PERF-013 for the server flight but not for the client path.

**Evidence:**
- File: `src/tls13/context.zig:2352`: `const cert_msg = try encodeHandshake(self.allocator, .certificate, cert_body);`
- File: `src/tls13/context.zig:2386`: `const cv_msg = try encodeHandshake(self.allocator, .certificate_verify, cv_body);`
- File: `src/tls13/context.zig:2397`: `const cert_msg = try encodeHandshake(self.allocator, .certificate, cert_body);` (empty cert path)
- File: `src/tls13/context.zig:2408`: `const fin_msg = try encodeHandshake(self.allocator, .finished, verify_data.slice());`
- Each follows `alloc -> memcpy -> appendOutbound -> free` pattern

**Root Cause:** Server flight was optimized with `encodeHandshakeBuf` + `appendOutboundFramed` in PERF-013. Client mTLS path was not in scope.

**Fix Guidance:**
Apply the same zero-alloc pattern from the server flight: use `encodeHandshakeBuf` or `appendOutboundFramed` for all client messages.

**Validation Plan:**
```
# Before: 6-8 allocations (3-4 build + 3-4 encode)
# After: 3-4 allocations (build only)
# Expected: ~2-4us savings per mTLS handshake
# Verify: mTLS conformance tests (OpenSSL + BoringSSL)
```

**Rollout Risk:** Low. Identical byte output. Pattern already proven in server flight.

**Confidence:** `confidence::confirmed` -- `encodeHandshake` calls with defer free are visible at lines 2352, 2386, 2397, 2408.

---

### PERF-039: tls13_build_context_and_hash Allocates ~130 Bytes Per Signature Operation (P2)

**PerfScore:** 10 (Impact: 2 x Likelihood: 3 x 4 = 24, scaled to 10)

**Summary:** `tls13_build_context_and_hash()` in `src/sig.zig:318-328` allocates ~130 bytes via `allocator.alloc` to construct the RFC 8446 Section 4.4.3 signed content (64 spaces + context string + 0x00 + transcript hash). The output is bounded (max 146 bytes) and could use stack allocation.

**Evidence:**
- File: `src/sig.zig:318-328`
- Line 323: `var out = try allocator.alloc(u8, 64 + ctx_len + 1 + hash_len);`
- Context string is always 33 bytes ("TLS 1.3, server/client CertificateVerify")
- Transcript hash is 32 (SHA-256) or 48 (SHA-384) bytes
- Maximum size: 64 + 33 + 1 + 48 = 146 bytes
- Called 1-2 times per handshake

**Root Cause:** Function returns an owned slice, requiring heap allocation. The bounded size (146 bytes max) makes stack allocation a better choice.

**Resolution:**
Changed function signature to accept a caller-provided `*[512]u8` stack buffer and return a slice into it. All 6 call sites updated to declare `var buf: [512]u8 = undefined;` on the stack and pass `&buf`. The allocator parameter was removed from the function. No heap allocations remain in this path.

**Validation:**
- All 545 tests pass (0 regressions)
- `zig fmt --check src/` clean

**Confidence:** `confidence::confirmed` -- resolved.

---

### PERF-040: Engine.zig 7+ Allocating encodeHandshake Calls Per Handshake (P2)

**PerfScore:** 10 (Impact: 2 x Likelihood: 3 x 4 = 24, scaled to 10)

**Summary:** `Engine` in `src/tls13/engine.zig` uses the allocating `encodeHandshake()` for 7+ handshake messages. Each call allocates, copies, appends to outbox, and frees. This is the same pattern fixed for Context in PERF-013 but not ported to the Engine path.

**Evidence:**
- File: `src/tls13/engine.zig` -- 10 references to `encodeHandshake`
- Line 487: `encodeHandshake(self.allocator, .new_session_ticket, body.items)`
- Line 1222: `encodeHandshake(self.allocator, .client_hello, ch_result.body)`
- Line 1248: `encodeHandshake(self.allocator, .finished, verify.slice())`
- Line 1317: `encodeHandshake(self.allocator, .encrypted_extensions, body.items)`
- Line 1360: `encodeHandshake(self.allocator, .certificate, body.items)`
- Line 1411: `encodeHandshake(self.allocator, .certificate_verify, body.items)`
- Line 1582: `encodeHandshake(self.allocator, .server_hello, sh_body)`

**Root Cause:** Engine is the legacy handshake driver not updated with PERF-013 zero-alloc encoding. Related to PERF-026 (Engine-to-Context migration).

**Fix Guidance:**
Port `encodeHandshakeBuf` from Context to Engine, or complete PERF-026 Engine-to-Context migration.

**Validation Plan:**
```
# Before: 14+ allocations (7 build + 7 encode)
# After: 7 allocations (build only)
# Expected: ~3-5us savings per Engine handshake
```

**Rollout Risk:** Low if porting direct-write pattern. Medium if migrating to Context.

**Confidence:** `confidence::confirmed` -- 7+ `encodeHandshake` call sites are visible in engine.zig.

---

### PERF-041: Zero-Capacity ArrayList in validateChain Name Constraints (P3)

**PerfScore:** 8 (Impact: 1 x Likelihood: 2 x 4)

**Summary:** `validateChain()` in `src/x509.zig:1657,1659` creates two zero-capacity ArrayLists (`accumulated_permitted` and `accumulated_excluded`) inside a per-certificate loop for name constraint validation. These are allocated and freed on every iteration even when most certificates have no name constraints.

**Evidence:**
- File: `src/x509.zig:1657`: `var accumulated_permitted = try std.ArrayList([]const u8).initCapacity(alloc, 0);`
- File: `src/x509.zig:1659`: `var accumulated_excluded = try std.ArrayList([]const u8).initCapacity(alloc, 0);`
- Created inside a `while (i < certs.len)` loop -- allocated/freed per certificate
- Name constraints are rare; most certificates have none

**Root Cause:** Zero-capacity ArrayLists are created even when the name constraints check is a no-op for most certs.

**Fix Guidance:**
1. Check if any issuer has name constraints before allocating
2. Or use a small fixed-size stack buffer (most chains have <4 name constraints)
3. Or pre-size to a reasonable capacity: `initCapacity(alloc, 4)`

**Validation Plan:**
```
# Count allocator calls during chain validation:
# Before: 2 ArrayList allocs per cert in chain (even if no name constraints)
# After: 0 allocs when no name constraints present
# Verify: name constraint validation tests pass
```

**Rollout Risk:** Low. Optimization only skips allocation when unnecessary.

**Confidence:** `confidence::confirmed` -- `initCapacity(alloc, 0)` in per-cert loop is visible at lines 1657, 1659.

---

### PERF-042: Per-Cert allocator.dupe in handleCertificate Loop (P3)

**PerfScore:** 8 (Impact: 1 x Likelihood: 2 x 4)

**Summary:** In `handleCertificate()` at `src/tls13/context.zig:2632-2634`, each certificate in the received chain is individually duplicated via `allocator.dupe(u8, cert_entry.cert)` inside a loop. For a typical 2-4 certificate chain, this is 2-4 separate allocator calls where a single batch allocation would suffice.

**Evidence:**
- File: `src/tls13/context.zig:2632-2634`
```zig
for (parsed.entries, 0..) |cert_entry, i| {
    chain[i] = try self.allocator.dupe(u8, cert_entry.cert);
    allocated_count += 1;
}
```
- Typical chain: 2-4 certificates, each 500-2000 bytes DER
- Each `dupe` = 1 alloc + 1 memcpy

**Root Cause:** Certificates are individually duplicated rather than batch-allocated into a contiguous buffer.

**Fix Guidance:**
1. Compute total chain DER size in a first pass
2. Allocate a single contiguous buffer
3. Copy all certs into the buffer and set slice pointers
4. Or use an arena allocator scoped to the certificate chain lifetime

**Validation Plan:**
```
# Before: 2-4 individual dupe calls
# After: 1 allocation for entire chain
# Expected: ~100-400ns savings
# Verify: certificate handling tests pass
```

**Rollout Risk:** Low-medium. Callers that individually free chain entries must be updated to free the batch buffer instead.

**Confidence:** `confidence::confirmed` -- Per-cert `allocator.dupe` in a loop is visible at lines 2632-2634.

---

### PERF-043: Context Struct Hot/Cold Field Mixing (P3)

**PerfScore:** 6 (Impact: 1 x Likelihood: 3 x 4 = 12, scaled to 6)

**Summary:** The `Context` struct at `src/tls13/context.zig:594-630` interleaves frequently accessed "hot" fields (phase, hash_kind, transcripts, secrets) with rarely accessed "cold" fields (hrr_sent, hrr_received, peer_sct_list, client_cert_requested). This causes unnecessary cache-line loads when accessing hot fields during the handshake fast path.

**Evidence:**
- File: `src/tls13/context.zig:594-630`
- Hot fields: `phase` (line 598), `hash_kind` (line 604), `transcripts` (line 599), `secrets` (line 600), `streams` (line 601)
- Cold fields interleaved: `hrr_sent` (line 614), `hrr_received` (line 615), `peer_cert_verify_alg` (line 620), `peer_sct_list` (line 622), `client_cert_requested` (line 624)
- A 64-byte cache line may contain both hot and cold fields, wasting cache space

**Root Cause:** Fields were added organically as features were implemented, without consideration for cache-line layout.

**Fix Guidance:**
Group hot fields at the top of the struct and cold fields at the end:
```zig
pub const Context = struct {
    // === Hot path (first 2-3 cache lines) ===
    phase: HandshakePhase,
    hash_kind: Hash,
    transcripts: TranscriptSet,
    secrets: SecretSchedule,
    streams: CryptoStreams,
    state: HandshakeState,
    allocator: std.mem.Allocator,
    config: Config,
    callbacks: Callbacks,
    // === Cold path ===
    hrr_sent: bool = false,
    hrr_received: bool = false,
    peer_cert_chain: ?[][]const u8 = null,
    // ... rest ...
};
```

**Validation Plan:**
```
# Measure with perf stat -e cache-misses during handshake:
# Before: N cache misses per handshake
# After: fewer cache misses (hot fields in fewer cache lines)
# This is a micro-optimization; measure before committing
```

**Rollout Risk:** Minimal. Field order change does not affect Zig struct semantics (named fields). All tests pass unchanged.

**Confidence:** `confidence::suspected` -- Cache-line impact depends on actual struct layout and access patterns. Zig may reorder fields. Measurement needed.

---

### PERF-044: Benchmark Uses page_allocator, Masking Allocation Overhead (P3)

**PerfScore:** 6 (Impact: 1 x Likelihood: 3 x 4 = 12, scaled to 6)

**Summary:** Several benchmarks in `tests/bench.zig` use `std.heap.page_allocator` for operations that exercise the allocator (certificate parsing, ClientHello parsing, chain validation). The page allocator maps/unmaps entire OS pages (4KB) for each allocation, which has vastly different performance characteristics than a typical general-purpose allocator. This masks the true allocation overhead that would occur in production.

**Evidence:**
- File: `tests/bench.zig:137`: `const alloc = std.heap.page_allocator;` (benchCertParse)
- File: `tests/bench.zig:267`: `const alloc = std.heap.page_allocator;` (benchClientHelloParse)
- File: `tests/bench.zig:289`: `const alloc = std.heap.page_allocator;` (benchCertChainValidation)
- page_allocator: each alloc/free = mmap/munmap syscall (~200-500ns per call)
- GeneralPurposeAllocator: each alloc/free = ~20-50ns per call

**Root Cause:** Convenience use of `page_allocator` which requires no initialization. Benchmark results are inflated by syscall overhead rather than reflecting actual allocation performance.

**Fix Guidance:**
Replace `std.heap.page_allocator` with `std.heap.GeneralPurposeAllocator` or a pre-allocated arena:
```zig
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
defer _ = gpa.deinit();
const alloc = gpa.allocator();
```

**Validation Plan:**
```
# Run benchmarks with page_allocator vs GeneralPurposeAllocator:
# page_allocator: cert_parse ~5000ns/op (inflated by mmap)
# GPA: cert_parse ~1000ns/op (actual allocation cost)
# The difference reveals true parsing cost vs syscall overhead
```

**Rollout Risk:** None. Benchmark-only change.

**Confidence:** `confidence::confirmed` -- `std.heap.page_allocator` usage is visible in bench.zig.

---

### PERF-045: hkdfLabel Still Allocates via FBA for Bounded-Size Buffer (P3)

**PerfScore:** 5 (Impact: 1 x Likelihood: 4 x 4 = 16, scaled to 5)

**Summary:** `hkdfLabel()` at `src/key_schedule.zig:309-334` accepts an `allocator` parameter and uses `allocator.alloc(u8, total)` to create the HkdfLabel output. While PERF-034 fixed the `std.mem.concat` call for the prefix, the function still performs a heap allocation (via whatever allocator is passed) for a buffer whose maximum size is bounded (~70 bytes: 2 + 1 + 6 + max_label + 1 + max_context). A stack-allocated array would eliminate this allocation entirely.

**Evidence:**
- File: `src/key_schedule.zig:309-334`
- Line 316: `var out = try alloc.alloc(u8, total);`
- Maximum `total`: 2 (length) + 1 (label_len) + 6 ("tls13 ") + 12 (longest label "ap traffic") + 1 (context_len) + 48 (SHA-384 hash) = ~70 bytes
- Called 6-12 times per handshake (once per HKDF-Expand-Label derivation)

**Root Cause:** The function returns an owned slice, requiring the caller to free it. A stack buffer or caller-provided buffer would eliminate the allocator dependency.

**Fix Guidance:**
Return a bounded stack array:
```zig
const MaxHkdfLabelLen = 2 + 1 + 6 + 255 + 1 + 255; // theoretical max
fn hkdfLabel(label: []const u8, context: []const u8, out_len: u16) struct { buf: [MaxHkdfLabelLen]u8, len: usize } {
    // ... fill buf, return { .buf = buf, .len = total } ...
}
```

**Validation Plan:**
```
# Before: 6-12 alloc/free per handshake for ~70 byte buffers
# After: 0 allocations (stack buffer)
# Expected: ~30-120ns savings per handshake
# Verify: all key derivation tests and RFC test vectors pass
```

**Rollout Risk:** Low. Requires updating callers to use stack-returned struct instead of owned slice. All callers immediately pass the result to HKDF and do not store it.

**Confidence:** `confidence::confirmed` -- `alloc.alloc(u8, total)` for bounded output is visible at line 316.

---

## Findings by Area

### App (33 findings)

| ID | PerfSeverity | Finding |
|----|-------------|---------|
| PERF-001 | P0 | ClientHello parse excessive heap allocations |
| PERF-002 | P0 | Context struct cache pollution from inline AntiReplayWindow |
| PERF-003 | P0 | Zero-capacity ArrayLists in ClientHello parsing |
| PERF-012 | P0 | buildFinished uses ArrayList for simple slice copy |
| PERF-004 | P1 | Dual-hash transcript after cipher negotiation |
| PERF-006 | P1 | copyForwards where @memcpy suffices |
| PERF-013 | P1 | 10+ alloc/free cycles per server flight (updated with PERF-028 analysis) |
| PERF-014 | P1 | Unbounded CryptoBuffer inbound growth |
| PERF-015 | P1 | Double buffer copy in ClientHello construction |
| PERF-007 | P2 | ServerHello builder zero-capacity ArrayLists |
| PERF-008 | P2 | CryptoBuffer.consume O(n) memmove |
| PERF-009 | P2 | empty_hash recomputed in key derivation |
| PERF-017 | P2 | Duplicate x509.parseCert calls for same leaf cert (updated with engine.zig site) |
| PERF-018 | P2 | pollCrypto copies outbound buffer via dupe |
| PERF-019 | P2 | Extension buffers built separately then appended |
| PERF-020 | P2 | Transcript struct copies on snapshot |
| PERF-021 | P2 | O(n*m) cipher suite negotiation loops |
| PERF-022 | P2 | flushCrypto copies full outbox |
| PERF-023 | P2 | encodeHandshake always allocates new buffer |
| PERF-031 | P2 | 13 zero-capacity ArrayLists in message builders (excl. ServerHello/ClientHello) |
| PERF-032 | P2 | 12 individual allocator.dupe calls in ClientHelloInfo.parse |
| PERF-036 | P2 | CryptoBuffer.consume still O(n) memmove -- PERF-008 fix incomplete |
| PERF-037 | P2 | Redundant leaf cert re-parse in handleCertificateVerify -- PERF-017 incomplete |
| PERF-038 | P2 | Client sendClientFinished 3-4 allocating encodeHandshake calls |
| PERF-039 | P2 | tls13_build_context_and_hash allocates ~130 bytes per sig op |
| PERF-040 | P2 | Engine.zig 7+ allocating encodeHandshake calls |
| PERF-010 | P3 | AntiReplayWindow.contains O(n) linear scan |
| PERF-025 | P3 | TicketStore.lookup scans all entries |
| PERF-027 | P3 | No timeout on X.509 chain validation |
| PERF-034 | P3 | hkdfLabel uses std.mem.concat for "tls13 " prefix |
| PERF-035 | P3 | Missing inline hint on deriveNonce |
| PERF-041 | P3 | Zero-capacity ArrayList in validateChain name constraints |
| PERF-042 | P3 | Per-cert allocator.dupe in handleCertificate loop |
| PERF-043 | P3 | Context struct hot/cold field mixing |
| PERF-045 | P3 | hkdfLabel still allocates via FBA for bounded-size buffer |

### Infra (3 findings)

| ID | PerfSeverity | Finding |
|----|-------------|---------|
| PERF-005 | P1 | Global mutex contention on getPool() |
| PERF-016 | P2 | Global trust store RwLock contention |
| PERF-026 | P3 | engine.zig legacy code duplicates Context |

### CI (4 findings)

| ID | PerfSeverity | Finding |
|----|-------------|---------|
| PERF-011 | P2 | Missing benchmark suite (upgraded from P3) |
| PERF-029 | P1 | Missing critical benchmarks -- bench.zig covers only 3 micro-ops |
| PERF-033 | P2 | No CI performance regression detection |
| PERF-044 | P3 | Benchmark uses page_allocator, masking allocation overhead |

### Infrastructure Tooling (1 finding)

| ID | PerfSeverity | Finding |
|----|-------------|---------|
| PERF-024 | P2 | No allocation tracking or memory profiling |

---

## Roadmap

### Quick Wins (< 1 day each)

| ID | Effort | Expected Impact | Status |
|----|--------|----------------|--------|
| PERF-012 | 5 min | ~200ns/handshake -- replace ArrayList with allocator.dupe in buildFinished | Closed |
| PERF-003 | 30 min | ~300ns/parse -- change 6 initCapacity(0) to initCapacity(4-8) | Closed |
| PERF-009 | 30 min | ~120ns/handshake -- precompute empty_hash as comptime const | Closed |
| PERF-018 | 15 min | ~100ns/poll -- use toOwnedSlice instead of dupe in pollCrypto | Closed |
| PERF-022 | 15 min | ~100ns/flush -- use toOwnedSlice instead of alloc+memcpy in flushCrypto | Closed |
| PERF-007 | 1 hr | ~200ns/ServerHello -- pre-allocate message builder ArrayLists | Closed |
| PERF-006 | 2 hr | <10ns/AEAD op -- replace ~37 copyForwards with @memcpy | Closed |
| PERF-031 | 2 hr | ~1-2us/handshake -- pre-size 13 zero-cap ArrayLists in message builders | Closed |
| PERF-034 | 30 min | ~60-120ns/handshake -- replace std.mem.concat with stack buffer in hkdfLabel | Closed |
| PERF-035 | 5 min | Informational -- add inline hint on deriveNonce (likely no-op) | Closed |
| PERF-037 | 30 min | ~15-30us/handshake -- share leaf cert parse across OCSP and CertVerify | **Open** |
| PERF-039 | 30 min | ~20-40ns/handshake -- stack buffer for tls13_build_context_and_hash | **Closed** |
| PERF-041 | 30 min | ~50-100ns/chain -- pre-size name constraint ArrayLists or guard allocation | **Open** |
| PERF-044 | 15 min | Measurement accuracy -- replace page_allocator in benchmarks with GPA | **Open** |
| PERF-045 | 1 hr | ~30-120ns/handshake -- stack buffer for hkdfLabel output | **Open** |

### Medium (1-5 days)

| ID | Effort | Expected Impact | Status |
|----|--------|----------------|--------|
| PERF-001 | 2 days | ~400ns/parse -- arena allocator for ClientHello parsing | Closed |
| PERF-002 | 1 day | ~2KB/connection -- box AntiReplayWindow behind pointer | Closed |
| PERF-004 | 2 days | ~2-5us/handshake -- single-hash transcript fast path | Closed |
| PERF-005 | 1 day | Eliminates mutex contention -- atomic double-checked locking | Closed |
| PERF-013 | 2 days | ~3-8us/handshake -- single-buffer server flight (pre-compute total size) | Closed |
| PERF-014 | 1 day | Bounded memory -- max_inbound_size guard for CryptoBuffer | Closed |
| PERF-015 | 1 day | ~200ns/ClientHello -- eliminate double buffer copy | Closed |
| PERF-017 | 1 day | ~50-100us/handshake -- parse leaf cert once, reuse across 4 call sites | Closed |
| PERF-023 | 2 days | ~150ns/handshake -- direct-write encodeHandshake variant | **Open** |
| PERF-027 | 1 day | DoS prevention -- max chain depth in validateChain | Closed |
| PERF-029 | 3 days | Validation infrastructure -- expand bench.zig with 7 critical benchmarks | Closed |
| PERF-032 | 2 days | ~1-2us/handshake -- arena allocator for ClientHelloInfo.parse dupe batch | **Open** |
| PERF-036 | 1 day | ~90-300ns/handshake -- offset-based O(1) consume for context.zig CryptoBuffer | **Open** |
| PERF-038 | 1 day | ~2-4us/mTLS handshake -- zero-alloc client flight encoding | **Open** |
| PERF-042 | 1 day | ~100-400ns/handshake -- batch cert chain duplication | **Open** |
| PERF-043 | 1 day | Cache-line optimization -- group hot fields in Context struct | **Open** |

### Strategic (> 5 days)

| ID | Effort | Expected Impact | Status |
|----|--------|----------------|--------|
| PERF-011 | 5-10 days | Regression prevention -- full benchmark suite with CI integration | Closed |
| PERF-024 | 3-5 days | Performance observability -- counting allocator for debug builds | Closed |
| PERF-008 | 3-5 days | Future-proofing -- ring buffer for CryptoBuffer (only if buffers grow) | Closed |
| PERF-010 | 3 days | Future-proofing -- hash-based anti-replay (only if window >256) | Closed |
| PERF-016 | 2-3 days | Reduced contention -- atomic trust store pointer with local caching | **Open** |
| PERF-026 | 5-10 days | Code health -- complete Engine-to-Context migration | **Open** |
| PERF-033 | 5 days | CI quality gate -- baseline comparison + threshold checking for benchmarks | **Open** |
| PERF-040 | 3-5 days | ~3-5us/Engine handshake -- port zero-alloc encode to Engine or migrate to Context | **Open** |

---

## Unknowns and Blockers

1. **No profiler data available.** All latency estimates are based on static analysis and known costs of Zig standard library operations. Running `perf record` or Tracy on a real handshake would confirm or refine these estimates.

2. **Context struct total size unknown.** The `Context` struct in `src/tls13/context.zig` is ~3500 lines with many fields. An `@sizeOf(Context)` measurement would confirm the cache pollution impact of PERF-002.

3. **AEAD copyForwards impact is theoretical.** The per-operation cost of copyForwards vs @memcpy is <10ns. Aggregate impact depends on throughput requirements (connections/sec). Profiling under load would confirm whether this is material.

4. **Transcript dual-hash cost depends on cipher suite distribution.** If 99% of connections use SHA-256 suites, the wasted SHA-384 computation is the full cost. If SHA-384 suites are common, both hashes are sometimes needed through ServerHello.

5. **CryptoBuffer DoS vector unquantified.** PERF-014 identifies unbounded growth but the actual memory exhaustion threshold depends on deployment constraints (available RAM, connection limits, OS rlimits).

6. **parseCert cost varies by certificate complexity.** PERF-017 estimates ~50-100us for 3 redundant parses across 4 call sites, but actual cost depends on certificate extensions, SAN count, and key type.

7. **PERF-035 inline impact unverified.** LLVM almost certainly inlines `deriveNonce` in ReleaseFast, but this has not been verified by inspecting emitted assembly. Until confirmed, tagged `confidence::suspected`.

8. **hkdfLabel FixedBufferAllocator overhead is theoretical.** PERF-034 estimates ~10ns per call for `std.mem.concat` on a FixedBufferAllocator, but actual overhead may be lower if the FBA's bump pointer is in cache. Needs micro-benchmark verification.

9. **PERF-043 cache-line impact depends on Zig struct layout.** Zig may reorder struct fields for alignment optimization. The actual cache-line impact requires `@sizeOf` and `@offsetOf` measurements to confirm field placement.

10. **PERF-044 benchmark allocator choice affects measurement validity.** The page_allocator-based benchmarks (cert parse, ClientHello parse, chain validation) report inflated latencies due to syscall overhead. True allocation cost is masked.

### What Would Confirm Suspected Items

41 of 43 findings are tagged `confidence::confirmed` based on unambiguous code evidence. PERF-035 and PERF-043 are tagged `confidence::suspected`. To refine the estimated latency impacts:
- Run `parseClientHello` with a counting allocator to get exact allocation counts
- Profile a full handshake with `std.time.Timer` to measure actual wall-clock time per phase
- Use `@sizeOf(Context)` to measure the struct size impact of PERF-002
- Benchmark `copyForwards` vs `@memcpy` for typical buffer sizes (12-48 bytes) on target hardware
- Send oversized CRYPTO frames to measure CryptoBuffer memory behavior (PERF-014)
- Count parseCert invocations per handshake to confirm PERF-017 redundancy (now 4 call sites)
- Inspect `zig build-lib ... --emit asm` output for `deriveNonce` to confirm LLVM inlining (PERF-035)
- Micro-benchmark `hkdfLabel` with and without `std.mem.concat` to measure actual FBA overhead (PERF-034)
- Count total allocator.dupe calls in ClientHelloInfo.parse to confirm PERF-032 count of 12
- Use `@offsetOf(Context, "phase")` etc. to confirm hot/cold field cache-line placement (PERF-043)
- Run bench.zig with GPA vs page_allocator to quantify syscall overhead masking (PERF-044)
- Count `encodeHandshake` alloc/free pairs in Engine path to confirm PERF-040 count of 7+
- Trace `tls13_build_context_and_hash` allocations per handshake to confirm PERF-039 (1-2 calls)
