# Gap Analysis -- Resolved

> Items moved here from `docs/GAP_ANALYSIS.md` when their tracking gap is resolved.
> The underlying work may still be tracked by separate GitLab issues.

---

### GAP-0082: QUAL-074 on_session_ticket callback not wired [RESOLVED]
- **Issue:** [#115](https://gitlab.com/devnw/zig/tls/-/issues/115) (open -- tracks remaining callback work)
- **Category:** Code Quality / API Contract
- **Resolution:** Tracking inconsistency resolved. QUAL-074 was marked Closed but the
  `on_session_ticket` callback was still not wired (`src/tls13/context.zig:1207`). Filed
  GitLab issue #115 as a separate tracking item for the callback implementation, as
  recommended by GAP-0082. The `new_session_ticket` message is now handled (logged) rather
  than silently dropped.
- **Evidence:** GitLab issue [#115](https://gitlab.com/devnw/zig/tls/-/issues/115) filed
  and annotated with resolution context.
- **Resolved date:** 2026-03-24

### GAP-0084: 9 open PERF items have no GitLab issues [RESOLVED]
- **Issue:** N/A (tracking gap, no dedicated issue)
- **Category:** CI-CD / Tracking
- **Resolution:** Of the 9 PERF items originally without GitLab issues:
  - 5 closed in code: PERF-008 (offset-based O(1) consume), PERF-010 (timing-safe by
    design), PERF-017 (parse leaf cert once), PERF-025 (timing-safe by design at
    max_tickets=16), PERF-027 (max_chain_depth=10 sufficient)
  - 4 now have GitLab issues: PERF-016 ([#103](https://gitlab.com/devnw/zig/tls/-/issues/103)),
    PERF-019 ([#104](https://gitlab.com/devnw/zig/tls/-/issues/104)),
    PERF-023 ([#105](https://gitlab.com/devnw/zig/tls/-/issues/105)),
    PERF-026 ([#106](https://gitlab.com/devnw/zig/tls/-/issues/106))
- **Evidence:** `docs/PERF_GAP_ANALYSIS.md` detail table shows all 9 items either Closed
  or with GitLab issue URLs populated.
- **Resolved date:** 2026-03-24

### GAP-0094: 7 closable GitLab issues remain open despite code implemented [RESOLVED]
- **Issue:** [#135](https://gitlab.com/devnw/zig/tls/-/issues/135) (closed)
- **Category:** Docs / Tracking
- **Resolution:** All 7 stale issues closed with evidence comments:
  - #4 (PSK Mode Activation) -- all PSK requirements implemented
  - #14 (RFC 8446 Appendix A Test Vectors) -- 33 tests implemented
  - #15 (PSK Binder Verification) -- constant-time binder verification implemented
  - #19 (Use Actual Ticket from Config) -- MissingResumptionTicket error replaces hardcoded string
  - #71 (QUAL-077 Engine-to-Context Migration Guide) -- covered by inline docs + PERF-026 #106
  - #83 (PERF-013) -- zero-alloc server flight implemented
  - #89 (PERF-015) -- single-buffer ClientHello construction implemented
- **Evidence:** Each issue has a closing comment citing specific files, line numbers, and
  GAP IDs that demonstrate the implementation.
- **Resolved date:** 2026-03-24

---

## Phase 8 Closures (2026-03-24)

### GAP-0087: RELEASE_NOTES.md falsely claims CRL parsing and validation [CLOSED]
- **Issue:** [#128](https://gitlab.com/devnw/zig/tls/-/issues/128)
- **Category:** Documentation Accuracy
- **Resolution:** RELEASE_NOTES.md line 63 corrected: "CRL parsing and validation" replaced with
  "CRL support not yet implemented (see lib.zig)". Section header changed from full checkmark to
  partial indicator.
- **Evidence:** `RELEASE_NOTES.md` diff shows corrected text with warning marker.
- **Resolved date:** 2026-03-24

### GAP-0088: RELEASE_NOTES.md falsely claims AIA support [CLOSED]
- **Issue:** [#129](https://gitlab.com/devnw/zig/tls/-/issues/129)
- **Category:** Documentation Accuracy
- **Resolution:** RELEASE_NOTES.md line 64 corrected: "Authority Information Access (AIA)" marked
  as "not yet implemented" with warning marker.
- **Evidence:** `RELEASE_NOTES.md` diff shows corrected text.
- **Resolved date:** 2026-03-24

### GAP-0089: RELEASE_NOTES.md falsely claims certificate policy enforcement [CLOSED]
- **Issue:** [#130](https://gitlab.com/devnw/zig/tls/-/issues/130)
- **Category:** Documentation Accuracy
- **Resolution:** RELEASE_NOTES.md line 65 corrected: "Certificate policy enforcement" marked as
  "not yet implemented" with warning marker.
- **Evidence:** `RELEASE_NOTES.md` diff shows corrected text.
- **Resolved date:** 2026-03-24

### GAP-0090: RELEASE_NOTES.md falsely claims FFDHE key exchange [CLOSED]
- **Issue:** [#131](https://gitlab.com/devnw/zig/tls/-/issues/131)
- **Category:** Documentation Accuracy
- **Resolution:** RELEASE_NOTES.md line 78 corrected: ffdhe2048/3072/4096 now states "wire format
  parsing only (no key agreement implementation)".
- **Evidence:** `RELEASE_NOTES.md` diff shows corrected text with warning marker.
- **Resolved date:** 2026-03-24

### GAP-0091: RELEASE_NOTES.md overstates P-256/P-384 key exchange support [CLOSED]
- **Issue:** [#132](https://gitlab.com/devnw/zig/tls/-/issues/132)
- **Category:** Documentation Accuracy
- **Resolution:** RELEASE_NOTES.md lines 76-77 corrected: secp256r1/secp384r1 clarified as
  "supported for signatures only (not key exchange)". X25519 identified as the sole key exchange
  implementation.
- **Evidence:** `RELEASE_NOTES.md` diff shows corrected text with warning marker.
- **Resolved date:** 2026-03-24

### SEC-047: Engine computeApplicationSecrets incorrect key schedule [CLOSED]
- **Issue:** [#123](https://gitlab.com/devnw/zig/tls/-/issues/123) (confidential)
- **Category:** Security / Key Schedule
- **Resolution:** `computeApplicationSecrets` in engine.zig now uses `emptyHash()` for context
  parameter to Derive-Secret(., "derived", "") and `zeroSecret()` for IKM to HKDF-Extract for
  master secret, matching RFC 8446 Section 7.1 key schedule exactly.
- **Evidence:** `src/tls13/engine.zig:1510-1516` -- `emptyHash()` and `zeroSecret()` calls.
- **Resolved date:** 2026-03-24

### SEC-040: startClientHandshake missing X25519 clamping [CLOSED]
- **Issue:** [#126](https://gitlab.com/devnw/zig/tls/-/issues/126)
- **Category:** Security / Defense-in-depth
- **Resolution:** Explicit X25519 clamping (priv[0]&=248, priv[31]&=127|=64) added per RFC 7748
  Section 5 for consistency with sendClientHello2() and engine.zig ensureKeypair().
- **Evidence:** `src/tls13/context.zig:2181-2187`
- **Resolved date:** 2026-03-24

### SEC-048: Server negotiateCipherAndKeys missing X25519 clamping [CLOSED]
- **Issue:** [#127](https://gitlab.com/devnw/zig/tls/-/issues/127)
- **Category:** Security / Defense-in-depth
- **Resolution:** Explicit X25519 clamping added to server key generation path for consistency.
- **Evidence:** `src/tls13/context.zig:1959-1965`
- **Resolved date:** 2026-03-24

### SEC-046: PSK identity comparison non-constant-time [CLOSED]
- **Issue:** N/A (no dedicated GitLab issue)
- **Category:** Security / Timing Side-channel
- **Resolution:** Replaced `std.mem.eql` with `std.crypto.timing_safe.compare` for PSK identity
  matching. Length check is non-secret (performed first), followed by constant-time byte comparison.
- **Evidence:** `src/tls13/context.zig:1825`
- **Resolved date:** 2026-03-24

### QUAL-115: setTransportParameters silently swallows OOM [CLOSED]
- **Issue:** [#122](https://gitlab.com/devnw/zig/tls/-/work_items/122)
- **Category:** Code Quality / API Contract
- **Resolution:** Changed return type from `void` to `!void` and replaced `catch return` with
  `try`. OOM now propagates to callers.
- **Evidence:** `src/tls13/context.zig:806`
- **Resolved date:** 2026-03-24

### QUAL-120: quic_transport_params.zig decode() missing errdefer [CLOSED]
- **Issue:** N/A
- **Category:** Code Quality / Error Handling
- **Resolution:** Added `errdefer params.deinit(allocator)` immediately after params initialization.
  This single errdefer covers all allocations in decode().
- **Evidence:** `src/quic_transport_params.zig:560`
- **Resolved date:** 2026-03-24

### QUAL-121: Engine cert handling converts OOM to cert-invalid [CLOSED]
- **Issue:** N/A
- **Category:** Code Quality / Error Handling
- **Resolution:** Replaced 3 instances of `catch { break :blk false }` with `try` in cert handling,
  allowing OOM to propagate instead of silently rejecting valid certificates.
- **Evidence:** `src/tls13/engine.zig:865-870`
- **Resolved date:** 2026-03-24

### PERF-039: tls13_build_context_and_hash heap allocation [CLOSED]
- **Issue:** [#121](https://gitlab.com/devnw/zig/tls/-/issues/121)
- **Category:** Performance / Allocation
- **Resolution:** Changed function signature to accept caller-provided `*[512]u8` stack buffer.
  All 6 call sites updated. Allocator parameter removed. Zero heap allocations in this path.
- **Evidence:** `src/sig.zig:318-328`
- **Resolved date:** 2026-03-24
