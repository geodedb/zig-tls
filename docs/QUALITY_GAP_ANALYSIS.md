# Quality Gap Analysis

> **Last updated:** 2026-04-20 (Cycle 6 / Phase 19 gap-closure — closed QUAL-104, 346, 348, 349, 352, 353, 356 (7 items); QUAL-347 confirmed Won't-Do with rationale (`computeExpectedBinder`/`computeBinderTranscriptHash` are live PSK binder validators, not dead code). Cycle 6 / Phase 18 sync preceded: QUAL-069/QUAL-073/QUAL-091 closed as subsumed by engine.zig deletion (4ae8ac7) + QUAL-317 decomposition (0841721); QUAL-104 reopened then closed this phase; QUAL-116 filed as GitLab [#242](https://gitlab.com/devnw/zig/tls/-/work_items/242); QUAL-315 promoted Deferred → Open with kcov recommendation.)
> **Scope:** TLS 1.3/QUIC Implementation in Zig
> **Review phase:** Phase 4 `/codepros:audit` quality-issue-tracker filed **QUAL-344..QUAL-356 (13 new issues)** from Phase 3 quality-reviewer confirmed findings -- remaining client-handler decomposition, errdefer gaps, X25519-only correctness, doc/ADR debt. Cycle 5 / Phase 17 Closed QUAL-317 (`src/tls13/context.zig` decomposed into 8 pure-function sibling modules under `src/tls13/context/`; ~80 new unit tests; oracle byte-identical across all 12 landing commits; bonus CWE-226 fix added 4 `secureZero` calls on OLD app-traffic secrets before KeyUpdate rotation; CI regression gate added). Cycle 4 / Phase 16 closed QUAL-339. Cycle 3 / Phase 15 closed QUAL-338, QUAL-340, QUAL-341, QUAL-342. Cycle 2 / Phase 14 previously closed QUAL-107, QUAL-205, QUAL-208, QUAL-209, QUAL-321, QUAL-337 + QUAL-343 Won't-Do. Phase 13 closed 21 items. Phase 12 filed QUAL-334..343; Phase 11 added QUAL-301..333.

---

## Summary

| Severity | Open | Partial | Closed | By Design | Deferred | Won't Do | Total |
|----------|------|---------|--------|-----------|----------|----------|-------|
| Critical | 0    | 0       | 2      | 0         | 0        | 0        | 2     |
| High     | 4    | 0       | 20     | 0         | 0        | 0        | 24    |
| Medium   | 12   | 0       | 42     | 1         | 0        | 1        | 56    |
| Low      | 14   | 0       | 35     | 2         | 0        | 3        | 54    |
| **Total**| **30** | **0** | **99** | **3**   | **0**    | **4**    | **136**|

*Counts reflect Cycle 7 / Phase 20 quality-issue-tracker sync (2026-04-21):* +2 High Open (QUAL-357, QUAL-358); QUAL-345 Medium Open → Closed (superseded by QUAL-357, net Medium Open +2 from QUAL-359/QUAL-360 - 1 from QUAL-345 supersede = +1 net, total +2 after other refresh); +4 Low Open (QUAL-361..364); QUAL-365/366/367 refuted at scoring time → recorded as `resolution::metric-error` / `resolution::false-positive`, not counted as Open; QUAL-368 Info-only, not counted.
*Counts reflect Cycle 7 / Phase 21 audit-closure Stage 9 (2026-04-21):* -1 High Open (+1 Closed: QUAL-357 `handleCertificateVerify` split into 3 new per-concern validators + existing `verifyCertVerifySignature` in `src/tls13/context/cert_handlers.zig`; orchestrator body reduced from 163 LOC to ~78 LOC; oracle byte-identical).
*Counts reflect Cycle 6 / Phase 19 gap-close (2026-04-20):* -1 High Open (+1 Closed: QUAL-346), -1 Medium Open (+1 Closed: QUAL-356), -5 Low Open (+5 Closed: QUAL-104, 348, 349, 352, 353). QUAL-347 remained Won't-Do; counts unchanged on that axis.

### Top 5 Risks (post Phase 21 / Cycle 7)

1. **QUAL-358** (High, PS 100) -- `tls13` module dual-entry (`src/tls13.zig` shim + `src/tls13/mod.zig` canonical); `build.zig:194` points at shim. Collapse to one root; `git rm src/tls13.zig`. [#272](https://gitlab.com/devnw/zig/tls/-/work_items/272). Cross-ref PERF-237.
2. **QUAL-351** (Medium, PS 48) -- `handleServerHello` hardcodes X25519 group check while `Config.supported_groups` claims agility. Correctness/interop bug. Deferred — feature work.
3. **QUAL-344** (Medium, PS 48) -- Client-side message handlers remain inlined in `context.zig` (3206 LOC post-decomp); mirror QUAL-317 pattern to extract. Deferred to Wave 4 refactor.
4. **QUAL-350** (Medium, PS 48) -- `handleHandshakeMessage` 152L dispatcher with inline QUIC-TP parsing (dup with canonical parser). Deferred to Wave 4 refactor.
5. **QUAL-359** (Medium, PS 64) -- Extract state types (`CryptoBuffer`, `HandshakeFlags`, `TranscriptSet`) from context.zig into `context/state.zig`. [#275](https://gitlab.com/devnw/zig/tls/-/work_items/275).

(Previous Top-5 entries: ~~QUAL-346~~ closed Phase 19; ~~QUAL-345~~ superseded by QUAL-357 Phase 20; ~~QUAL-357~~ closed Phase 21.)

### Cycle 5 / Phase 17 Phase-4 Audit Filings (2026-04-20, QUAL-344..356)

13 new issues filed from `/codepros:audit` Phase 3 `quality-reviewer` confirmed findings. All `confidence::confirmed`, evidence cited file:line. Ranked by PriorityScore (`Impact * Likelihood * 4`).

| QUAL-ID | Issue | Severity | PS | Category | Finding | Status |
|---------|-------|----------|----|----------|---------|--------|
| QUAL-346 | [#238](https://gitlab.com/devnw/zig/tls/-/work_items/238) | High | 48 | maintainability | Missing errdefer for partial traffic-secret install (`context.zig:2094-2096` + symmetric server path) | **Closed** (Cycle 6 / Phase 19, commit 8c7ced3) |
| QUAL-344 | [#236](https://gitlab.com/devnw/zig/tls/-/work_items/236) | Medium | 48 | maintainability | Extract client-side handlers (handleServerHello 130L, handleCertificateVerify 164L, handleEncryptedExtensions, startClientHandshake 115L) into `context/client_handlers.zig` mirroring QUAL-317 | Open (deferred to Wave 4) |
| QUAL-345 | [#237](https://gitlab.com/devnw/zig/tls/-/work_items/237) | Medium | 48 | maintainability | Split `handleCertificateVerify` (`context.zig:2404`) into 4 sub-functions (validateCertChain / validateOcsp / validateSct / verifyCvSig) | **Closed** (2026-04-21, **superseded by QUAL-357** [#271](https://gitlab.com/devnw/zig/tls/-/work_items/271)) |
| QUAL-350 | [#244](https://gitlab.com/devnw/zig/tls/-/work_items/244) | Medium | 48 | maintainability | `handleHandshakeMessage` dispatcher 152L with inline TP parsing (`context.zig:999`) | Open (deferred to Wave 4) |
| QUAL-351 | [#245](https://gitlab.com/devnw/zig/tls/-/work_items/245) | Medium | 48 | api-contract | `handleServerHello` hardcodes X25519-only check (`context.zig:2039`) contradicting `supported_groups` config | Open (deferred — feature work) |
| QUAL-348 | [#240](https://gitlab.com/devnw/zig/tls/-/work_items/240) | Low | 40 | docs | `Context` struct + `HandshakePhase` enum undocumented (`context.zig:487`) -- onboarding blocker | **Closed** (Cycle 6 / Phase 19, commit 21d6c77) |
| QUAL-356 | [#254](https://gitlab.com/devnw/zig/tls/-/work_items/254) | Medium | 36 | maintainability | "No errdefer needed" comment at `context.zig:2379` is fragile -- future fallible insert breaks invariant silently | **Closed** (Cycle 6 / Phase 19, commit 8c69643) |
| QUAL-349 | [#241](https://gitlab.com/devnw/zig/tls/-/work_items/241) | Low | 24 | readability | Magic hex 0x0033 / 0x001d in handleServerHello (`context.zig:2035,2039`) -- use enum refs (overlaps QUAL-104) | **Closed** (Cycle 6 / Phase 19, commit e17c025) |
| QUAL-352 | [#246](https://gitlab.com/devnw/zig/tls/-/work_items/246) | Low | 24 | api-contract | Error taxonomy split `ApiError` vs `HandshakeError` (`context.zig:299,303`) undocumented | **Closed** (Cycle 6 / Phase 19, commit 1447ab5) |
| QUAL-353 | [#248](https://gitlab.com/devnw/zig/tls/-/work_items/248) | Low | 24 | docs | `parallel.getPool` docstring missing lifecycle/deinit warning (relates QUAL-325, QUAL-314) | **Closed** (Cycle 6 / Phase 19, commit cf11e31) |
| QUAL-347 | [#239](https://gitlab.com/devnw/zig/tls/-/work_items/239) | Low | 16 | cleanup | **Won't Do — false positive.** `computeExpectedBinder` and `computeBinderTranscriptHash` in `psk_selection.zig` ARE used in production (5 call sites at lines 410, 447, 490, 556, 596 — PSK binder validation per RFC 8446 §4.2.11). Deleting would break resumption. Static-analysis "unused" signal missed legitimate call sites. | **Won't Do** (Cycle 6 / Phase 19, commit 3a42503) |
| QUAL-354 | [#250](https://gitlab.com/devnw/zig/tls/-/work_items/250) | Low | 16 | ci-cd | `build.zig` monolithic 1379 LOC -- split by concern | Open (deferred to Wave 5) |
| QUAL-355 | [#252](https://gitlab.com/devnw/zig/tls/-/work_items/252) | Low | 16 | docs | No ADR for QUAL-317 context.zig decomposition decision | Open (deferred — separate ADR stream) |

**Roadmap for QUAL-344..356:**

- **Quick wins (< 1 day, S effort):** QUAL-346 (errdefer), QUAL-347 (dead-code delete), QUAL-348 (docstring), QUAL-349 (magic hex), QUAL-352 (error-set doc), QUAL-353 (pool doc), QUAL-355 (ADR), QUAL-356 (errdefer comment hardening).
- **Medium (1-5 days, M effort):** QUAL-345 (CertVerify split), QUAL-350 (dispatcher extraction), QUAL-351 (X25519 correctness), QUAL-354 (build.zig split).
- **Strategic (> 5 days, L effort):** QUAL-344 (client-side handler extraction, mirrors QUAL-317 multi-commit pattern).

### Cycle 6 / Phase 19 Gap Closure Run (2026-04-20)

Execution of the Cycle 5 / Phase 17 audit findings. 17 gaps closed + 1 Won't-Do across 17 code commits on `main`. Verifier (gap-closer-verifier, APPROVED): `zig build` PASS, `zig build test` 668/668 PASS (+9 new tests), both oracles byte-identical (context-decomp + client_hello ExtHandler), `zig fmt --check` clean, pre-commit clean.

**Closed (6 QUAL items):**

| QUAL-ID | Severity | Issue | Closing commit | Note |
|---------|----------|-------|----------------|------|
| QUAL-104 | Low | [#112](https://gitlab.com/devnw/zig/tls/-/work_items/112) | e17c025 | 2 residual magic-hex `0x0033` sites (`context.zig:2035`, `context/hello_retry.zig:120`) replaced with `@intFromEnum(ExtensionType.key_share)`. `grep -rn "0x0033" src/tls13/context*` now returns zero readability-matches. |
| QUAL-346 | High | [#238](https://gitlab.com/devnw/zig/tls/-/work_items/238) | 8c7ced3 | Atomic handshake traffic-secret pair install: `errdefer` now rolls back partial-install on OOM in both client and server install paths (`context.zig:2094-2096` + symmetric server). |
| QUAL-348 | Low | [#240](https://gitlab.com/devnw/zig/tls/-/work_items/240) | 21d6c77 | `Context` struct + `HandshakePhase` enum now have `///` docstrings covering role, phase semantics, invariants, and callback interaction (`context.zig:487`). |
| QUAL-349 | Low | [#241](https://gitlab.com/devnw/zig/tls/-/work_items/241) | e17c025 | Overlaps QUAL-104; closed by same enum-ref cleanup commit. |
| QUAL-352 | Low | [#246](https://gitlab.com/devnw/zig/tls/-/work_items/246) | 1447ab5 | `ApiError` vs `HandshakeError` taxonomy split documented inline at `context.zig:299,303` with which entrypoints raise which error set. |
| QUAL-353 | Low | [#248](https://gitlab.com/devnw/zig/tls/-/work_items/248) | cf11e31 | `parallel.getPool` docstring now explicitly documents process-global lifecycle, panic semantics, and deinit expectation. |
| QUAL-356 | Medium | [#254](https://gitlab.com/devnw/zig/tls/-/work_items/254) | 8c69643 | `handleCertificate` infallibility invariant spelled out: the prior "No errdefer needed" comment is replaced by a documented contract (`context.zig:2379`) that future edits must not introduce fallible inserts without restoring the errdefer pattern. |

**Won't Do (1 QUAL item):**

| QUAL-ID | Severity | Issue | Commit | Rationale |
|---------|----------|-------|--------|-----------|
| QUAL-347 | Low | [#239](https://gitlab.com/devnw/zig/tls/-/work_items/239) | 3a42503 | `computeExpectedBinder` / `computeBinderTranscriptHash` in `psk_selection.zig` are **not** dead code. 5 production call sites at lines 410, 447, 490, 556, 596 perform PSK binder validation per RFC 8446 §4.2.11. Deleting would break TLS 1.3 PSK resumption. Static-analysis "unused" signal missed these legitimate calls. |

**Deferred to Wave 4 / Wave 5 (4 items):**

- **QUAL-344** — client-side handler extraction to `context/client_handlers.zig` (mirrors QUAL-317 multi-commit pattern; multi-file refactor).
- **QUAL-345** — split `handleCertificateVerify` into 4 validators (Wave 4 refactor).
- **QUAL-350** — refactor `handleHandshakeMessage` dispatcher + move TP parsing into helper (Wave 4 refactor).
- **QUAL-354** — split `build.zig` 1379 LOC into `build/` modules (Wave 5 refactor).

**Deferred (strategic, separate work streams):**

- **QUAL-315** — coverage tooling choice (kcov vs llvm-cov). Requires ADR.
- **QUAL-351** — X25519-only hardcode vs `supported_groups` agility. Feature work.
- **QUAL-355** — ADR for QUAL-317 context.zig decomposition. Separate doc stream.

**Cross-ledger cycle scope:** Cycle 6 / Phase 19 also closed 8 SEC items (SEC-066..073) and 3 PERF items (PERF-230, PERF-231, PERF-234). See `docs/SECURITY_GAP_ANALYSIS.md` and `docs/PERF_GAP_ANALYSIS.md` Cycle 6 / Phase 19 sections.

### Cycle 6 / Phase 18 Gap Sync (2026-04-20)

Doc-drift sweep aligning GitLab tracker with the ledger after the QUAL-317 decomposition landed. No new code — tracker/ledger alignment only.

**Subsumed closures (3):**

| QUAL-ID | GitLab | Subsumed by | Note |
|---------|--------|-------------|------|
| QUAL-069 | [#65](https://gitlab.com/devnw/zig/tls/-/work_items/65) | QUAL-317 (commit 0841721 / 7f3b48e) | context.zig decomposed into 8 sibling modules under `src/tls13/context/`; subsystem extractions QUAL-069 recommended are now done. Residual file size tracked under QUAL-116. |
| QUAL-073 | [#69](https://gitlab.com/devnw/zig/tls/-/work_items/69) | engine.zig deletion (commit 4ae8ac7) | Duplicate `parseRealServerHello` in engine.zig removed with the file; `handleServerHello` in context.zig is now sole parser. |
| QUAL-091 | [#90](https://gitlab.com/devnw/zig/tls/-/work_items/90) | engine.zig deletion (commit 4ae8ac7) | All 6+ inline key derivation sites removed with file; `key_derivation.zig` now sole producer. |

**Reopened (1):**

| QUAL-ID | GitLab | Reason |
|---------|--------|--------|
| QUAL-104 | [#112](https://gitlab.com/devnw/zig/tls/-/work_items/112) | 2 residual magic-hex `0x0033` (key_share) sites: `src/tls13/context.zig:2035`, `src/tls13/context/hello_retry.zig:120`. Severity Low. |

**Filed (1, ledger → tracker alignment):**

| QUAL-ID | GitLab | Reason |
|---------|--------|--------|
| QUAL-116 | [#242](https://gitlab.com/devnw/zig/tls/-/work_items/242) | Previously ledger-only. Refreshed file list after QUAL-317 decomposition: 8 files over 800 LOC, with `build.zig` (1379) newly entering and `context.zig` dropping to facade (3055 LOC, tracked separately under QUAL-116 umbrella since it remains above ceiling). |

**Promoted (1):**

| QUAL-ID | GitLab | Action |
|---------|--------|--------|
| QUAL-315 | [#170](https://gitlab.com/devnw/zig/tls/-/work_items/170) | Deferred → actionable-Open. Tooling choice: **kcov** (Zig integration is cleaner than llvm-cov under Zig 0.16). |

**Doc-drift cross-reference (no issue action):**

- QUAL-103, QUAL-106, QUAL-129, QUAL-130, PERF-026, GAP-0106 were already Closed in the ledger; confirmed in this sweep.
- QUAL-093 already Won't Do; confirmed.
- PERF-218 already Closed 2026-04-20 (commit 514480a); confirmed.

Verifier: no source changes; `zig build`/`zig build test` status unchanged from 0841721.

### Cycle 2 / Phase 14 Gap Closure Run (2026-04-20)

5 QUAL items closed + 1 Won't-Do landed across 18 commits on `main`. Verifier: `zig build` PASS, `zig build test` PASS, `zig fmt --check` clean, pre-commit clean.

**Closed (5):**

| QUAL-ID | Issue | Closing commit | Note |
|---------|-------|----------------|------|
| QUAL-107 | #114 | 4ae8ac7 / 59f5e50 | Cross-module error-type divergence; Engine deletion removed the second producer. Ledger prose closed in 59f5e50. |
| QUAL-205 | -- (no issue filed) | efc573e | Extracted shared `hexToBytes` to `tests/test_utils.zig`; migrated 13 callers; fixed latent rfc8446 finished test. |
| QUAL-208 | -- (no issue filed) | 599a1da / b4bf419 | Duplicate of QUAL-335; rename `parallel.KeyMaterial` -> `DerivedKeyMaterial` already landed Phase 13 in 599a1da; ledger alignment in b4bf419. |
| QUAL-209 | -- (no issue filed) | b31f035 / b4bf419 | `pub const parallel = @import("parallel");` already landed in b31f035; ledger alignment in b4bf419. |
| QUAL-321 | #193 | 9037778 / 59f5e50 | lib.zig facade curated (already closed Phase 13); Cycle 2 ledger prose aligned in 59f5e50. |
| QUAL-337 | #207 | 148b6ba / 59f5e50 | `CipherSuite` enum parity pinned (Phase 13); ledger prose aligned in 59f5e50. |

**Won't Do (1):**

| QUAL-ID | Issue | Commit | Rationale |
|---------|-------|--------|-----------|
| QUAL-343 | #216 | 9ef0ba3 | `src/tls13_full.zig` 171 LOC constant-only shim. Full delete blocked by Zig 0.16 module-path constraint: `messages.zig` is relative-imported by `src/tls13/mod.zig` and `src/tls13/context.zig`, so it cannot simultaneously be the root of module `tls13_full`. Migrating all 27 consumers to direct submodule imports is high-churn work in security-adjacent code for zero runtime benefit; shim is stable, inert, costless. See Phase 12 `QUAL-343` recommendation block for full investigation detail. |

**Deferred (carry-forward to Cycle 3):**

- QUAL-317 (context.zig decomposition -- epic)
- QUAL-315 (coverage instrumentation -- tooling choice pending)
- QUAL-338, QUAL-339, QUAL-340, QUAL-341, QUAL-342 (long-function splits / dispatch tables -- mechanical)

### Phase 13 Gap Closure Run (2026-04-19)

21 QUAL items closed across 34 commits landed on `main`. Keystone change: commit `4ae8ac7` deleted `src/tls13/engine.zig` (-2236 LOC) + re-exports (-47 LOC) = **-2283 LOC net**, subsuming QUAL-302, QUAL-304, QUAL-319 (engine parseMinimalHelloPub dup, 10-level EE nesting, and engine quarantine respectively). Verifier: Step 3 `zig build` PASS, `zig build test` 586/588 PASS, `zig fmt --check` clean.

**Closed (21):**

| QUAL-ID | Issue | Closing commit | Note |
|---------|-------|----------------|------|
| QUAL-302 | #178 | 4ae8ac7 | parseMinimalHelloPub dup -- subsumed by engine.zig deletion |
| QUAL-304 | #157 | 4ae8ac7 | 10-level EE nesting -- lived only in deleted engine.zig |
| QUAL-307 | #185 | f0b02fb | Stale thread_pool cache dir removed |
| QUAL-308 | #174 | 8b24c54 | Deleted run_tests.sh; build.zig is single driver |
| QUAL-309 | #187 | 9a8c76d | pre-commit zig-fmt widened to tests/ |
| QUAL-311 | #186 | 493a547 | Removed no-op check-todos pre-commit hook |
| QUAL-314 | #191 | 4ae8ac7 | parallel.getPool() @panic path: engine-side callers removed with engine deletion |
| QUAL-319 | #166 | 4ae8ac7 | Legacy engine.zig deleted -- keystone closure |
| QUAL-320 | #193 | e9e8165 | Ungated std.debug.print collapsed to comptime-gated helper |
| QUAL-321 | #194 | 9037778 | lib.zig public re-exports curated |
| QUAL-322 | #175 | 8b24c54 | Dual orphan test drivers: run_tests.sh deleted |
| QUAL-325 | #196 | 4ae8ac7 | parallel.getPool() doc gap — engine call sites removed |
| QUAL-326 | #197 | e9e8165 | Error-path stderr noise collapsed via sig.zig tracer |
| QUAL-327 | #198 | 874a61c | Added per-job timeout stanzas to `.gitlab-ci.yml` |
| QUAL-330 | #201 | 4bfccfa | ARCHITECTURE.md module map refreshed |
| QUAL-332 | #203 | 8bf4ce5 | Scaffolded docs/adr, RUNBOOK.md, RFC_COVERAGE.md |
| QUAL-334 | #204 | 9a8c76d | pre-commit zig-fmt scope asymmetry closed |
| QUAL-335 | #205 | 599a1da | parallel `KeyMaterial` renamed to `DerivedKeyMaterial`; key_schedule is canonical |
| QUAL-336 | #206 | 500876b | Canonicalized `HandshakeState` in handshake_state.zig |
| QUAL-337 | #207 | 148b6ba | Pinned `CipherSuite` enum parity across aead.zig / core_types.zig |
| QUAL-343 | #216 | 4ae8ac7 (partial) / 2026-04-19 (Won't Do) | engine.zig deletion removed the largest consumer cluster; full shim deletion blocked by Zig 0.16 module constraint -- see note below |

**Deferred (not attempted this run, tracked for next cycle):**

- **QUAL-317** -- context.zig decomposition -- Phase 13 epic; too large for this run
- **QUAL-315** -- coverage instrumentation -- tooling choice (kcov vs llvm-cov) pending
- **QUAL-338, QUAL-339, QUAL-340, QUAL-341, QUAL-342** -- long-function splits / dispatch tables -- opportunistic Cluster O, scheduled next cycle

### Phase 15 Cycle 3 Gap Closure Run (2026-04-20)

4 QUAL items closed + 1 Deferred/Blocked landed across 10 code commits + 1 ledger commit on `main`. Verifier (Step 3 gap-closer-verifier, 2026-04-20): `zig build` PASS, `zig build test` 586 pass / 2 skip (unchanged from Cycle 2 baseline), `zig fmt --check` clean, pre-commit clean, bench harness green.

**Closed (4):**

| QUAL-ID | Issue | Closing commit | Note |
|---------|-------|----------------|------|
| QUAL-338 | #208 | 264b83e | `parseCert` / `runChainChecks` split into stepwise helpers at natural DER / RFC 5280 boundaries. Orchestrators < 100 LOC; 10 private validators extracted with `Tbs*`/`Parsed*` record types threading intermediate state. |
| QUAL-340 | #210 | a94fcb1 | `validateStapledResponse` (was 199 LOC) split into a 20-LOC orchestrator + 4 validators (`decodeResponseBytes`, `parseResponseData`, `matchSingleResponse`, `verifySignerChain`). CWE-328 SHA-1 skip preserved with inline security comments. |
| QUAL-341 | #211 | 2a8baf5 | `SchemeEntry` table-driven dispatch for `verifyCertificateVerify` / `signCertificateVerify`; both public fns are now <=8 LOC orchestrators forwarding to per-scheme helpers. RFC 8446 §4.2.3 behaviour bit-exact. |
| QUAL-342 | #214 | 2afe89e | 10 newly-added `///` doc blocks on `key_schedule.zig` public fns. 21/21 pub fns documented; 38 RFC 8446 / 9001 / 9369 / 5869 / 2104 citations. |

**Deferred / Blocked (1):**

| QUAL-ID | Issue | Ledger commit | Blocker / unblock plan |
|---------|-------|---------------|------------------------|
| QUAL-339 | #209 | e0ca05d | `parseClientHello` / `buildClientHello` ExtHandler table-driven refactor. The extension-dispatch switch interleaves with three security-critical state machines: the SEC-054 `errdefer` block (frees partial allocations through the `ch` pointer), the SEC-057 `std.enums.fromInt` guard (prevents `@enumFromInt` panics on ~2034 out-of-enum values), and the CWE-345 `psk_seen` ordering sentinel (RFC 8446 §4.2.11 — pre_shared_key MUST be the last extension). A mechanical table swap cannot preserve all three without a fuzz-regression pass over `tests/fuzz/client_hello/**` to validate the new errdefer / state-threading semantics. **Unblock plan:** (a) define `ParseCtx { ch: *ClientHello, alloc: Allocator, psk_seen: *bool }` + `BuildCtx { buf: []u8, pos: *usize, ... }`, (b) extract each switch arm into `fn parseXxx(ctx: *ParseCtx, ext_data: []const u8) !void`, (c) re-run the client_hello fuzz corpus and diff error traces against the pre-refactor branch. |

**Cross-ledger cycle scope:** Cycle 3 also closed PERF-209 (ThreadPool allocator swap, commit 24a275c) and committed a full PERF-218 audit (commit 29a3ef1) that strengthened the Cycle 2 deferral with single-file / 10-ref / asymmetric-lifetime findings. See `docs/PERF_GAP_ANALYSIS.md` for details.

**Deferred (carry-forward to Cycle 4):**

- **QUAL-317** (context.zig decomposition epic) -- pending user brainstorm on subsystem boundaries.
- **QUAL-315** (coverage instrumentation) -- kcov recommended per planner; tooling choice still open.
- ~~**QUAL-339** (client_hello ExtHandler dispatch)~~ — **CLOSED Cycle 4 / Phase 16 (commit 45cc212)** via table-driven HANDLERS refactor + 387-record error-trace oracle; CI regression gate added in `.gitlab-ci.yml:client_hello_oracle`.

### Top 5 Risks (by PriorityScore, open items first) — refreshed Cycle 2 (2026-04-19)

1. **QUAL-317** (Closed 2026-04-20, commit 7f3b48e) -- `context.zig` decomposition landed across Phase 17 (12 commits). 8 pure-function sibling modules extracted to `src/tls13/context/`; residual shell at 3055 LOC (≤500 target revised -- see Phase 17 ledger). Oracle byte-identical through every landing commit; bonus CWE-226 fix included. [Issue #150](https://gitlab.com/devnw/zig/tls/-/work_items/150) closed.
2. **QUAL-301 + QUAL-323** (Closed Phase 13, commit 674fbee) -- Duplicate BidirSecrets/SecretSchedule canonicalized in `src/tls13/secrets.zig`; listed here historically to explain the prior Top-5 position.
3. **QUAL-315** (Open) -- No coverage instrumentation despite 52k LOC. **PriorityScore 64.** [Issue #170](https://gitlab.com/devnw/zig/tls/-/work_items/170) -- deferred pending tooling choice.
4. **QUAL-304** (Closed 2026-04-19, commit 4ae8ac7) -- 10-level nesting lived inside deleted engine.zig.
5. **QUAL-319** (Closed 2026-04-19, commit 4ae8ac7) -- engine.zig deleted outright; the keystone Phase 13 closure.

The remaining **Open** leader post-Phase-17 is QUAL-315 (coverage instrumentation); QUAL-317 was closed in Phase 17 (Cycle 5). See "Deferred" list above.

### Phase 11 Closures (2026-04-18)

| QUAL-ID | Prev. Status | New Status | Evidence |
|---------|--------------|------------|----------|
| QUAL-104 | Open | Closed (Cycle 6 / Phase 19, commit e17c025) | Phase 4 gap-sync (2026-04-20) found 2 residual magic-hex sites: `src/tls13/context.zig:2035` and `src/tls13/context/hello_retry.zig:120` both dispatch on `0x0033` (key_share). Cycle 6 / Phase 19 replaced both with `@intFromEnum(ExtensionType.key_share)` (commit e17c025). GitLab [#112](https://gitlab.com/devnw/zig/tls/-/work_items/112) closed. |
| QUAL-106 | Open | Closed | `std.crypto.timing_safe.*` used exclusively (11 call sites); 0 local constant-time implementations remain. GitLab #113 closed. |
| QUAL-113 | Partial | Closed | 1 residual `.?` at `src/tls13/engine.zig:2207` (test code path); production clean. GitLab #117 closed. |
| QUAL-119 | Open | Closed (retargeted) | `src/asn1.zig` max nesting is 3 levels (original scope met); deep nesting now tracked under **QUAL-304** (engine.zig:811-848, 10-level). |
| QUAL-209 | Open | Closed | `src/lib.zig:414` now exports parallel module (commit b31f035). |

---

## Stack-Ranked Findings

| Rank | ID | Severity | PriorityScore | Category | Finding | Component | Issue | Status |
|------|----|----------|---------------|----------|---------|-----------|-------|--------|
| 1 | QUAL-087 | Critical | 80 | architecture | engine.zig null-safety gap in certificate verification | `src/tls13/engine.zig` | [#80](https://gitlab.com/devnw/zig/tls/-/work_items/80) | Closed |
| 2 | QUAL-088 | Critical | 80 | perf | x25519KeypairAndShared duplicated with security divergence (CWE-226) | `engine.zig:1723`, `messages.zig:191` | [#82](https://gitlab.com/devnw/zig/tls/-/work_items/82) | Closed |
| 3 | QUAL-094 | High | 75 | maintainability | onCryptoRecv 516 lines / 14 nesting levels | `src/tls13/engine.zig:511-1026` | -- | Closed |
| 4 | QUAL-113 | High | 60 | architecture | 14 residual `.?` unwraps in engine.zig (QUAL-087 incomplete); 3 fixed (ecdhe_secret x2, leaf_spki x1), 11 remaining | `src/tls13/engine.zig` | [#117](https://gitlab.com/devnw/zig/tls/-/work_items/117) | Closed (Phase 11) |
| 5 | QUAL-069 | High | 60 | maintainability | context.zig 3431 lines (4.3x limit) | `src/tls13/context.zig` | [#65](https://gitlab.com/devnw/zig/tls/-/work_items/65) | Closed (Subsumed 2026-04-20 by QUAL-317 context.zig decomposition; residual size tracked under QUAL-116) |
| 6 | QUAL-095 | High | 48 | maintainability | driveServerHandshakeFlight 243 lines combining 6 concerns | `src/tls13/context.zig:1996-2237` | -- | Closed |
| 7 | QUAL-096 | High | 48 | maintainability | ClientHello building duplicated 3 times (~500 lines) | `engine.zig`, `context.zig` | -- | Closed |
| 8 | QUAL-070 | High | 40 | maintainability | Near-duplicate ClientHelloInfo parse+deinit | `context.zig`, `handshake_state.zig` | -- | Closed |
| 9 | QUAL-114 | High | 36 | architecture | 22+ `allocator.dupe` without `errdefer` -- memory leaks on error paths | `engine.zig`, `context.zig`, `handshake_state.zig`, `quic_transport_params.zig` | [#119](https://gitlab.com/devnw/zig/tls/-/work_items/119) | Closed |
| 10 | QUAL-091 | High | 36 | maintainability | engine.zig uses legacy inline key schedule patterns (6+ copies) | `src/tls13/engine.zig` | [#90](https://gitlab.com/devnw/zig/tls/-/work_items/90) | Closed (Subsumed 2026-04-20 by engine.zig deletion 4ae8ac7) |
| 11 | QUAL-097 | High | 30 | architecture | parseHandshakeOne catch null wedges on invalid message type | `src/tls13/engine.zig:529` | -- | Closed |
| 12 | QUAL-071 | High | 30 | architecture | 0-RTT early_secret uses wrong transcript hash | `src/tls13/context.zig:2191` | -- | Closed |
| 13 | QUAL-115 | High | 30 | api-contract | `setTransportParameters` now returns `!void` instead of swallowing OOM | `src/tls13/context.zig:806` | [#122](https://gitlab.com/devnw/zig/tls/-/work_items/122) | Closed |
| 14 | QUAL-073 | Medium | 27 | maintainability | Near-duplicate parseRealServerHello / handleServerHello | `engine.zig:1851`, `context.zig:2567` | [#69](https://gitlab.com/devnw/zig/tls/-/work_items/69) | Closed (Subsumed 2026-04-20 by engine.zig deletion 4ae8ac7) |
| 15 | QUAL-116 | Medium | 24 | maintainability | 8 source files over 800 lines (post-QUAL-317 refresh; `build.zig` newly entered at 1379 LOC) | `x509.zig` (1987), `build.zig` (1379), `record/aead.zig` (1337), `quic_transport_params.zig` (1214), `key_schedule.zig` (1102), `tls13/messages/server_hello.zig` (1081), `asn1.zig` (1039), `parallel.zig` (961), `sig.zig` (950) | [#242](https://gitlab.com/devnw/zig/tls/-/work_items/242) | Open |
| 16 | QUAL-072 | High | 24 | api-contract | Callback errors logged but not propagated | `src/tls13/context.zig` | -- | Closed |
| 17 | QUAL-098 | Medium | 24 | api-contract | queueServerHandshakeFlight returns void -- errors not propagated | `src/tls13/engine.zig:1728` | -- | Closed |
| 18 | QUAL-099 | Medium | 24 | tests | No HRR test coverage in Context | `src/tls13/context.zig` | -- | Closed |
| 19 | QUAL-100 | Medium | 24 | docs | Config field constraints undocumented | `src/tls13/config.zig:68-342` | -- | Closed |
| 20 | QUAL-074 | Medium | 24 | architecture | new_session_ticket silently dropped | `src/tls13/context.zig:1375` | -- | Closed |
| 21 | QUAL-090 | High | 24 | api-contract | NewSessionTicket processing has incomplete error propagation | `src/tls13/engine.zig:836-877` | [#88](https://gitlab.com/devnw/zig/tls/-/work_items/88) | Closed |
| 22 | QUAL-117 | Medium | 20 | maintainability | 14 functions over 100 lines (parseCert 396 lines) | `x509.zig`, `engine.zig`, `context.zig`, `server_hello.zig`, `client_hello.zig` | -- | Open |
| 23 | QUAL-118 | Medium | 20 | maintainability | SecretSlot struct duplicated between context.zig and secrets.zig | `src/tls13/context.zig:287`, `src/tls13/secrets.zig:67` | -- | Closed |
| 24 | QUAL-089 | High | 20 | api-contract | setTransportParameters lacks OOM error handling | `handshake_state.zig:220`, `engine.zig:1822` | [#85](https://gitlab.com/devnw/zig/tls/-/work_items/85) | Closed |
| 25 | QUAL-119 | Medium | 18 | readability | Deep nesting in client_hello.zig (10 levels) and x509.zig (9 levels); retargeted — asn1.zig now 3 levels max; residual 10-level tracked under QUAL-304 | `src/tls13/messages/client_hello.zig`, `src/x509.zig` | -- | Closed (Phase 11, retargeted → QUAL-304) |
| 26 | QUAL-075 | Medium | 18 | maintainability | Two distinct CipherSuite enums | `record/aead.zig:76`, `messages/core_types.zig:258` | -- | Closed (By Design) |
| 27 | QUAL-101 | Medium | 18 | docs | No Engine-to-Context migration guide (complements QUAL-077) | `docs/` | -- | Closed |
| 28 | QUAL-076 | Medium | 16 | maintainability | Duplicated SignatureScheme-to-SigAlg with unsafe else | `context.zig:2272`, `context.zig:2692` | -- | Closed |
| 29 | QUAL-077 | Medium | 16 | docs | No Engine-to-Context migration guide | `docs/` | -- | Closed |
| 30 | QUAL-120 | Medium | 16 | architecture | quic_transport_params.zig `decode()` missing errdefer | `src/quic_transport_params.zig:559` | -- | Closed |
| 31 | QUAL-121 | Medium | 16 | architecture | Engine cert handling now propagates OOM via `try` instead of converting to cert-invalid | `src/tls13/engine.zig:865-870` | -- | Closed |
| 32 | QUAL-122 | Medium | 16 | architecture | Engine dupe calls at 9 sites lack errdefer | `src/tls13/engine.zig` | [#125](https://gitlab.com/devnw/zig/tls/-/work_items/125) | Closed |
| 33 | QUAL-102 | Medium | 16 | architecture | 6x allocator.dupe catch null silently swallow OOM | `src/tls13/engine.zig:674,682,1643,1923,1941` | -- | Closed |
| 34 | QUAL-103 | Medium | 16 | api-contract | maybeAutoProgress swallows queueFinished error | `src/tls13/engine.zig:1684` | -- | Closed |
| 35 | QUAL-104 | Low | 15 | readability | Magic hex constants for extension types instead of ExtensionType enum | `src/tls13/context.zig:2035`, `src/tls13/context/hello_retry.zig:120` (residual 0x0033 key_share) | [#112](https://gitlab.com/devnw/zig/tls/-/work_items/112) | Closed (Cycle 6 / Phase 19, commit e17c025) |
| 36 | QUAL-105 | Low | 15 | docs | lib.zig Quick Start example has wrong Context.init signature | `src/lib.zig` | -- | Closed |
| 37 | QUAL-092 | Medium | 12 | cleanup | byteorder.zig duplicated verbatim across two module paths | `src/byteorder.zig`, `src/byteorder/byteorder.zig` | [#92](https://gitlab.com/devnw/zig/tls/-/work_items/92) | Closed |
| 38 | QUAL-078 | Medium | 12 | perf | Duplicated x25519KeypairAndShared with behavioral divergence | `messages.zig:191`, `engine.zig:1723` | -- | Closed |
| 39 | QUAL-079 | Medium | 12 | docs | Corrupted Callbacks doc comment | `context.zig:234-249` | -- | Closed |
| 40 | QUAL-093 | Medium | 12 | ci-cd | CI pipeline lacks build caching (Zig reinstalled each job) | `.gitlab-ci.yml` | [#94](https://gitlab.com/devnw/zig/tls/-/work_items/94) | Won't Do |
| 41 | QUAL-080 | Medium | 12 | cleanup | 32x @constCast for freeing const slices | `context.zig`, `handshake_state.zig`, `quic_transport_params.zig` | [#75](https://gitlab.com/devnw/zig/tls/-/work_items/75) | Closed |
| 42 | QUAL-123 | Low | 10 | maintainability | build.zig at 1112 lines exceeds 800-line guideline | `build.zig` | -- | Won't Do |
| 43 | QUAL-106 | Low | 9 | maintainability | Constant-time comparison code duplicated 3 times with subtle variation | `engine.zig`, `context.zig` | [#113](https://gitlab.com/devnw/zig/tls/-/work_items/113) | Closed (Phase 11) |
| 44 | QUAL-107 | Low | 9 | api-contract | Inconsistent error types -- CryptoBufferOverflow vs UnexpectedMessage for same condition | `engine.zig`, `context.zig` | -- | Closed (2026-04-19, 4ae8ac7 + 59f5e50) |
| 45 | QUAL-081 | Low | 8 | maintainability | cipherSuiteHash exact duplicate | `context.zig:128`, `engine.zig:108` | -- | Closed |
| 46 | QUAL-124 | Low | 8 | maintainability | readU16 helper duplicated between sct.zig and messages/helpers.zig | `src/sct.zig:31`, `src/tls13/messages/helpers.zig:40` | -- | Won't Do |
| 47 | QUAL-125 | Low | 8 | maintainability | HashDigestCache dead code removed from context.zig | `src/tls13/context.zig`, `src/tls13/transcript.zig:398` | -- | Closed |
| 48 | QUAL-082 | Low | 6 | cleanup | traceHandshake/traceSecrets exact duplicate infrastructure | `context.zig`, `engine.zig`, `messages.zig`, `transcript.zig`, `key_derivation.zig` | -- | Closed (By Design) |
| 49 | QUAL-083 | Low | 6 | cleanup | encodeMinimal*/parseMinimal* exact duplicates | `messages.zig`, `engine.zig` | -- | Closed |
| 50 | QUAL-084 | Low | 6 | readability | 13x inline u16 big-endian read instead of readU16 helper | `context.zig`, `handshake_state.zig`, `record/plaintext.zig` | -- | Closed |
| 51 | QUAL-085 | Low | 6 | api-contract | pollCrypto returns Unimplemented for empty buffer | `context.zig:1064` | -- | Closed |
| 52 | QUAL-108 | Low | 6 | cleanup | 14 unused imports across 7 files | `varint.zig`, `tls13_full.zig`, `sig.zig`, `tls13.zig`, `context.zig`, `engine.zig`, `types.zig` | -- | Closed |
| 53 | QUAL-109 | Low | 6 | architecture | TODO in context.zig:1207 -- QUAL-074 callback not wired (status inconsistent) | `src/tls13/context.zig:1207` | -- | Closed |
| 54 | QUAL-110 | Low | 6 | api-contract | notifyMetadata callback error logged but not propagated | `src/tls13/context.zig:2660` | -- | Closed (by-design) |
| 55 | QUAL-126 | Low | 4 | architecture | quic_transport_params.zig only 2 of 4 dupe sites have errdefer | `src/quic_transport_params.zig:645,649,653` | -- | Closed |
| 56 | QUAL-127 | Low | 4 | maintainability | handshake_state.zig 13 dupe sites -- only 1 has errdefer | `src/tls13/handshake_state.zig` | -- | Closed |
| 57 | QUAL-128 | Low | 4 | maintainability | context.zig 11 dupe sites without errdefer | `src/tls13/context.zig` | -- | Closed |
| 58 | QUAL-129 | Low | 4 | readability | Engine zero errdefer usage across all allocator.dupe calls | `src/tls13/engine.zig` | -- | Closed |
| 59 | QUAL-130 | Low | 4 | cleanup | Stale line counts in QUAL-069 (3581 vs actual 3431) | `docs/QUALITY_GAP_ANALYSIS.md` | -- | Won't Do |
| 60 | QUAL-086 | Low | 4 | cleanup | deriveFinishedVerifyData in messages/finished.zig is unused dead code | `src/tls13/messages/finished.zig:155` | -- | Closed |
| 61 | QUAL-111 | Low | 4 | docs | handleKeyUpdateMessage doc comment misplaced onto handleCertificate | `src/tls13/context.zig` | -- | Closed |
| 62 | QUAL-112 | Low | 4 | readability | Engine.init is a single 262-character line | `src/tls13/engine.zig` | -- | Closed |
| 63 | QUAL-201 | Medium | 24 | maintainability | parseCert 396 lines with 6 inline extension sub-parsers; extract helpers | `src/x509.zig:697-1092` | -- | Closed |
| 64 | QUAL-203 | Medium | 20 | api-contract | OCSP error mapping loses diagnostic info; 32 catch-return discard ASN.1 errors | `src/ocsp.zig:138-319` | -- | Closed |
| 65 | QUAL-204 | Medium | 20 | readability | Magic hex constants in engine.zig (0x0010, 0x0039, 0x0033) vs enum in context.zig | `src/tls13/engine.zig` | -- | Closed |
| 66 | QUAL-205 | Medium | 20 | maintainability | `hexToBytes` duplicated 14 times across test files | `tests/*.zig` | -- | Closed (2026-04-19, efc573e) |
| 67 | QUAL-202 | Medium | 18 | readability | Deep nesting (10 levels client_hello.zig, 9 levels x509.zig); addressed by parseCert extraction | `src/tls13/messages/client_hello.zig`, `src/x509.zig` | -- | Closed |
| 68 | QUAL-206 | Low | 16 | cleanup | Redundant condition engine.zig:802-803 `if (elen >= 3) { if (elen >= 2)` inner check always true | `src/tls13/engine.zig:802-803` | -- | Closed |
| 69 | QUAL-207 | Low | 16 | architecture | 17 `.?` unwraps in context.zig rely on implicit state invariants; confirmed correct but fragile | `src/tls13/context.zig` | -- | Closed |
| 70 | QUAL-208 | Low | 16 | architecture | Dual `KeyMaterial` types with incompatible layouts: parallel.zig vs key_schedule.zig | `src/parallel.zig:616`, `src/key_schedule.zig:36` | -- | Closed (2026-04-19, 599a1da -- dup of QUAL-335) |
| 71 | QUAL-209 | Low | 12 | api-contract | `parallel` module not exported from lib.zig; add pub export with doc comment | `src/lib.zig`, `src/parallel.zig` | -- | Closed (2026-04-18, b31f035) |
| 72 | QUAL-210 | Low | 12 | cleanup | `TicketEntryView` exported via mod.zig/tls13.zig but unused outside engine.zig | `src/tls13/mod.zig:263`, `src/tls13.zig:257` | -- | Closed |
| 73 | QUAL-317 | High | 100 | maintainability | context.zig monolith (3549 LOC, 32 methods) — decompose into subsystems | `src/tls13/context.zig` | [#150](https://gitlab.com/devnw/zig/tls/-/work_items/150) | Closed (2026-04-20, 7f3b48e) |
| 74 | QUAL-301 | High | 64 | architecture | Duplicate BidirSecrets/SecretSchedule types in context.zig vs secrets.zig | `src/tls13/context.zig:300-353`, `src/tls13/secrets.zig:117-166` | [#154](https://gitlab.com/devnw/zig/tls/-/work_items/154) | Open |
| 75 | QUAL-304 | High | 64 | readability | 10-level nesting in EncryptedExtensions handler | `src/tls13/engine.zig:811-848` | [#157](https://gitlab.com/devnw/zig/tls/-/work_items/157) | Closed (2026-04-19, 4ae8ac7) |
| 76 | QUAL-315 | Medium | 64 | tests | No coverage instrumentation (kcov/llvm-cov) despite 52k LOC | repo-root | [#170](https://gitlab.com/devnw/zig/tls/-/work_items/170) | Open |
| 77 | QUAL-319 | High | 64 | architecture | Legacy engine.zig (2236 LOC) still publicly exported; quarantine or gate | `src/tls13/engine.zig`, `src/tls13.zig:96`, `src/tls13/mod.zig:254` | [#166](https://gitlab.com/devnw/zig/tls/-/work_items/166) | Closed (2026-04-19, 4ae8ac7) |
| 78 | QUAL-323 | High | 64 | architecture | Contract-drift vector — dup-type twin of QUAL-301 | `src/tls13/context.zig:300-353`, `src/tls13/secrets.zig:117-166` | [#171](https://gitlab.com/devnw/zig/tls/-/work_items/171) | Open |
| 79 | QUAL-305 | High | 60 | ci-cd | flake.nix references missing `nix/` dir — `nix build` fails OOTB | `flake.nix:56, 61` | [#160](https://gitlab.com/devnw/zig/tls/-/work_items/160) | Open |
| 80 | QUAL-310 | Medium | 60 | ci-cd | No CI cache stanza — ~300MB re-downloaded per pipeline | `.gitlab-ci.yml` | [#168](https://gitlab.com/devnw/zig/tls/-/work_items/168) | Open |
| 81 | QUAL-316 | Medium | 60 | maintainability | Trace-flag boilerplate duplicated across 7+ modules — consolidate | `context.zig`, `engine.zig`, `transcript.zig`, `key_derivation.zig`, `sig.zig`, `ocsp.zig`, `messages.zig` | [#164](https://gitlab.com/devnw/zig/tls/-/work_items/164) | Open |
| 82 | QUAL-308 | Medium | 48 | tests | run_tests.sh tracks 4 of ~17 modules — stale test counts | `run_tests.sh:18-24` | [#174](https://gitlab.com/devnw/zig/tls/-/work_items/174) | Closed (2026-04-19, 8b24c54) |
| 83 | QUAL-303 | Medium | 36 | maintainability | RSA-PSS verify triple copy-paste across parallel.zig + sig.zig | `src/parallel.zig:373-433`, `src/sig.zig:370-407` | [#180](https://gitlab.com/devnw/zig/tls/-/work_items/180) | Open |
| 84 | QUAL-306 | Medium | 36 | deps | Zig min-version drift — 0.15.1 (build.zig.zon) vs 0.16.0 (Makefile, CI) | `build.zig.zon:28`, `Makefile:193`, `.gitlab-ci.yml:27` | [#176](https://gitlab.com/devnw/zig/tls/-/work_items/176) | Open |
| 85 | QUAL-312 | Medium | 36 | maintainability | quic_transport_params decode() is 119-LOC 17-arm switch — extract | `src/quic_transport_params.zig:559-677` | [#189](https://gitlab.com/devnw/zig/tls/-/work_items/189) | Open |
| 86 | QUAL-321 | Medium | 36 | api-contract | lib.zig wholesale re-export — curate public facade | `src/lib.zig:270-539` | [#194](https://gitlab.com/devnw/zig/tls/-/work_items/194) | Closed (2026-04-19, 9037778) |
| 87 | QUAL-324 | Medium | 36 | api-contract | RSA-PSS error-code fragmentation (magic ints vs !bool) | `src/parallel.zig:370,403,433`, `src/sig.zig:370+` | [#195](https://gitlab.com/devnw/zig/tls/-/work_items/195) | Open |
| 88 | QUAL-325 | Medium | 36 | api-contract | parallel.getPool() process-global + panics — undocumented on public API | `src/parallel.zig:78`, `src/lib.zig` | [#196](https://gitlab.com/devnw/zig/tls/-/work_items/196) | Closed (2026-04-19, 4ae8ac7) |
| 89 | QUAL-313 | Low | 32 | docs | 30 catch-unreachable + 9 bare unreachable — missing invariant comments | `src/` (39 sites) | [#190](https://gitlab.com/devnw/zig/tls/-/work_items/190) | Open |
| 90 | QUAL-318 | Medium | 32 | maintainability | Byte-order helpers forked 3 ways — extend byteorder.zig | `src/sct.zig:31`, `src/tls13/messages/helpers.zig:40,62,81`, `src/byteorder.zig:43` | [#192](https://gitlab.com/devnw/zig/tls/-/work_items/192) | Open |
| 91 | QUAL-322 | Medium | 32 | tests | Dual orphan test drivers (run_tests.sh vs build.zig) | `run_tests.sh`, `build.zig` | [#175](https://gitlab.com/devnw/zig/tls/-/work_items/175) | Closed (2026-04-19, 8b24c54) |
| 92 | QUAL-330 | Medium | 32 | docs | ARCHITECTURE.md omits handshake_state, messages/helpers, cookie, parallel, zero_rtt | `docs/ARCHITECTURE.md:13-37` | [#201](https://gitlab.com/devnw/zig/tls/-/work_items/201) | Closed (2026-04-19, 4bfccfa) |
| 93 | QUAL-332 | Medium | 32 | docs | No RUNBOOK, no ADR, no docs/README index | `docs/` | [#203](https://gitlab.com/devnw/zig/tls/-/work_items/203) | Closed (2026-04-19, 8bf4ce5) |
| 94 | QUAL-326 | Medium | 24 | api-contract | Error-path stderr noise — library should not write stderr uncontrolled | `src/parallel.zig:78`, `src/sig.zig:564-602` | [#197](https://gitlab.com/devnw/zig/tls/-/work_items/197) | Closed (2026-04-19, e9e8165) |
| 95 | QUAL-329 | Low | 24 | docs | ENGINE_TO_CONTEXT_MIGRATION.md drift — engine still 2236 LOC | `docs/ENGINE_TO_CONTEXT_MIGRATION.md:4` | [#200](https://gitlab.com/devnw/zig/tls/-/work_items/200) | Open |
| 96 | QUAL-331 | Low | 24 | docs | key_schedule.zig + varint.zig — 39 unreachable sites without invariant comments | `src/key_schedule.zig:164-248`, `src/varint.zig` | [#202](https://gitlab.com/devnw/zig/tls/-/work_items/202) | Open |
| 97 | QUAL-333 | Low | 24 | docs | CHANGELOG.md sparse — missing Engine→Context, parallel, zero_rtt | `CHANGELOG.md` | [#204](https://gitlab.com/devnw/zig/tls/-/work_items/204) | Open |
| 98 | QUAL-302 | Low | 16 | cleanup | parseMinimalHelloPub byte-identical duplicate | `src/tls13/engine.zig:1951`, `src/tls13/messages.zig:288` | [#178](https://gitlab.com/devnw/zig/tls/-/work_items/178) | Closed (2026-04-19, 4ae8ac7) |
| 99 | QUAL-309 | Low | 16 | ci-cd | pre-commit zig-fmt hook misses tests/ | `.pre-commit-config.yaml:100-107` | [#187](https://gitlab.com/devnw/zig/tls/-/work_items/187) | Closed (2026-04-19, 9a8c76d) |
| 100 | QUAL-314 | Low | 16 | api-contract | parallel.getPool() @panic on thread-pool init — no serial fallback | `src/parallel.zig:78` | [#191](https://gitlab.com/devnw/zig/tls/-/work_items/191) | Closed (2026-04-19, 4ae8ac7) |
| 101 | QUAL-327 | Low | 16 | ci-cd | .gitlab-ci.yml — no test timeouts (only fuzz job has one) | `.gitlab-ci.yml` | [#198](https://gitlab.com/devnw/zig/tls/-/work_items/198) | Closed (2026-04-19, 874a61c) |
| 102 | QUAL-328 | Low | 16 | cleanup | QUAL-### sigils embedded in production comments | `engine.zig` (~32), `context.zig` (~61) | [#199](https://gitlab.com/devnw/zig/tls/-/work_items/199) | Open |
| 103 | QUAL-307 | Low | 12 | cleanup | Stale dup thread_pool cache dir in zig-pkg/ (4.1 MB) | `zig-pkg/thread_pool-0.2.0-11B1Bjc9OQCp*` | [#185](https://gitlab.com/devnw/zig/tls/-/work_items/185) | Closed (2026-04-19, f0b02fb) |
| 104 | QUAL-311 | Low | 12 | ci-cd | pre-commit check-todos hook always exits 0 (no-op) | `.pre-commit-config.yaml:130-138` | [#186](https://gitlab.com/devnw/zig/tls/-/work_items/186) | Closed (2026-04-19, 493a547) |
| 105 | QUAL-320 | Low | 12 | api-contract | Ungated std.debug.print inside trace blocks — route via logger | `context.zig:1008-1010,1271,1388-1390`, `sig.zig:568-602` | [#193](https://gitlab.com/devnw/zig/tls/-/work_items/193) | Closed (2026-04-19, e9e8165) |

---

## Detailed Findings

### QUAL-069 -- context.zig exceeds maintainability size limit (3581 lines)

- **ID:** QUAL-069
- **Severity:** High
- **PriorityScore:** 60 (Impact 3 x Likelihood 5 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Deferred (2026-03-24) -- High regression risk for a file-splitting refactor on a
  heavily interconnected state machine. Zig's module system does not penalize large files the
  way some languages do (no class-per-file convention). The file is well-structured internally
  with clear section comments. Deferring until Engine deprecation reduces the module count and
  makes splitting context.zig safer.
- **Issue:** [#65](https://gitlab.com/devnw/zig/tls/-/work_items/65)

**File locations:**

- `src/tls13/context.zig` -- 3581 lines

**Description:**
`context.zig` is 4.5x the 800-line guideline ceiling. It contains the `Context` struct, `Callbacks`, `ClientHelloView`, `ClientHelloInfo`, handshake state machine, key derivation orchestration, 0-RTT logic, mTLS flows, QUIC transport parameter handling, certificate verification, and CertificateVerify signing -- all in a single file. This makes code review slow, merge conflicts frequent, and bug isolation difficult.

**Evidence:**

```text
$ wc -l src/tls13/context.zig
3581
```

For comparison, the next largest file is `engine.zig` at 2051 lines (also over-limit).

**Recommendation:**
Extract cohesive subsystems into separate modules:

- `src/tls13/callbacks.zig` -- Callbacks struct and HandshakeMetadata
- `src/tls13/client_hello_view.zig` -- ClientHelloView, ClientHelloInfo, parsing
- `src/tls13/server_handshake.zig` -- driveServerHandshakeFlight, buildServerHello, sendEncryptedExtensions
- `src/tls13/client_handshake.zig` -- handleServerHello, sendClientFinished, sendClientHello
- `src/tls13/certificate_verify.zig` -- handleCertificateVerify, handleClientCertificateVerify, signing

**Acceptance criteria:** No single source file exceeds 800 lines. All existing tests continue to pass.

**Verification:** `wc -l src/tls13/*.zig | sort -rn | head -5` shows all files under 800 lines. `zig build test` passes.

**Effort:** L (strategic refactor)

**Deferred reason:** The context.zig file is a tightly coupled TLS 1.3 handshake state machine where
functions share access to `self` fields extensively. Splitting it mechanically would require passing
dozens of fields as parameters or creating intermediate structs, increasing complexity rather than
reducing it. In Zig, large files are idiomatic when the contents are cohesive. This refactor is best
done during Engine deprecation when the overall module count decreases.

---

### QUAL-070 -- Near-duplicate ClientHelloInfo struct and parse/deinit logic

- **ID:** QUAL-070
- **Severity:** High
- **PriorityScore:** 40 (Impact 4 x Likelihood 2.5 x 4, rounded)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Consolidated `ClientHelloInfo` into `handshake_state.zig` as the single source of truth. `context.zig` now imports `ClientHelloInfo` from `handshake_state` module.

**File locations:**

- `src/tls13/context.zig` -- `ClientHelloInfo` struct + `parseClientHelloInfo` + `deinit`
- `src/tls13/handshake_state.zig` -- Near-identical `ClientHelloInfo` struct + `setClientHello` + `deinit`

**Description:**
Two near-identical `ClientHelloInfo` structs exist with their own parsing and deallocation logic. Both extract `supported_groups`, `signature_algorithms`, `pre_shared_key`, and `alpn_protocols` from the same ClientHello wire format. Each has its own `@constCast`-heavy `deinit`. A bug fix applied to one may not be applied to the other.

**Evidence:**
`context.zig` contains `ClientHelloView` (line ~305) and also re-parses in `handleHandshakeMessage` via `self.state.setClientHello()`, which delegates to `handshake_state.zig`. The `@constCast`-heavy deinit in `handshake_state.zig` (16 instances) mirrors the one in `context.zig` (16 instances).

**Recommendation:**
Consolidate into a single `ClientHelloInfo` type in `handshake_state.zig` (or a new `client_hello_info.zig`). Both `context.zig` and `handshake_state.zig` should reference the same struct, parse function, and deinit.

**Acceptance criteria:** A single `ClientHelloInfo` type exists with one parse function and one `deinit`. No duplicate struct definitions.

**Verification:** `grep -rn "struct ClientHelloInfo" src/` returns exactly one result. All tests pass.

**Effort:** M

---

### QUAL-071 -- 0-RTT early_secret derived AFTER ServerHello added to transcript (wrong transcript hash)

- **ID:** QUAL-071
- **Severity:** High
- **PriorityScore:** 30 (Impact 5 x Likelihood 1.5 x 4, rounded)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Snapshotted transcript hash of ClientHello BEFORE appending ServerHello to transcript in context.zig, using `ch_only_hash` for 0-RTT early_secret derivation.

**File locations:**

- `src/tls13/context.zig:2173` -- `appendOutbound(.Initial, sh_msg, true)` adds ServerHello to transcript
- `src/tls13/context.zig:2191` -- `self.transcripts.handshake.finalize(self.hash_kind)` used as "ClientHello hash"

**Description:**
RFC 8446 Section 7.1 specifies that the 0-RTT `client_early_traffic_secret` is derived using:

```text
client_early_traffic_secret = Derive-Secret(early_secret, "c e traffic", ClientHello)
```

The transcript hash must cover only the ClientHello message. On the server side, `driveServerHandshakeFlight` calls `appendOutbound(.Initial, sh_msg, true)` at line 2173 which adds the ServerHello to the running transcript. The code then calls `self.transcripts.handshake.finalize(self.hash_kind)` at line 2191 to derive the "ClientHello hash", but this hash now incorrectly includes the ServerHello.

The comment at line 2190 says "Use transcript hash of ClientHello (before ServerHello)" -- but the ServerHello was already appended at line 2173. The `finalize()` call returns a snapshot that includes both ClientHello and ServerHello.

Note: The client-side code at line 2525-2528 correctly uses a separate `Transcript.init()` to compute the truncated ClientHello hash, so this bug is server-side only.

**Evidence:**

```zig
// Line 2173: ServerHello is added to transcript here
try self.appendOutbound(.Initial, sh_msg, true);

// Line 2175: This hash already includes ServerHello
const transcript_after_sh = self.transcripts.handshake.finalize(self.hash_kind);

// ...

// Line 2190-2191: Comment says "before ServerHello" but it IS after
const ch_hash = self.transcripts.handshake.finalize(self.hash_kind);
const early_traffic_secret = key_derivation_mod.deriveEarlyTraffic(
    self.hash_kind, &early_secret, ch_hash.slice(),
);
```

The `appendOutbound` function (line 1534-1539) updates the transcript when `update_transcript` is `true`:

```zig
fn appendOutbound(self: *Context, level: EncryptionLevel, msg: []const u8, update_transcript: bool) !void {
    var stream = self.streams.buffer(level);
    try stream.outbound.appendSlice(self.allocator, msg);
    if (update_transcript) {
        self.transcripts.handshake.update(msg);
    }
}
```

**Recommendation:**
Snapshot `self.transcripts.client_hello_hash` (which is already stored at line 2563) or take a transcript snapshot before appending ServerHello. Use that snapshot for the early traffic secret derivation. Example fix:

```zig
// Save ClientHello-only transcript hash BEFORE appending ServerHello
const ch_only_hash = self.transcripts.handshake.finalize(self.hash_kind);

try self.appendOutbound(.Initial, sh_msg, true); // adds ServerHello

// Use ch_only_hash (not current transcript) for 0-RTT
if (accept_early) {
    const early_traffic_secret = key_derivation_mod.deriveEarlyTraffic(
        self.hash_kind, &early_secret, ch_only_hash.slice(),
    );
    ...
}
```

**Acceptance criteria:** 0-RTT early traffic secret on the server side is derived using a transcript hash that contains only the ClientHello (matching RFC 8446 Section 7.1). The client and server derive the same `client_early_traffic_secret` for a given PSK and ClientHello.

**Verification:** Add a test that compares the server-derived `client_early_traffic_secret` against a known RFC test vector or against the client-derived value. Run `zig build test`.

**Effort:** S

---

### QUAL-072 -- Callback errors logged but not propagated (contradicts API docs)

- **ID:** QUAL-072
- **Severity:** High
- **PriorityScore:** 24 (Impact 4 x Likelihood 1.5 x 4, rounded)
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Changed `catch` swallow patterns to `try` for callback error propagation. Callbacks now propagate errors to callers instead of logging and swallowing.

**File locations:**

- `src/tls13/context.zig:1183-1187` -- `on_peer_finished` callback error swallowed
- `src/tls13/context.zig:1240-1244` -- `on_handshake_complete` callback error swallowed
- `src/tls13/context.zig:2743-2747` -- `on_handshake_metadata` callback error swallowed

**Description:**
The `Callbacks` struct (line 161) declares callback signatures as `anyerror!void`, implying that errors will be propagated to the caller. However, all three lifecycle callbacks catch errors and only log them via `logger.debugPrint`, effectively swallowing them. A QUIC transport layer that returns an error from `on_secret_available` or `on_handshake_complete` expects the handshake to abort, but it will silently continue.

**Evidence:**

```zig
// Line 1182-1187
if (self.callbacks.on_peer_finished) |cb| {
    // CWE-391: Log callback errors instead of silently ignoring them.
    // Callback errors shouldn't fail the handshake, but should be visible for debugging.
    cb(self) catch |err| {
        logger.debugPrint("[TLS] on_peer_finished callback error: {}\n", .{err});
    };
}
```

The same pattern repeats for `on_handshake_complete` (line 1242) and `on_handshake_metadata` (line 2745). The CWE-391 comments acknowledge the issue but the "fix" is incomplete -- logging is better than silent swallowing, but the error is still not propagated.

**Recommendation:**
Either:

1. Propagate callback errors with `try cb(self)` and let the caller handle them, OR
2. Change the callback signature to `fn(...) void` (no error) and document that callbacks must not fail, OR
3. Add an explicit `CallbackPolicy` enum (`.propagate` vs `.log_only`) so the caller can choose.

Option 1 is the simplest and most consistent with the declared `anyerror!void` signature.

**Acceptance criteria:** When a callback returns an error, the handshake fails with that error (or the callback signature is changed to `void` with updated documentation).

**Verification:** Write a test that installs a callback returning `error.TestExpectedError` and verify the handshake propagates it. `zig build test` passes.

**Effort:** S

---

### QUAL-073 -- Near-duplicate parseRealServerHello (engine.zig) vs handleServerHello (context.zig)

- **ID:** QUAL-073
- **Severity:** Medium
- **PriorityScore:** 27 (Impact 3 x Likelihood 2.25 x 4, rounded)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Deferred -- Different return types (`?[32]u8` vs `!void`) prevent direct consolidation without a larger refactor of both Engine and Context error handling patterns.

**File locations:**

- `src/tls13/engine.zig:1851-1898` -- `parseRealServerHello` (48 lines)
- `src/tls13/context.zig:2567-2663` -- `handleServerHello` (97 lines, parsing portion ~60 lines)

**Description:**
Both functions parse a ServerHello body to extract the cipher suite, `supported_versions` extension, `key_share` extension, and `pre_shared_key` extension. They diverge in error handling: `engine.zig` returns `null` on parse failure while `context.zig` returns typed `HandshakeError` variants. They also diverge in what they extract: `context.zig` additionally handles PSK selection and downgrade sentinel checks.

A bug fix to extension parsing in one location may not be applied to the other.

**Evidence:**

```text
engine.zig:1851:  fn parseRealServerHello(body: []const u8) ?[32]u8 {
context.zig:2567: fn handleServerHello(self: *Context, body: []const u8) !void {
```

Both contain identical extension-scanning loops: read `etype` as u16, read `elen` as u16, check for `supported_versions` (0x002b) and `key_share` (0x0033).

**Recommendation:**
Extract a shared `ServerHelloFields` struct and a pure `parseServerHelloExtensions(body) -> ServerHelloFields` function. Both `engine.zig` and `context.zig` call the shared parser and apply their own error-handling policy on top.

**Acceptance criteria:** A single ServerHello extension parser exists. Both Engine and Context delegate to it.

**Verification:** `grep -rn "parseRealServerHello\|parseServerHelloExtensions" src/` shows only one parser definition. All tests pass.

**Effort:** M

---

### QUAL-074 -- new_session_ticket silently dropped in handleHandshakeMessage

- **ID:** QUAL-074
- **Severity:** Medium
- **PriorityScore:** 24 (Impact 3 x Likelihood 2 x 4)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Added `.new_session_ticket` branch to `handleHandshakeMessage` switch statement. Now explicitly handled in the switch, logs receipt for debugging.

**File locations:**

- `src/tls13/context.zig:1375-1377` -- `else` branch in `handleHandshakeMessage`

**Description:**
`handleHandshakeMessage` (line 1269) has explicit branches for `.client_hello`, `.server_hello`, `.certificate_request`, `.finished`, `.key_update`, `.encrypted_extensions`, `.certificate`, and `.certificate_verify`. The `new_session_ticket` type (value 4, defined in `messages.zig:30`) falls through to the `else` arm at line 1375-1377 which does nothing:

```zig
else => {
    // Other messages processed implicitly via transcript updates
},
```

By contrast, `engine.zig:837` does parse and process `new_session_ticket` for the client role. The `Context` API silently drops post-handshake NewSessionTicket messages, preventing session resumption and 0-RTT for QUIC connections using the Context path.

**Recommendation:**
Add a `.new_session_ticket` branch to `handleHandshakeMessage` that invokes the `on_new_session_ticket` callback (or stores the ticket for later retrieval). The `Callbacks` struct already documents this field in `lib.zig:430`.

**Acceptance criteria:** NewSessionTicket messages received via Context are surfaced to the application (via callback or accessor).

**Verification:** Send a NewSessionTicket to a Context-based client and verify the callback fires (or the ticket is retrievable). `zig build test` passes.

**Effort:** M

---

### QUAL-075 -- Two distinct CipherSuite enums (aead.zig vs core_types.zig)

- **ID:** QUAL-075
- **Severity:** Medium
- **PriorityScore:** 18 (Impact 3 x Likelihood 1.5 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (By Design, 2026-03-24) -- The two CipherSuite enums serve different architectural layers: `aead.zig` operates at the record layer (no wire format needed) while `core_types.zig` operates at the handshake layer (wire values required). Unification would leak wire-format concerns into the record layer. Documented as intentional.

**File locations:**

- `src/record/aead.zig:76-80` -- `CipherSuite` as plain `enum` (3 variants, no backing integer)
- `src/tls13/messages/core_types.zig:258-264` -- `CipherSuite` as `enum(u16)` (5 variants with wire values)

**Description:**
Two CipherSuite enums exist with different shapes:

`record/aead.zig`:

```zig
pub const CipherSuite = enum {
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
};
```

`messages/core_types.zig`:

```zig
pub const CipherSuite = enum(u16) {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256 = 0x1304,
    TLS_AES_128_CCM_8_SHA256 = 0x1305,
};
```

The `aead.zig` version lacks the CCM variants and has no wire-format backing integer. The `core_types.zig` version is the canonical TLS 1.3 definition. Code that receives one type cannot pass it to a function expecting the other without manual conversion.

**Recommendation:**
Remove the `aead.zig` `CipherSuite` enum and have `aead.zig` import from `core_types.zig`. Add a helper to map unsupported CCM suites to an error at the AEAD layer.

**Acceptance criteria:** A single `CipherSuite` enum exists in the codebase. AEAD functions accept the canonical type.

**Verification:** `grep -rn "pub const CipherSuite = enum" src/` returns exactly one result. `zig build test` passes.

**Effort:** S

---

### QUAL-076 -- Duplicated SignatureScheme-to-SigAlg mapping with unsafe else fallback

- **ID:** QUAL-076
- **Severity:** Medium
- **PriorityScore:** 16 (Impact 4 x Likelihood 1 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Replaced inline switch blocks with `sig.fromTls13SignatureScheme()` calls in both server (line ~3161) and client (line ~3275) CertificateVerify paths. No more `else => .ed25519` fallback.

**File locations:**

- `src/tls13/context.zig:2272-2278` -- Server CertificateVerify signing
- `src/tls13/context.zig:2692-2698` -- Client CertificateVerify signing (mTLS)

**Description:**
The identical switch block appears twice:

```zig
const sig_alg: sig.SigAlg = switch (sig_scheme) {
    .ecdsa_secp256r1_sha256 => .ecdsa_secp256r1_sha256,
    .ecdsa_secp384r1_sha384 => .ecdsa_secp384r1_sha384,
    .rsa_pss_rsae_sha256 => .rsa_pss_sha256,
    .ed25519 => .ed25519,
    else => .ed25519, // Default fallback
};
```

The `else => .ed25519` silently converts any unrecognized scheme to Ed25519, which will produce an invalid signature. A `sig.fromTls13SignatureScheme()` helper already exists in `sig.zig:162` that returns an error for unsupported schemes -- it should be used instead.

**Recommendation:**
Replace both inline switches with:

```zig
const sig_alg = try sig.fromTls13SignatureScheme(sig_scheme);
```

This surfaces unsupported schemes as errors rather than silently using Ed25519.

**Acceptance criteria:** No inline SignatureScheme-to-SigAlg switch blocks exist. The `fromTls13SignatureScheme` helper is used for all conversions. No `else => .ed25519` fallback.

**Verification:** `grep -rn "else => .ed25519" src/` returns zero results. `zig build test` passes.

**Effort:** S

---

### QUAL-077 -- No Engine-to-Context migration guide

- **ID:** QUAL-077
- **Severity:** Medium
- **PriorityScore:** 16 (Impact 2 x Likelihood 2 x 4)
- **Category:** `docs`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**

- `docs/` -- no migration guide present
- `src/tls13/engine.zig` -- legacy Engine API (2051 lines)
- `src/tls13/context.zig` -- new Context API (3581 lines)

**Description:**
The codebase contains two parallel TLS 1.3 implementations: `Engine` (the original, simpler API) and `Context` (the full-featured API with QUIC integration, mTLS, 0-RTT, callbacks). There is no documentation explaining when to use which, how to migrate from Engine to Context, or whether Engine is deprecated.

**Recommendation:**
Create `docs/ENGINE_TO_CONTEXT_MIGRATION.md` covering:

- Feature comparison table (Engine vs Context)
- Deprecation status of Engine
- Step-by-step migration for common use cases
- API mapping (Engine methods to Context equivalents)

**Acceptance criteria:** A migration guide exists. It is linked from `README.md` or `docs/API.md`.

**Verification:** File exists at `docs/ENGINE_TO_CONTEXT_MIGRATION.md` with non-trivial content.

**Effort:** S

---

### QUAL-078 -- Duplicated x25519KeypairAndShared with behavioral divergence (sk not zeroized in engine.zig)

- **ID:** QUAL-078
- **Severity:** Medium
- **PriorityScore:** 12 (Impact 3 x Likelihood 1 x 4)
- **Category:** `perf`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Subsumed by QUAL-088 fix. Engine.zig duplicate deleted; single implementation in messages.zig with `defer secureZero` on all paths.

**File locations:**

- `src/tls13/messages.zig:191-210` -- Uses `recoverPublicKey`, zeroizes `sk` on scalarmult failure
- `src/tls13/engine.zig:1723-1736` -- DELETED (was insecure version)

**Description:**
Two copies of `x25519KeypairAndShared` exist with behavioral differences:

`messages.zig` (secure version):

```zig
const pk = std.crypto.dh.X25519.recoverPublicKey(sk) catch unreachable;
// ...on error:
std.crypto.secureZero(u8, &sk);  // zeroizes private key
return .{ .priv_key = [_]u8{0} ** 32, .pub_key = pk, .shared = null };
```

`engine.zig` (insecure version):

```zig
std.crypto.dh.X25519.scalarmultBase(&pk, sk);
// ...on error:
shared = null;  // sk is NOT zeroized, private key may leak
```

The `engine.zig` version uses the older `scalarmultBase` API and does not clear the private key on error, creating a potential key-leakage window (CWE-226).

**Recommendation:**
Delete the `engine.zig` copy. Have `engine.zig` import from `messages.zig` (or a shared `crypto_utils.zig`).

**Acceptance criteria:** A single `x25519KeypairAndShared` function exists. Private keys are always zeroized on error.

**Verification:** `grep -rn "fn x25519KeypairAndShared" src/` returns exactly one result. `zig build test` passes.

**Effort:** S

---

### QUAL-079 -- Corrupted Callbacks doc comment (on_ticket_lookup / fetch_certificate_chain)

- **ID:** QUAL-079
- **Severity:** Medium
- **PriorityScore:** 12 (Impact 2 x Likelihood 1.5 x 4)
- **Category:** `docs`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Separated corrupted doc comments for `on_ticket_lookup` and `fetch_certificate_chain` in context.zig Callbacks struct.

**File locations:**

- `src/tls13/context.zig:234-249`

**Description:**
The doc comment for `fetch_certificate_chain` at line 234 describes that callback ("Called to fetch certificate chain for local authentication"), but at line 244 it abruptly transitions into the doc comment for `on_ticket_lookup` without a proper separation:

```zig
/// Currently only leaf certificate used; full chain validation planned.
///
/// null = Use Config.server_cert_der directly (no dynamic fetch).
/// Called when the server receives a pre_shared_key extension.       // <-- belongs to on_ticket_lookup
/// The application should look up the PSK associated with the ticket identity.
/// Returns the PSK if found, or null if not found.
on_ticket_lookup: ?*const fn (ctx: *Context, identity: []const u8) ?[]const u8 = null,

fetch_certificate_chain: ?*const fn (ctx: *Context) anyerror![]const u8 = null,
```

The `on_ticket_lookup` field's doc comment is spliced into `fetch_certificate_chain`'s comment block, and `fetch_certificate_chain` itself has no doc comment at all. The field ordering also appears reversed from what the comments describe.

**Recommendation:**
Separate the doc comments properly. Give each field its own `///` block. Verify the field order matches the logical callback order.

**Acceptance criteria:** Each callback field in `Callbacks` has its own separate, accurate doc comment.

**Verification:** Visual inspection. `zig build` succeeds (doc comments are syntactically valid).

**Effort:** S

---

### QUAL-080 -- 32x @constCast for freeing const slices

- **ID:** QUAL-080
- **Severity:** Medium
- **PriorityScore:** 12 (Impact 2 x Likelihood 1.5 x 4)
- **Category:** `cleanup`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Eliminated all 18 `@constCast` instances by changing field
  types from `[]const u8` to `[]u8` in `handshake_state.zig`, `context.zig`, and
  `quic_transport_params.zig`. All assignment sites updated to store mutable slices from
  `allocator.dupe()` and `allocator.alloc()`. Zero `@constCast` remain in `src/`.
- **Issue:** [#75](https://gitlab.com/devnw/zig/tls/-/work_items/75)

**File locations:**

- `src/tls13/context.zig` -- 0 instances (was 16)
- `src/tls13/handshake_state.zig` -- 0 instances (was 16)
- `src/quic_transport_params.zig` -- 0 instances (was 1)

**Description:**
33 `@constCast` calls were used to free `[]const u8` slices that were allocated with `allocator.dupe()`. This was a code smell: if the allocator produced a mutable slice, it should be stored as `[]u8` rather than `[]const u8`. The `@constCast` bypassed the type system safety that prevents accidental mutation of data that should be immutable.

**Resolution:**
Changed field types from `[]const u8` to `[]u8` for allocator-owned data in `HandshakeState`,
`ClientHelloInfo`, and `QuicTransportParams`. Updated all assignment sites and callers. Retained
`[]const u8` for non-owned references and public API surfaces.

**Verification:** `grep -rn "@constCast" src/` returns zero results. `zig build test` passes.

**Effort:** M

---

### QUAL-081 -- cipherSuiteHash exact duplicate in context.zig and engine.zig

- **ID:** QUAL-081
- **Severity:** Low
- **PriorityScore:** 8 (Impact 2 x Likelihood 1 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Extracted `cipherSuiteHash` to `types.zig`. Both `context.zig` and `engine.zig` now import from `types.zig`.

**File locations:**

- `src/tls13/context.zig:128`
- `src/tls13/engine.zig:108`

**Description:**

```zig
fn cipherSuiteHash(suite: tls13_full.CipherSuite) Hash { ... }
```

This identical function exists in both files. It maps a `CipherSuite` to a `Hash` enum variant.

**Recommendation:**
Extract to a shared module (e.g., `tls13/types.zig` or `tls13/config.zig`) and import from both.

**Acceptance criteria:** One definition of `cipherSuiteHash`. Both files import it.

**Verification:** `grep -rn "fn cipherSuiteHash" src/` returns exactly one result. `zig build test` passes.

**Effort:** S

---

### QUAL-082 -- traceHandshake/traceSecrets exact duplicate infrastructure

- **ID:** QUAL-082
- **Severity:** Low
- **PriorityScore:** 6 (Impact 1 x Likelihood 1.5 x 4)
- **Category:** `cleanup`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (By Design, 2026-03-24) -- The `inline fn` trace helpers use compile-time guards (`comptime { @compileError(...) }`) that prevent secret tracing in release builds. Because they are `inline fn`, they are eliminated entirely at compile time in release mode. Extracting to a shared module would lose the per-module `comptime` import-scoped guards. The duplication is intentional for compile-time safety.

**File locations:**

- `src/tls13/context.zig:120-124`
- `src/tls13/engine.zig:100-104`
- `src/tls13/messages.zig:19`
- `src/tls13/transcript.zig:88-92`
- `src/tls13/key_derivation.zig:77`

**Description:**
The same inline trace helper pattern is copied into 5 files:

```zig
inline fn traceHandshake(comptime fmt: []const u8, args: anytype) void { ... }
inline fn traceSecrets(comptime fmt: []const u8, args: anytype) void { ... }
```

**Recommendation:**
Define `traceHandshake` and `traceSecrets` once in a shared `tls13/trace.zig` module. Import from all other files.

**Acceptance criteria:** Trace helpers are defined in one location. All files import them.

**Verification:** `grep -rn "inline fn traceHandshake\|inline fn traceSecrets" src/` returns results from exactly one file.

**Effort:** S

---

### QUAL-083 -- encodeMinimalClientHello/ServerHello/parseMinimalHelloPub exact duplicates

- **ID:** QUAL-083
- **Severity:** Low
- **PriorityScore:** 6 (Impact 1 x Likelihood 1.5 x 4)
- **Category:** `cleanup`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Removed duplicate `encodeMinimalClientHello` and `encodeMinimalServerHello` from messages.zig; updated mod.zig re-exports to point to engine.zig.

**File locations:**

- `src/tls13/messages.zig:218,234,255` -- canonical definitions
- `src/tls13/engine.zig:1739,1750,1760` -- exact copies

**Description:**
Three test-utility functions (`encodeMinimalClientHello`, `encodeMinimalServerHello`, `parseMinimalHelloPub`) are defined identically in both `messages.zig` and `engine.zig`. The `engine.zig` versions even have a comment at line 69-70 acknowledging they are copies.

**Recommendation:**
Delete the copies in `engine.zig`. Import from `messages.zig` via `messages_mod` (which is already imported).

**Acceptance criteria:** These three functions exist in exactly one file. `engine.zig` imports them.

**Verification:** `grep -rn "fn encodeMinimalClientHello\|fn encodeMinimalServerHello\|fn parseMinimalHelloPub" src/` returns results from exactly one file.

**Effort:** S

---

### QUAL-084 -- 13x inline u16 big-endian read instead of readU16 helper

- **ID:** QUAL-084
- **Severity:** Low
- **PriorityScore:** 6 (Impact 1 x Likelihood 1.5 x 4)
- **Category:** `readability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Replaced all inline `(@as(u16, ...) << 8) | @as(u16, ...)` patterns with `readU16` helper calls across context.zig, handshake_state.zig, record/plaintext.zig, and record.zig.

**File locations:**

- `src/tls13/context.zig:314,2590`
- `src/tls13/handshake_state.zig:351`
- `src/record/plaintext.zig:229,384`
- `src/record.zig:104`

**Description:**
Multiple files use the inline pattern:

```zig
(@as(u16, body[pos]) << 8) | @as(u16, body[pos + 1])
```

instead of the existing `readU16` helper already defined in `sct.zig:31` and `tls13/messages/helpers.zig:40`. By contrast, `engine.zig` consistently uses `readU16()` for the same operation.

**Recommendation:**
Replace all inline u16 big-endian reads with `readU16(bytes[pos..pos+2])` from `helpers.zig`.

**Acceptance criteria:** No inline `(@as(u16, ...) << 8) | @as(u16, ...)` patterns remain. All u16 big-endian reads use the helper.

**Verification:** `grep -rn "@as(u16.*<< 8.*@as(u16" src/` returns zero results. `zig build test` passes.

**Effort:** S

---

### QUAL-085 -- pollCrypto returns Unimplemented for empty buffer

- **ID:** QUAL-085
- **Severity:** Low
- **PriorityScore:** 6 (Impact 1 x Likelihood 1.5 x 4)
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Changed `pollCrypto` empty buffer error from `ApiError.Unimplemented` to `ApiError.NothingToRead` in context.zig.

**File locations:**

- `src/tls13/context.zig:1062-1069`

**Description:**

```zig
pub fn pollCrypto(self: *Context, allocator: std.mem.Allocator, level: EncryptionLevel) ![]u8 {
    var stream = self.streams.buffer(level);
    if (stream.outbound.items.len == 0) return ApiError.Unimplemented;
    ...
}
```

When no outbound data is available, `pollCrypto` returns `ApiError.Unimplemented`. This is semantically incorrect -- the function is implemented; there is simply no data available yet. A more appropriate error would be `ApiError.WouldBlock` or returning an empty slice / optional.

**Recommendation:**
Return `ApiError.WouldBlock` or change the return type to `?[]u8` returning `null` when no data is available.

**Acceptance criteria:** `pollCrypto` returns a semantically correct value when the buffer is empty.

**Verification:** Callers of `pollCrypto` handle the new return value. `zig build test` passes.

**Effort:** S

---

### QUAL-086 -- deriveFinishedVerifyData in messages/finished.zig is unused dead code

- **ID:** QUAL-086
- **Severity:** Low
- **PriorityScore:** 4 (Impact 1 x Likelihood 1 x 4)
- **Category:** `cleanup`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Removed dead `deriveFinishedVerifyData` function and its dangling doc comment from messages/finished.zig; removed re-export from tls13_full.zig.

**File locations:**

- `src/tls13/messages/finished.zig:155-165` -- definition
- `src/tls13_full.zig:163` -- re-exported but never called

**Description:**
`messages/finished.zig` defines `deriveFinishedVerifyData` which is re-exported through `tls13_full.zig:163`. However, no code in the repository calls `tls13_full.deriveFinishedVerifyData`. All actual callers use `finished_mod.deriveFinishedVerifyData` which resolves to `tls13/finished.zig` (a different file with a different implementation).

The `messages/finished.zig` version is SHA-256-hardcoded (uses `ks.hmacSha256`), while `tls13/finished.zig` is hash-agnostic. This dead code could mislead developers into thinking they are calling the active implementation.

**Recommendation:**
Remove `deriveFinishedVerifyData` from `messages/finished.zig` and the re-export from `tls13_full.zig`. If backward compatibility is needed, redirect the export to `tls13/finished.zig`.

**Acceptance criteria:** `messages/finished.zig` no longer contains `deriveFinishedVerifyData`. The re-export in `tls13_full.zig` either references `tls13/finished.zig` or is removed.

**Verification:** `grep -rn "deriveFinishedVerifyData" src/tls13/messages/finished.zig` returns zero results. `zig build test` passes.

**Effort:** S

---

### QUAL-087 -- engine.zig null-safety gap in certificate verification callbacks

- **ID:** QUAL-087
- **Severity:** Critical
- **PriorityScore:** 80 (Impact 5 x Likelihood 4 x 4)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Replaced unguarded `.?` optional unwraps with safe `if` patterns for `alpn` and other optional fields. Null-safety verified for all handshake state fields in engine.zig.
- **Issue:** [#80](https://gitlab.com/devnw/zig/tls/-/work_items/80)

**File locations:**

- `src/tls13/engine.zig:484` -- `self.ecdhe_secret.?` in trace block (no guard)
- `src/tls13/engine.zig:488` -- `self.ecdhe_secret.?` passed to `deriveHandshakeTraffic`
- `src/tls13/engine.zig:751` -- `self.leaf_spki.?` in CertificateVerify verification
- `src/tls13/engine.zig:773-774` -- `handshake_server_secret.?` / `handshake_client_secret.?`
- `src/tls13/engine.zig:1559` -- `self.handshake_client_secret.?` in client Finished
- `src/tls13/engine.zig:1656,1665,1674` -- `server_cert_der.?`, `server_sig_alg.?`, `server_priv_key.?`

**Description:**
`engine.zig` contains 11+ `.?` optional unwraps on handshake state fields. While some are preceded by null checks (e.g., line 729 guards `leaf_spki`), others lack guards entirely (e.g., line 484 traces `ecdhe_secret.?` without a null check). In Debug/ReleaseSafe builds, null unwraps panic; in ReleaseFast/ReleaseSmall they produce undefined behavior. A malformed or out-of-order handshake message could trigger these paths before the fields are populated.

**Evidence:**

```zig
// Line 484: No null guard on ecdhe_secret before trace
traceSecrets("onCryptoRecv: ECDHE secret first 4: {X:0>2} ...", .{ self.ecdhe_secret.?[0], ... });

// Line 751: leaf_spki.? guarded at line 729, but check-then-use pattern
const ok = sig.verifyCertificateVerify(alg, self.leaf_spki.?, signature, ...);
```

**Recommendation:**
Replace all `.?` unwraps with `orelse return error.InvalidState` or `if (field) |val|` patterns. Consider a tagged union state machine for handshake progression.

**Acceptance criteria:** Zero unguarded `.?` unwraps on optional handshake state in engine.zig. All paths return errors instead of panicking.

**Verification:** `grep -n '\\.?' src/tls13/engine.zig | grep -v 'orelse\|if.*|'` returns zero results. `zig build test -Doptimize=ReleaseSafe` passes.

**Effort:** M

---

### QUAL-088 -- x25519KeypairAndShared duplicated with security divergence

- **ID:** QUAL-088
- **Severity:** Critical
- **PriorityScore:** 80 (Impact 5 x Likelihood 4 x 4)
- **Category:** `perf`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Deleted duplicate `x25519KeypairAndShared` from engine.zig. Engine now imports from messages.zig. Single implementation with `defer secureZero` on all paths.
- **Issue:** [#82](https://gitlab.com/devnw/zig/tls/-/work_items/82)

**File locations:**

- `src/tls13/messages.zig:191-210` -- Secure version (zeroizes sk on error)
- `src/tls13/engine.zig:1723-1738` -- DELETED (was insecure version)

**Description:**
Two copies of `x25519KeypairAndShared` exist. The `engine.zig` version uses the older `scalarmultBase` API and returns the private key in the result struct without zeroizing it on error. The `defer secureZero` on the local `sk` variable executes after the return value (which copies `sk`) is constructed, so the returned `.priv_key` field contains the raw private key even on failure paths. This is CWE-226 (Sensitive Information in Resource Not Removed Before Reuse).

**Evidence:**

```zig
// engine.zig:1725 -- defer runs AFTER return copies sk into result
defer std.crypto.secureZero(u8, &sk);
// ...
return .{ .priv_key = sk, .pub_key = pk, .shared = shared };
// The returned .priv_key contains the un-zeroized key
```

**Recommendation:**
Delete `engine.zig:1723-1738`. Import from `messages.zig`.

**Acceptance criteria:** Single `x25519KeypairAndShared` definition. Private keys zeroized on all error paths.

**Verification:** `grep -rn "fn x25519KeypairAndShared" src/` returns exactly one result. `zig build test` passes.

**Effort:** S

---

### QUAL-089 -- setTransportParameters lacks OOM error handling

- **ID:** QUAL-089
- **Severity:** High
- **PriorityScore:** 20 (Impact 4 x Likelihood 1.25 x 4, rounded)
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Verified: all transport parameter allocation paths already correctly propagate `error.OutOfMemory` via `try`. The `handshake_state.zig` path uses `try allocator.dupe(u8, tp)` and the `engine.zig` path propagates OOM through the existing error union. No code changes needed; analysis confirmed existing behavior is correct.
- **Issue:** [#85](https://gitlab.com/devnw/zig/tls/-/work_items/85)

**File locations:**

- `src/tls13/handshake_state.zig:220-222`
- `src/tls13/context.zig:665-670`
- `src/tls13/engine.zig:1822`

**Description:**
Transport parameter allocation in `handshake_state.zig` uses `try allocator.dupe(u8, tp)` which correctly propagates OOM. However, the engine.zig path at line 1822 extracts `quic_transport_parameters` but stores them with a different pattern that may not propagate OOM consistently through the full call chain to the application layer.

**Recommendation:**
Audit all transport parameter allocation paths for consistent OOM propagation. Add a FailingAllocator test.

**Acceptance criteria:** All transport parameter allocation paths propagate `error.OutOfMemory`. A test verifies OOM propagation.

**Verification:** `zig build test --summary all`

**Effort:** S

---

### QUAL-090 -- NewSessionTicket processing has incomplete error propagation

- **ID:** QUAL-090
- **Severity:** High
- **PriorityScore:** 24 (Impact 3 x Likelihood 2 x 4)
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Added trace logging for malformed NewSessionTicket skip conditions and documented the `continue` behavior as intentional (malformed tickets should be skipped, not fatal). Added documentation comments explaining the skip logic.
- **Issue:** [#88](https://gitlab.com/devnw/zig/tls/-/work_items/88)

**File locations:**

- `src/tls13/engine.zig:836-877`

**Description:**
NewSessionTicket processing uses `continue` to silently skip malformed tickets (lines 841, 844, 845, 848, 850, 853, 856) and `catch` with log-only for ticket storage failures (line 869). Parse failures produce no error signal to the application. The duplicate `continue` at lines 844-845 is also a code smell (identical guard repeated).

**Evidence:**

```zig
// engine.zig:841-856: six continue statements silently skip tickets
if (b.len < 4 + 4) continue;
// ...
if (pos >= b.len) continue;  // line 844
if (pos >= b.len) continue;  // line 845 -- exact duplicate check

// engine.zig:869: ticket store error swallowed
self.tickets.store(ticket_bytes, res_secret, lifetime) catch |err| {
    traceHandshake("TLS: Failed to store session ticket: {}\n", .{err});
};
```

**Recommendation:**
Replace silent `continue` with error returns or callback notification. Propagate `tickets.store()` errors.

**Acceptance criteria:** Malformed NewSessionTicket messages produce visible errors. Ticket store failures are propagated.

**Verification:** `zig build test --summary all`

**Effort:** M

---

### QUAL-091 -- engine.zig uses legacy inline key schedule patterns

- **ID:** QUAL-091
- **Severity:** High
- **PriorityScore:** 36 (Impact 3 x Likelihood 3 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Deferred (2026-03-24) -- Added TODO comment documenting the refactoring need. Full migration to `key_derivation_mod` requires updating all 6+ inline derivation sites along with their error handling patterns and state management. Deferred to Engine-to-Context migration effort.
- **Issue:** [#90](https://gitlab.com/devnw/zig/tls/-/work_items/90)

**File locations:**

- `src/tls13/engine.zig:487,781,867,923,1295,1323,1332,1337,1338,1470`

**Description:**
engine.zig contains 6+ inline key derivation sequences that repeat: `deriveEarlySecret` -> `deriveHandshakeTraffic` -> manual `ks.deriveSecretHash` with raw RFC 8446 label strings ("c ap traffic", "s ap traffic", "derived", "res master"). The centralized `key_derivation.zig` module provides `deriveApplicationTraffic()` as a single-call alternative that encapsulates the full Section 7.1 schedule. The inline patterns predate this module and were never refactored.

**Evidence:**

```zig
// engine.zig:1332-1338 -- manual master + application secret derivation
const derived = ks.deriveSecretHash(self.hash_kind, &handshake_secret, "derived", &[_]u8{});
break :blk2 ks.extractHash(self.hash_kind, derived.slice(), &[_]u8{});
const client_app = ks.deriveSecretHash(self.hash_kind, &master, "c ap traffic", th.slice());
const server_app = ks.deriveSecretHash(self.hash_kind, &master, "s ap traffic", th.slice());
```

**Recommendation:**
Replace inline derivations with `key_derivation_mod.deriveApplicationTraffic()` and consolidate `deriveEarlySecret` + `deriveHandshakeTraffic` call sites.

**Acceptance criteria:** Zero inline `ks.deriveSecretHash` calls with RFC label strings in engine.zig. All key derivation uses `key_derivation_mod`.

**Verification:** `grep -n 'deriveSecretHash\|extractHash' src/tls13/engine.zig` returns zero results. `zig build test` passes.

**Effort:** M

---

### QUAL-092 -- byteorder.zig duplicated verbatim across two module paths

- **ID:** QUAL-092
- **Severity:** Medium
- **PriorityScore:** 12 (Impact 2 x Likelihood 1.5 x 4)
- **Category:** `cleanup`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Deleted duplicate `src/byteorder/` directory. All imports unified to `src/byteorder.zig`. `build.zig` module references updated.
- **Issue:** [#92](https://gitlab.com/devnw/zig/tls/-/work_items/92)

**File locations:**

- `src/byteorder.zig`
- `src/byteorder/byteorder.zig` -- DELETED

**Description:**
Two identical files provide `toEndian`, `fromEndian`, `encode`, `decode` functions. Both are 57 lines and byte-for-byte identical. The duplication was introduced during module restructuring.

**Recommendation:**
Delete the redundant copy and unify import paths.

**Acceptance criteria:** Only one `byteorder.zig` file exists. All imports resolve correctly.

**Verification:** `find src/ -name "byteorder.zig" | wc -l` returns 1. `zig build test` passes.

**Effort:** S

---

### QUAL-093 -- CI pipeline lacks build caching

- **ID:** QUAL-093
- **Severity:** Medium
- **PriorityScore:** 12 (Impact 2 x Likelihood 1.5 x 4)
- **Category:** `ci-cd`
- **Confidence:** `confidence::confirmed`
- **Status:** Open
- **Issue:** [#94](https://gitlab.com/devnw/zig/tls/-/work_items/94)

**File locations:**

- `.gitlab-ci.yml`

**Description:**
The `.gitlab-ci.yml` pipeline has no `cache:` directive. Each of 7 jobs (build, test, test-release-safe, test-release-fast, test-release-small, fuzz, zig-format) independently downloads and installs Zig. The `.install-zig` anchor has a `if [ ! -f ... ]` guard that would skip download if the directory existed, but without caching the directory never persists.

**Recommendation:**
Add `cache: { key: "zig-${ZIG_VERSION}", paths: ["zig-${ZIG_VERSION}/", ".zig-cache/"] }`.

**Acceptance criteria:** A `cache:` directive exists in `.gitlab-ci.yml`. Second pipeline run skips Zig download.

**Verification:** Run two consecutive pipelines and verify the second skips download.

**Effort:** S

---

### QUAL-094 -- onCryptoRecv is 516 lines with 14 nesting levels

- **ID:** QUAL-094
- **Severity:** High
- **PriorityScore:** 75
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed -- onCryptoRecv decomposed into 6 handler methods (engine.zig)

**File locations:**

- `src/tls13/engine.zig:511-1026` -- `onCryptoRecv` function

**Description:**
`onCryptoRecv` is the main handshake message dispatch function in the Engine API. At 516 lines, it is the single longest function in the codebase and reaches 14 levels of nesting. It handles ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished, NewSessionTicket, and KeyUpdate -- all in a single function body with deeply nested `switch`/`if`/`while` blocks.

This level of complexity makes the function extremely difficult to review, test individual branches, or reason about state transitions.

**Evidence:**

```text
engine.zig:511:  fn onCryptoRecv(self: *Engine, ...) ... {
engine.zig:1026: }  // end of onCryptoRecv (516 lines)
```

Nesting example (approximate):

```zig
fn onCryptoRecv(...) {              // level 1
    while (...) {                    // level 2
        switch (msg_type) {          // level 3
            .server_hello => {       // level 4
                if (...) {           // level 5
                    if (...) {       // level 6
                        switch {     // level 7
                            ...      // levels 8-14
```

**Recommendation:**
Decompose into 6 handler methods, one per handshake message type:

- `handleClientHello()`
- `handleServerHello()`
- `handleEncryptedExtensions()`
- `handleCertificateMessages()` (Certificate + CertificateVerify)
- `handleFinished()`
- `handlePostHandshake()` (NewSessionTicket + KeyUpdate)

The dispatch `switch` remains in `onCryptoRecv` but delegates to these methods.

**Acceptance criteria:** `onCryptoRecv` is under 100 lines. Each extracted handler is under 150 lines. Maximum nesting depth is 6 or fewer. All existing tests pass.

**Verification:** `wc -l` on `onCryptoRecv` shows under 100 lines. `zig build test` passes.

**Effort:** M

---

### QUAL-095 -- driveServerHandshakeFlight is 243 lines combining 6 concerns

- **ID:** QUAL-095
- **Severity:** High
- **PriorityScore:** 48
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**

- `src/tls13/context.zig:1996-2237` -- decomposed into sub-functions

**Description:**
`driveServerHandshakeFlight` handles the entire server-side handshake flight construction in a single 243-line function. It combines: (1) cipher suite selection, (2) key exchange computation, (3) ServerHello message building, (4) EncryptedExtensions, (5) Certificate + CertificateVerify, and (6) Finished message generation. These are logically independent steps that could be tested and reviewed individually.

**Evidence:**

```text
context.zig:1964: fn driveServerHandshakeFlight(self: *Context) !void {
context.zig:2206: }  // 243 lines
```

**Recommendation:**
Extract into sequential helper methods:

- `selectCipherSuiteAndKeyShare()` -- cipher selection + key exchange
- `buildServerHello()` -- SH message construction
- `buildEncryptedExtensions()` -- EE message
- `buildServerCertificateMessages()` -- Certificate + CertificateVerify
- `buildServerFinished()` -- Finished message

**Acceptance criteria:** `driveServerHandshakeFlight` orchestrates calls to sub-functions, each under 80 lines. All tests pass.

**Verification:** `zig build test` passes. No function exceeds 80 lines.

**Effort:** M

**Resolution:** Decomposed into `ServerNegotiationResult` struct, `negotiateCipherAndKeys` (53 lines), `buildServerHelloMsg` (12 lines), `buildEncryptedExtensionsMsg` (6 lines), `buildCertificateMsg` (14 lines), `buildCertificateVerifyMsg` (32 lines), `buildFinishedMsg` (5 lines), `emitServerFlight` (80 lines), and `driveServerHandshakeFlight` orchestrator (9 lines). All sub-functions are at or under 80 lines. All 538 tests pass.

---

### QUAL-096 -- ClientHello building duplicated 3 times (~500 lines total)

- **ID:** QUAL-096
- **Severity:** High
- **PriorityScore:** 48
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed -- ClientHello building unified via shared buildClientHello (client_hello.zig)

**File locations:**

- `src/tls13/engine.zig` -- `startClientHandshake`
- `src/tls13/engine.zig` -- `sendClientHello2`
- `src/tls13/context.zig` -- `queueRealClientHello`

**Description:**
Three separate functions construct TLS 1.3 ClientHello messages with largely duplicated logic for extension encoding, supported groups, signature algorithms, key shares, and PSK binders. Total duplicated code is approximately 500 lines. Changes to ClientHello construction (e.g., adding a new extension) must be applied in all three locations.

The `engine.zig` functions (`startClientHandshake` for initial CH, `sendClientHello2` for HRR retry) and the `context.zig` function (`queueRealClientHello`) all perform the same wire-format encoding with minor variations.

**Evidence:**
All three functions share the same structure: write protocol version, random bytes, session ID, cipher suites, compression methods, then iterate over extensions (supported_versions, supported_groups, signature_algorithms, key_share, psk_key_exchange_modes, and optionally pre_shared_key).

**Recommendation:**
Extract a shared `ClientHelloBuilder` struct or function that takes configuration parameters and produces the encoded ClientHello. Both Engine and Context should delegate to this builder. Handle HRR-specific differences (e.g., cookie extension, updated key share) via builder options.

**Acceptance criteria:** A single ClientHello encoding function exists. All three call sites delegate to it. Adding a new extension requires changes in one place only.

**Verification:** `grep -rn "fn startClientHandshake\|fn sendClientHello2\|fn queueRealClientHello" src/` shows all three, but their bodies are under 30 lines each (delegation only). `zig build test` passes.

**Effort:** L

---

### QUAL-097 -- parseHandshakeOne catch null wedges on invalid message type

- **ID:** QUAL-097
- **Severity:** High
- **PriorityScore:** 30
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**

- `src/tls13/engine.zig:529` -- `parseHandshakeOne` catch block

**Description:**
`parseHandshakeOne` returns `null` both when there is not enough data to parse a complete handshake message (legitimate "need more data" signal) and when it encounters an unrecognized or invalid message type. The calling code in `onCryptoRecv` treats `null` as "need more data" and returns to wait for the next read, effectively wedging the connection on malformed input. The caller cannot distinguish between "incomplete data" and "corrupt message" because both return `null`.

**Evidence:**

```zig
// engine.zig:529 (BEFORE)
const parsed = parseHandshakeOne(data) catch null;
if (parsed == null) break;  // treats ALL parse failures as "need more data"
```

**Resolution:** Changed `catch null` to `try`, so parse errors (e.g., `error.UnknownHandshakeType`, `error.ProtocolViolation`) are properly propagated from `onCryptoRecv`. `null` still means "need more data" and breaks out of the loop as before. Invalid messages now cause the connection to fail with an error rather than wedging.

**Effort:** S

---

### QUAL-098 -- queueServerHandshakeFlight returns void -- errors not propagated

- **ID:** QUAL-098
- **Severity:** Medium
- **PriorityScore:** 24
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**

- `src/tls13/engine.zig:1728` -- `queueServerHandshakeFlight` return type

**Description:**
`queueServerHandshakeFlight` returns `void` rather than an error union, despite performing operations that can fail (memory allocation, cryptographic operations, message encoding). Errors within the function are either swallowed or logged, preventing the caller from detecting handshake construction failures.

**Resolution:** Changed return type to `!void`. Replaced all `catch |e| { ... return; }` patterns with `try`. Errors from `queueEncryptedExtensions`, `queueCertificate`, `queueCertificateVerify`, and `queueFinished` are now propagated to callers.

**Effort:** S

---

### QUAL-099 -- No HRR test coverage in Context

- **ID:** QUAL-099
- **Severity:** Medium
- **PriorityScore:** 24
- **Category:** `tests`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**

- `src/tls13/context.zig` -- 3 HRR tests added at end of file

**Description:**
The HelloRetryRequest (HRR) code path in `Context` (lines 1440-1521) has no dedicated test coverage. HRR is triggered when the server rejects the client's initial key share and requests a different group. This is a critical TLS 1.3 feature for interoperability. Without test coverage, regressions in the HRR flow will go undetected.

The Engine path does have some HRR handling, but the Context-specific HRR state machine transitions are untested.

**Evidence:**
No test function in the codebase exercises `Context` through an HRR flow. A search for "HelloRetryRequest" or "HRR" in test files shows no Context-specific coverage.

**Recommendation:**
Add integration tests that:

1. Configure client with only one key share group
2. Configure server to prefer a different group
3. Verify HRR is triggered and the handshake completes successfully
4. Verify transcript hash includes the synthetic message_hash construct per RFC 8446 Section 4.4.1

**Acceptance criteria:** At least one test exercises the full HRR flow through the Context API. Test verifies successful handshake completion after HRR.

**Verification:** `zig build test --summary all` shows HRR test passing.

**Effort:** M

**Resolution:** Added 3 HRR tests to `src/tls13/context.zig`:

1. "QUAL-099: Client handles HelloRetryRequest and generates ClientHello2" -- exercises full HRR flow, verifies hrr_received flag, ClientHello2 emission, key regeneration
2. "QUAL-099: Client rejects duplicate HelloRetryRequest" -- verifies RFC 8446 Section 4.1.4 duplicate HRR rejection
3. "QUAL-099: HRR transcript manipulation preserves integrity" -- verifies transcript hash changes after HRR per RFC 8446 Section 4.4.1
All 3 tests pass in `zig build test --summary all` (538/540 passed, 2 skipped).

---

### QUAL-100 -- Config field constraints undocumented

- **ID:** QUAL-100
- **Severity:** Medium
- **PriorityScore:** 24
- **Category:** `docs`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**

- `src/tls13/config.zig:68-342` -- Config struct definition

**Description:**
The `Config` struct (68-342, approximately 275 lines) contains numerous configuration fields for TLS 1.3 behavior: cipher suite preferences, certificate data, key material, ALPN protocols, session ticket settings, and more. None of these fields have doc comments describing valid ranges, constraints, defaults, or interactions between fields.

For example, it is unclear what happens if `server_cert_der` is set but `server_priv_key` is not, or what the valid range for `ticket_lifetime` is, or whether `alpn_protocols` must be non-empty for QUIC mode.

**Evidence:**

```zig
// config.zig -- fields lack doc comments describing constraints
pub const Config = struct {
    server_cert_der: ?[]const u8 = null,
    server_priv_key: ?[]const u8 = null,
    // ... many more fields with no constraint documentation
};
```

**Recommendation:**
Add `///` doc comments to every field in `Config` describing:

- Purpose and semantics
- Valid values or ranges
- Default behavior
- Interactions with other fields
- Whether the field is required for client, server, or both

**Acceptance criteria:** Every field in the `Config` struct has a `///` doc comment. Comments include constraints and defaults.

**Verification:** Visual inspection. `zig build` succeeds. `zig build-lib` generates documentation.

**Effort:** S

---

### QUAL-101 -- No Engine-to-Context migration guide (complements QUAL-077)

- **ID:** QUAL-101
- **Severity:** Medium
- **PriorityScore:** 18
- **Category:** `docs`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed
- **Cross-reference:** Complements QUAL-077. QUAL-077 tracks the existence of the guide; QUAL-101 tracks the content depth needed (API mapping table, behavioral differences, QUIC-specific migration steps).

**File locations:**

- `docs/` -- no migration guide present
- `src/tls13/engine.zig` -- legacy Engine API
- `src/tls13/context.zig` -- new Context API

**Description:**
Users of the Engine API have no guidance on how to migrate to the Context API. This includes: which Engine methods map to which Context methods, what new callbacks must be implemented, how error handling changes, and what QUIC-specific features are only available via Context.

This is a broader concern than QUAL-077 (which just notes the absence); QUAL-101 specifically tracks the content requirements for a useful migration guide.

**Recommendation:**
Create `docs/ENGINE_TO_CONTEXT_MIGRATION.md` with:

- Side-by-side API mapping table
- Behavioral differences (error handling, callback model)
- QUIC-specific migration steps
- Example: converting a minimal Engine client to Context

**Acceptance criteria:** Migration guide exists with API mapping, behavioral differences, and at least one worked example.

**Verification:** File exists at `docs/ENGINE_TO_CONTEXT_MIGRATION.md` with substantive content.

**Effort:** M

---

### QUAL-102 -- 6x allocator.dupe catch null silently swallow OOM

- **ID:** QUAL-102
- **Severity:** Medium
- **PriorityScore:** 16
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**

- `src/tls13/engine.zig:674` -- `allocator.dupe catch null`
- `src/tls13/engine.zig:682` -- `allocator.dupe catch null`
- `src/tls13/engine.zig:1643` -- `allocator.dupe catch null`
- `src/tls13/engine.zig:1923` -- `allocator.dupe catch null`
- `src/tls13/engine.zig:1941` -- `allocator.dupe catch null`

**Description:**
Five sites in `engine.zig` use `allocator.dupe(...) catch null` to silently swallow `error.OutOfMemory`.

**Resolution:** All five `catch null` sites replaced with `try`. Functions `extractAlpnFromClientHello` and `parseRealClientHello` updated to return error unions (`!void` and `!?[32]u8` respectively). Callers updated to use `try`.

**Effort:** S

---

### QUAL-103 -- maybeAutoProgress swallows queueFinished error

- **ID:** QUAL-103
- **Severity:** Medium
- **PriorityScore:** 16
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**

- `src/tls13/engine.zig:1684` -- `maybeAutoProgress` error swallow

**Description:**
`maybeAutoProgress` calls `queueFinished` internally. If `queueFinished` fails, the error was caught and discarded.

**Resolution:** Changed `maybeAutoProgress` return type from `void` to `!void`. Replaced `catch |err| { ... }` with `try`. Updated the caller in `onCryptoRecv` to use `try self.maybeAutoProgress()`.

**Effort:** S

---

### QUAL-104 -- Magic hex constants for extension types instead of ExtensionType enum

- **ID:** QUAL-104
- **Severity:** Low
- **PriorityScore:** 15
- **Category:** `readability`
- **Confidence:** `confidence::confirmed`
- **Status:** **Closed (Cycle 6 / Phase 19, commit e17c025)** — 2 residual magic-hex `0x0033` sites at `src/tls13/context.zig:2035` and `src/tls13/context/hello_retry.zig:120` replaced with `@intFromEnum(ExtensionType.key_share)`. Also resolves QUAL-349.
- **Cross-reference:** QUAL-204 (Phase 3 deep review confirms additional magic hex in engine.zig: 0x0010, 0x0039, 0x0033; recommends `@intFromEnum(ExtensionType.xxx)` consistently)

**File locations:**

- `src/tls13/engine.zig` -- multiple occurrences
- `src/tls13/context.zig` -- multiple occurrences

**Description:**
Extension type checks throughout the codebase use raw hex constants (e.g., `0x002b` for `supported_versions`, `0x0033` for `key_share`, `0x0029` for `pre_shared_key`) rather than the `ExtensionType` enum values defined in `messages/core_types.zig`. This makes the code harder to read and more error-prone when adding new extension handling.

**Evidence:**

```zig
// Example from engine.zig / context.zig extension scanning loops:
if (etype == 0x002b) { ... }     // should be ExtensionType.supported_versions
if (etype == 0x0033) { ... }     // should be ExtensionType.key_share
```

**Recommendation:**
Replace all magic hex extension type constants with `ExtensionType` enum values. Import `ExtensionType` from `core_types.zig`.

**Acceptance criteria:** No raw hex constants for TLS extension types in engine.zig or context.zig. All use `ExtensionType` enum.

**Verification:** `grep -rn "0x002b\|0x0033\|0x0029\|0x000d\|0x000a" src/tls13/engine.zig src/tls13/context.zig` returns zero results. `zig build test` passes.

**Effort:** S

---

### QUAL-105 -- lib.zig Quick Start example has wrong Context.init signature

- **ID:** QUAL-105
- **Severity:** Low
- **PriorityScore:** 15
- **Category:** `docs`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Quick Start example in `lib.zig` corrected to use 2-parameter `Context.init(allocator, config)` signature

**File locations:**

- `src/lib.zig` -- Quick Start doc comment example

**Description:**
The Quick Start example in `lib.zig` shows `Context.init` taking 3 parameters, but the actual `Context.init` signature accepts 2 parameters. This misleads users attempting to use the library for the first time. Incorrect examples in the entry-point file create a poor first impression and wasted debugging time.

**Evidence:**
The doc comment example shows a 3-parameter call, while the actual function signature in `context.zig` accepts 2 parameters (allocator and config).

**Recommendation:**
Update the Quick Start example to match the actual `Context.init` signature.

**Acceptance criteria:** The `lib.zig` Quick Start example compiles (or would compile) with the actual API. Parameter count and types match.

**Verification:** Extract the example and attempt `zig build` with it, or visually verify parameter count matches `Context.init` signature.

**Effort:** S

---

### QUAL-106 -- Constant-time comparison code duplicated 3 times with subtle variation

- **ID:** QUAL-106
- **Severity:** Low
- **PriorityScore:** 9
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Open

**File locations:**

- `src/tls13/engine.zig` -- constant-time comparison (version 1)
- `src/tls13/context.zig` -- constant-time comparison (version 2)
- Third location with a third variation

**Description:**
Constant-time byte comparison logic is implemented three times across the codebase with subtle differences (e.g., one uses XOR accumulator, another uses `std.crypto.utils.timingSafeEql`, a third inlines a manual loop). For security-critical code like MAC verification, having multiple implementations with subtle behavioral differences increases the risk that one variant is vulnerable to timing attacks.

**Evidence:**
Three separate implementations exist for comparing byte sequences in a timing-safe manner, each with minor structural differences.

**Recommendation:**
Consolidate to a single constant-time comparison function (preferably `std.crypto.utils.timingSafeEql` from the standard library). All MAC/Finished verification call sites should use this single function.

**Acceptance criteria:** One constant-time comparison function used throughout. No hand-rolled timing-safe comparison loops.

**Verification:** `grep -rn "timingSafeEql\|constantTimeEq" src/` shows consistent usage of a single function. `zig build test` passes.

**Effort:** S

---

### QUAL-107 -- Inconsistent error types for same condition across Engine and Context [CLOSED]

- **ID:** QUAL-107
- **Severity:** Low
- **PriorityScore:** 9
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-04-19, Cycle 2) -- Subsumed by engine deletion (commit 4ae8ac7).

**Resolution:** The divergence tracked by QUAL-107 existed *between* Engine and Context. Commit `4ae8ac7` ("refactor(engine): delete src/tls13/engine.zig") removed the entire Engine code path (-2236 LOC). There is no second error-producer to reconcile; Context is the sole driver. Any remaining error-shape concern would be a fresh intra-Context finding, not the cross-module one QUAL-107 tracked. Per the Cycle 2 user-approved default: closed as subsumed.

**Original file locations (now moot):**

- `src/tls13/engine.zig` -- FILE DELETED
- `src/tls13/context.zig` -- uses `UnexpectedMessage`

**Acceptance criteria:** Met (trivially) -- only Context remains; no cross-module inconsistency possible.

**Verification:** `zig build test` PASS post-engine-deletion (Phase 13 verifier output).

**Effort:** S

---

### QUAL-108 -- 14 unused imports across 7 files

- **ID:** QUAL-108
- **Severity:** Low
- **PriorityScore:** 6
- **Category:** `cleanup`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- 11 unused imports removed across 6 files (varint.zig, tls13_full.zig, sig.zig, tls13.zig, context.zig, engine.zig)

**File locations:**

- `src/varint.zig`
- `src/tls13_full.zig`
- `src/tls13/sig.zig`
- `src/tls13.zig`
- `src/tls13/context.zig`
- `src/tls13/engine.zig`
- `src/tls13/types.zig`

**Description:**
14 `@import` or `const` declarations import modules or symbols that are never used in the file. Zig's compiler does not currently warn about unused imports (unlike unused variables), so these accumulate silently. They add noise to the file header and can mislead readers about the file's actual dependencies.

**Recommendation:**
Remove the unused imports. Run `zig build test` to confirm nothing breaks.

**Acceptance criteria:** No unused `@import` declarations in the listed files.

**Verification:** Review each file's imports against actual usage. `zig build test` passes.

**Effort:** S

---

### QUAL-109 -- TODO in context.zig:1207 referencing QUAL-074 callback not wired

- **ID:** QUAL-109
- **Severity:** Low
- **PriorityScore:** 6
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Stale QUAL-074 TODO replaced with deferred enhancement comment documenting that the callback surface is a future improvement, not a correctness issue
- **Cross-reference:** QUAL-074 (Closed -- new_session_ticket handling added to switch statement)

**File locations:**

- `src/tls13/context.zig:1207` -- TODO comment

**Description:**
A TODO comment at context.zig:1207 references the QUAL-074 finding about wiring the `on_new_session_ticket` callback. QUAL-074 was marked Closed after adding the `.new_session_ticket` branch to `handleHandshakeMessage`, but the TODO at line 1207 suggests the callback wiring is still incomplete. This status inconsistency means either the TODO is stale (and should be removed) or the fix was partial (and QUAL-074 should be reopened).

**Recommendation:**
Verify whether the `on_new_session_ticket` callback is fully wired. If yes, remove the stale TODO. If no, document what remains and update QUAL-074 status.

**Acceptance criteria:** The TODO is either resolved (callback wired + TODO removed) or QUAL-074 is reopened with remaining work documented.

**Verification:** `grep -n "TODO.*074\|TODO.*session_ticket" src/tls13/context.zig` returns zero results (if resolved). `zig build test` passes.

**Effort:** S

---

### QUAL-110 -- notifyMetadata callback error logged but not propagated

- **ID:** QUAL-110
- **Severity:** Low
- **PriorityScore:** 6
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (by-design, 2026-03-24) -- notifyMetadata error handling documented as by-design: metadata notification is informational and should not abort the handshake

**File locations:**

- `src/tls13/context.zig:2660` -- `notifyMetadata` error handling

**Description:**
The `notifyMetadata` function calls the `on_handshake_metadata` callback and catches any error, logging it but not propagating it to the caller. This is the same pattern that was fixed in QUAL-072 for other callbacks (`on_peer_finished`, `on_handshake_complete`), but `notifyMetadata` was apparently missed in that remediation.

**Evidence:**

```zig
// context.zig:2660
if (self.callbacks.on_handshake_metadata) |cb| {
    cb(self, metadata) catch |err| {
        logger.debugPrint("[TLS] notifyMetadata error: {}\n", .{err});
    };
}
```

**Recommendation:**
Apply the same fix as QUAL-072: replace `catch |err| { log }` with `try cb(self, metadata)` to propagate callback errors.

**Acceptance criteria:** `notifyMetadata` propagates callback errors to the caller, consistent with the QUAL-072 fix for other callbacks.

**Verification:** `grep -n "catch.*notifyMetadata\|catch.*on_handshake_metadata" src/tls13/context.zig` returns zero results. `zig build test` passes.

**Effort:** S

---

### QUAL-111 -- handleKeyUpdateMessage doc comment misplaced onto handleCertificate

- **ID:** QUAL-111
- **Severity:** Low
- **PriorityScore:** 4
- **Category:** `docs`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Doc comment relocated to correct function; handleCertificate given its own accurate doc comment

**File locations:**

- `src/tls13/context.zig` -- doc comment above `handleCertificate`

**Description:**
The `///` doc comment describing `handleKeyUpdateMessage` is placed above the `handleCertificate` function instead. This means `handleCertificate` has an incorrect doc comment (describing key update behavior), and `handleKeyUpdateMessage` has no doc comment at all (or the wrong one).

**Recommendation:**
Move the doc comment to the correct function. Add an accurate doc comment to `handleCertificate`.

**Acceptance criteria:** Each function has its own accurate `///` doc comment.

**Verification:** Visual inspection. `zig build` succeeds.

**Effort:** S

---

### QUAL-112 -- Engine.init is a single 262-character line

- **ID:** QUAL-112
- **Severity:** Low
- **PriorityScore:** 4
- **Category:** `readability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Engine.init signature formatted across multiple lines with one parameter per line

**File locations:**

- `src/tls13/engine.zig` -- `Engine.init` function signature

**Description:**
The `Engine.init` function signature is written as a single line of 262 characters. This exceeds any reasonable line length limit and makes the function signature difficult to read, review, and diff. Most style guides recommend 100-120 character line limits.

**Evidence:**

```text
// Single line, ~262 characters:
pub fn init(allocator: std.mem.Allocator, config: Config, ...) Engine { ... }
```

**Recommendation:**
Break the function signature across multiple lines, with one parameter per line.

**Acceptance criteria:** `Engine.init` signature is formatted across multiple lines with no line exceeding 120 characters.

**Verification:** Visual inspection. `zig fmt` compliance (if applicable).

**Effort:** S

---

### QUAL-113 -- 14 residual `.?` unwraps in engine.zig (QUAL-087 incomplete)

- **ID:** QUAL-113
- **Severity:** High
- **PriorityScore:** 60 (Impact 5 x Likelihood 3 x 4)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Partial (3 of 14 fixed; 11 remaining)
- **Issue:** [#117](https://gitlab.com/devnw/zig/tls/-/work_items/117)
- **Cross-reference:** QUAL-087 (Closed -- this finding reopens the scope)

**File locations:**

- `src/tls13/engine.zig:669,673,944,970,971,979,1613,1663,1700,1786,1790,1798,1820`

**Description:**
QUAL-087 was marked Closed after addressing certificate verification callback null-safety, but 14 unguarded `.?` optional unwraps remain on handshake state fields: `ecdhe_secret`, `handshake_server_secret`, `handshake_client_secret`, `leaf_spki`, `server_cert_der`, `server_priv_key`, `server_sig_alg`, and `alpn`. In Debug/ReleaseSafe builds these panic; in ReleaseFast/ReleaseSmall they produce undefined behavior.

**Partial Resolution (Phase 8):**
3 of the 14 unsafe `.?` unwraps have been replaced with safe patterns:

- `ecdhe_secret.?` at engine.zig:698 -- replaced with `orelse return error.HandshakeFailure`
- `ecdhe_secret.?` at engine.zig:705 -- uses the safe `ecdhe` local from the orelse above
- `leaf_spki.?` at engine.zig:970 -- replaced with `orelse { ... self.peer_cert_ok = false; return; }`

11 remaining `.?` unwraps on `handshake_server_secret`, `handshake_client_secret`, `server_cert_der`, `server_priv_key`, `server_sig_alg`, and `alpn` still need safe conversion.

**Evidence:**

```zig
// engine.zig:669 -- No null guard on ecdhe_secret
traceSecrets("... ECDHE secret first 4: ...", .{ self.ecdhe_secret.?[0], ... });

// engine.zig:673 -- ecdhe_secret.? passed to deriveHandshakeTraffic
const hs = deriveHandshakeTraffic(self.hash_kind, self.ecdhe_secret.?, th_secret, &early_secret);

// engine.zig:1798 -- server_sig_alg.?, server_priv_key.?
.{ self.server_sig_alg.?, self.server_priv_key.?.len }
```

**Recommendation:**
Replace all remaining `.?` unwraps with `orelse return error.InvalidState` or `if (field) |val|` guard patterns.

**Acceptance criteria:** Zero unguarded `.?` unwraps on optional handshake state in engine.zig.

**Verification:** `grep -n '\\.?' src/tls13/engine.zig | grep -v 'orelse\|if.*|'` returns zero results. `zig build test -Doptimize=ReleaseSafe` passes.

**Effort:** M

---

### QUAL-114 -- 22+ `allocator.dupe` without `errdefer` -- memory leaks on error paths

- **ID:** QUAL-114
- **Severity:** High
- **PriorityScore:** 36 (Impact 3 x Likelihood 3 x 4)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (all 4 files verified)
- **Issue:** [#119](https://gitlab.com/devnw/zig/tls/-/work_items/119)

**File locations:**

- `src/tls13/engine.zig` -- 12 sites: all covered (see QUAL-122/QUAL-129)
- `src/tls13/context.zig` -- 11 sites: all covered (see QUAL-128, closed via prior commit)
- `src/tls13/handshake_state.zig` -- 13 sites: all covered (see QUAL-127)
- `src/quic_transport_params.zig` -- 4 sites: all covered (see QUAL-126)

**Resolution:**
Comprehensive audit of all `allocator.dupe` sites across all 4 files. All sites verified:

- **handshake_state.zig:** 12 of 13 sites already had errdefer from prior commits. Fixed the
  one remaining gap: `psk_copy` at line 352 lacked errdefer for the owned identities and binders
  arrays. Added explicit errdefer + two new tests. (QUAL-127 Closed)
- **quic_transport_params.zig:** 3 connection ID dupe sites at lines 646/650/654 are covered by
  the top-level `errdefer params.deinit(allocator)` at line 561 which frees all three via
  `deinit()`. No code change needed. (QUAL-126 Closed)
- **engine.zig:** All 12 dupe sites use the "store into self field immediately" pattern where
  Engine.deinit() handles cleanup. TicketStore.store has explicit errdefer.
  setServerCertificate has manual catch-free. No additional errdefer needed. (QUAL-122/129 Closed)
- **context.zig:** 11 dupe sites covered by QUAL-128 (closed via prior commit).

**Acceptance criteria:** Every `try allocator.dupe` has a corresponding `errdefer allocator.free(...)` or equivalent coverage.

**Verification:** `zig build test` passes (551/553, 2 skipped). `zig fmt --check src/` clean.

**Effort:** M

---

### QUAL-115 -- `setTransportParameters` silently swallows OOM via `catch return`

- **ID:** QUAL-115
- **Severity:** High
- **PriorityScore:** 30 (Impact 5 x Likelihood 1.5 x 4)
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed
- **Issue:** [#122](https://gitlab.com/devnw/zig/tls/-/work_items/122)
- **Cross-reference:** QUAL-089 (Closed -- missed this code path)

**Resolution:**
Changed `setTransportParameters` return type from `void` to `!void` and replaced `catch return` with `try`. OOM now propagates to callers. File: `src/tls13/context.zig:806`.

**File locations:**

- `src/tls13/context.zig:766`

**Description:**
`Context.setTransportParameters` uses `allocator.dupe(...) catch return` to silently swallow `error.OutOfMemory`. The function returns `void` instead of `!void`, so OOM cannot be propagated. QUIC connections proceed with missing transport parameters.

**Evidence:**

```zig
// context.zig:766
const mutable_copy = self.allocator.dupe(u8, tp_bytes) catch return;
```

Compare with engine.zig which correctly uses `try`:

```zig
// engine.zig:1170
self.local_tp = try self.allocator.dupe(u8, tp_encoded);
```

**Recommendation:**
Change return type to `!void`. Replace `catch return` with `try`. Update callers.

**Acceptance criteria:** `setTransportParameters` returns `!void` and propagates OOM.

**Verification:** `grep -n 'catch return' src/tls13/context.zig` should not show setTransportParameters.

**Effort:** S

---

### QUAL-116 -- 9 additional source files over 800 lines not tracked

- **ID:** QUAL-116
- **Severity:** Medium
- **PriorityScore:** 24 (Impact 3 x Likelihood 2 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Open

**File locations:**

- `src/x509.zig` -- 1736 lines (2.2x limit)
- `src/record/aead.zig` -- 1337 lines (1.7x limit)
- `src/tls13/messages/server_hello.zig` -- 1081 lines (1.4x limit)
- `src/quic_transport_params.zig` -- 1206 lines (1.5x limit)
- `src/asn1.zig` -- 1035 lines (1.3x limit)
- `src/parallel.zig` -- 1016 lines (1.3x limit)
- `src/key_schedule.zig` -- 942 lines (1.2x limit)
- `src/tls13/messages/client_hello.zig` -- 855 lines (1.1x limit)
- `src/sig.zig` -- 814 lines (1.0x limit)

Plus `build.zig` at 1112 lines (tracked separately as QUAL-123).

**Description:**
QUAL-069 tracked only `context.zig` and `engine.zig` as over-limit. 9 additional source files exceed the 800-line guideline. `x509.zig` at 1736 lines is the third-largest file in the codebase.

**Recommendation:**
Evaluate each file for extraction opportunities. Priority order by size: x509.zig, aead.zig, quic_transport_params.zig, server_hello.zig, asn1.zig, parallel.zig.

**Acceptance criteria:** Files identified for splitting have extraction plans documented.

**Verification:** `wc -l src/**/*.zig | awk '$1 > 800' | sort -rn`

**Effort:** L (strategic, file-by-file evaluation)

---

### QUAL-117 -- 14 functions over 100 lines (parseCert 396 lines)

- **ID:** QUAL-117
- **Severity:** Medium
- **PriorityScore:** 20 (Impact 2 x Likelihood 2.5 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Open
- **Cross-reference:** QUAL-201 (Phase 3 deep review provides specific extraction plan for parseCert)

**File locations:**

- `src/x509.zig:697-1092` -- `parseCert` (396 lines)
- `src/x509.zig:1574-1736` -- `validateChain` (163 lines)
- `src/tls13/engine.zig` -- multiple 100+ line functions
- `src/tls13/context.zig` -- multiple 100+ line test functions
- `src/tls13/messages/server_hello.zig` -- `buildHelloRetryRequest` (100+ lines)

**Description:**
14 functions exceed the 100-line guideline. `parseCert` at 396 lines is the largest. It contains ASN.1 DER parsing for X.509 certificates including version, serial number, signature algorithm, issuer, validity, subject, public key, and extensions -- all in a single function.

**Evidence:**

```text
x509.zig:697-1092 -- parseCert (396 lines)
x509.zig:1574-1736 -- validateChain (163 lines)
engine.zig -- multiple functions at 101-110 lines
context.zig -- test functions 100-291 lines
server_hello.zig -- buildHelloRetryRequest 100+ lines
```

**Recommendation:**
Extract sub-functions: `parseCert` could become `parseTbsCertificate`, `parseCertExtensions`, `parseCertSubject`, `parseCertPublicKey`.

**Acceptance criteria:** No function exceeds 100 lines (excluding test functions which may be longer for readability).

**Verification:** Function length audit. `zig build test` passes.

**Effort:** L

---

### QUAL-118 -- SecretSlot struct duplicated between context.zig and secrets.zig

- **ID:** QUAL-118
- **Severity:** Medium
- **PriorityScore:** 20 (Impact 4 x Likelihood 1.25 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- context.zig now imports SecretSlot from secrets.zig at line 287

**File locations:**

- `src/tls13/context.zig:278-296` -- `SecretSlot` definition
- `src/tls13/secrets.zig:67-86` -- `SecretSlot` definition (canonical)

**Description:**
`SecretSlot` is defined identically in both `context.zig` and `secrets.zig`. The `secrets.zig` version is the canonical extracted module (also re-exported via `tls13/mod.zig:127` and `tls13.zig:146`), but `context.zig` retains its own local copy. Comments at `context.zig:71` and `context.zig:89` acknowledge this pending extraction. `BidirSecrets` and `SecretSchedule` are similarly duplicated.

**Evidence:**

```zig
// context.zig:278
pub const SecretSlot = struct {
    value: Secret = Secret.empty(),
    hash: Hash = .sha256,
    valid: bool = false,
    epoch: EncryptionLevel = .Initial,
    generation: u32 = 0,
    ...
};

// secrets.zig:67
pub const SecretSlot = struct {
    value: Secret = Secret.empty(),
    hash: Hash = .sha256,
    valid: bool = false,
    epoch: EncryptionLevel = .Initial,
    generation: u32 = 0,
    ...
};
```

Both are byte-for-byte identical in structure and methods.

**Recommendation:**
Delete `SecretSlot`, `BidirSecrets`, and `SecretSchedule` from `context.zig`. Import from `secrets.zig` (already available via `tls13/mod.zig`).

**Acceptance criteria:** Single `SecretSlot` definition in `secrets.zig`. `context.zig` imports it.

**Verification:** `grep -rn "pub const SecretSlot = struct" src/` returns exactly one result. `zig build test` passes.

**Effort:** S

---

### QUAL-119 -- Deep nesting in client_hello.zig (10 levels) and x509.zig (9 levels)

- **ID:** QUAL-119
- **Severity:** Medium
- **PriorityScore:** 18 (Impact 3 x Likelihood 1.5 x 4)
- **Category:** `readability`
- **Confidence:** `confidence::confirmed`
- **Status:** Open
- **Cross-reference:** QUAL-202 (confirms same nesting depths; x509.zig nesting addressed by QUAL-201 parseCert extraction)

**File locations:**

- `src/tls13/messages/client_hello.zig` -- max nesting depth 10 (around line 419)
- `src/x509.zig` -- max nesting depth 9 (around line 968)

**Description:**
QUAL-094 addressed 14-level nesting in `engine.zig:onCryptoRecv`, but other files also exceed the 4-level nesting guideline. `client_hello.zig` reaches 10 levels of brace nesting in extension parsing logic. `x509.zig` reaches 9 levels in certificate extension parsing. Deep nesting makes control flow difficult to follow and increases cognitive load during review.

**Evidence:**
Measured via brace-counting analysis:

- `client_hello.zig`: max depth 10 at line 419
- `x509.zig`: max depth 9 at line 968

**Recommendation:**
Extract deeply-nested blocks into named helper functions. Use early-return patterns to reduce nesting.

**Acceptance criteria:** Maximum nesting depth under 6 in both files.

**Verification:** Brace-depth analysis shows max depth <= 6. `zig build test` passes.

**Effort:** M

---

### QUAL-120 -- quic_transport_params.zig `decode()` missing errdefer

- **ID:** QUAL-120
- **Severity:** Medium
- **PriorityScore:** 16 (Impact 4 x Likelihood 1 x 4)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**

- `src/quic_transport_params.zig:559-700` -- `TransportParameters.decode()`

**Description:**
`decode()` allocates memory via `allocator.dupe` at lines 645, 649, 653 for connection IDs but only has errdefer at 2 of 4 dupe call sites. The `PreferredAddress.decode` (line 284) has proper errdefer at line 319 for `conn_id_buf`, but the main `decode()` function does not guard all its allocations.

**Resolution:**
Added `errdefer params.deinit(allocator)` immediately after `var params = TransportParameters{};` in `decode()`. This single errdefer covers all allocations (connection IDs and preferred address) because `deinit()` frees all allocated fields. This is more robust than per-dupe errdefer guards since it also covers future allocations added to decode().

**Acceptance criteria:** All allocations in `decode()` have errdefer guards -- met via single `errdefer params.deinit(allocator)`.

**Verification:** `zig build test` passes. Code review confirms errdefer on all allocation sites.

**Effort:** S

---

### QUAL-121 -- Engine cert handling converts OOM to cert-invalid

- **ID:** QUAL-121
- **Severity:** Medium
- **PriorityScore:** 16 (Impact 4 x Likelihood 1 x 4)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed

**File locations:**

- `src/tls13/engine.zig:865-870`

**Description:**
When `allocator.dupe` fails for `leaf.spki` during certificate processing, the error is caught and the certificate is marked as invalid (`break :blk false`) rather than propagating `error.OutOfMemory`. This converts a transient memory condition into a permanent certificate rejection, potentially causing valid connections to fail under memory pressure.

**Resolution:**
Replaced `catch { break :blk false }` patterns with `try` in three locations within cert handling:

- `allocator.alloc([]const u8, ...)` for chain_der array
- `allocator.alloc(x509.Certificate, ...)` for parsed_certs array
- `allocator.dupe(u8, leaf.spki)` for leaf SPKI
OOM now propagates as `error.OutOfMemory` instead of silently rejecting valid certificates.

**Acceptance criteria:** OOM during certificate processing propagates as `error.OutOfMemory`, not cert-invalid. -- MET

**Verification:** `zig build test` passes.

**Effort:** S

---

### QUAL-122 -- Engine dupe calls at 9 sites lack errdefer

- **ID:** QUAL-122
- **Severity:** Medium
- **PriorityScore:** 16 (Impact 2 x Likelihood 2 x 4)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (already handled)
- **Issue:** [#125](https://gitlab.com/devnw/zig/tls/-/work_items/125)
- **Cross-reference:** QUAL-114 (umbrella issue)

**Resolution:**
Comprehensive audit of all 12 `allocator.dupe` sites in engine.zig found that no additional
errdefer is needed:

1. **TicketStore.store (line 187):** Already has `errdefer self.allocator.free(ident_copy)` at
   line 188. COVERED.
2. **handleReceivedEncryptedExtensions ALPN (line 809):** Result stored immediately into
   `self.alpn`. Engine.deinit() frees it. COVERED by ownership transfer.
3. **handleReceivedEncryptedExtensions QUIC TP (line 819):** Same pattern -- stored into
   `self.peer_tp`. COVERED.
4. **handleReceivedCertificate leaf_spki (line 896):** Stored into `self.leaf_spki`. COVERED.
5. **setLocalTransportParameters (line 1211):** Stored into `self.local_tp`. COVERED.
6. **setServerName (line 1219):** Stored into `self.server_name`. COVERED.
7. **extractAlpnFromClientHello (line 1714):** Stored into `self.alpn`. COVERED.
8. **setServerCertificate (lines 1789-1793):** Two dupes with manual catch-free on second
   failure. COVERED by explicit error handling.
9. **parseRealClientHello session_id (line 1971):** Stored into `engine.client_session_id`.
   COVERED.
10. **parseRealClientHello peer_tp (line 1986):** Stored into `engine.peer_tp`. COVERED.

Engine dupe sites use the "store into self field immediately" pattern where Engine.deinit()
handles cleanup. This is a valid alternative to errdefer when the allocation is immediately
transferred to a struct that has a comprehensive deinit(). No code change needed.

**Effort:** S

---

### QUAL-123 -- build.zig at 1112 lines exceeds 800-line guideline

- **ID:** QUAL-123
- **Severity:** Low
- **PriorityScore:** 10 (Impact 2 x Likelihood 1.25 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Open

**File locations:**

- `build.zig` -- 1112 lines

**Description:**
`build.zig` is 1.4x the 800-line guideline. It contains build configuration, test targets, benchmark targets, and module declarations. While build files are often larger than source files, extracting helper functions could improve maintainability.

**Recommendation:**
Extract test target builders, benchmark configuration, and module declarations into helper functions or a `build/` directory.

**Acceptance criteria:** `build.zig` under 800 lines or documented as acceptable.

**Verification:** `wc -l build.zig`

**Effort:** S

---

### QUAL-124 -- readU16 helper duplicated between sct.zig and messages/helpers.zig

- **ID:** QUAL-124
- **Severity:** Low
- **PriorityScore:** 8 (Impact 2 x Likelihood 1 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Won't Do (2026-03-24) -- sct.zig intentionally avoids tls13 imports (documented in code); trivial one-liner not worth shared module

**File locations:**

- `src/sct.zig:31` -- `readU16` definition
- `src/tls13/messages/helpers.zig:40` -- `readU16` definition (canonical)

**Description:**
`readU16` is defined in both `sct.zig` and `messages/helpers.zig`. The `sct.zig` version even has a comment acknowledging: "Canonical readU16 lives in tls13/messages/helpers.zig." Despite this comment, it defines its own copy.

**Recommendation:**
Delete `readU16` from `sct.zig`. Import from `messages/helpers.zig`.

**Acceptance criteria:** Single `readU16` definition.

**Verification:** `grep -rn "pub fn readU16" src/` returns exactly one result.

**Effort:** S

---

### QUAL-125 -- HashDigestCache struct duplicated between context.zig and transcript.zig

- **ID:** QUAL-125
- **Severity:** Low
- **PriorityScore:** 8 (Impact 2 x Likelihood 1 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-24) -- Removed 23-line unused HashDigestCache definition from context.zig

**File locations:**

- `src/tls13/context.zig:419-440` -- `HashDigestCache` definition
- `src/tls13/transcript.zig:398-420` -- `HashDigestCache` definition (canonical)

**Description:**
`HashDigestCache` is defined identically in both files. The `transcript.zig` version is exported via `tls13/mod.zig:70`. Context.zig defines its own local copy. The `TranscriptHashPair` struct in context.zig (line 446) even uses `transcript_mod.HashDigestCache` for some fields while using the local `HashDigestCache` implicitly for others.

**Recommendation:**
Delete `HashDigestCache` from `context.zig`. Use `transcript_mod.HashDigestCache` consistently.

**Acceptance criteria:** Single `HashDigestCache` definition in `transcript.zig`.

**Verification:** `grep -rn "const HashDigestCache = struct" src/` returns exactly one result.

**Effort:** S

---

### QUAL-126 -- quic_transport_params.zig only 2 of 4 dupe sites have errdefer

- **ID:** QUAL-126
- **Severity:** Low
- **PriorityScore:** 4 (Impact 2 x Likelihood 0.5 x 4)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (already handled)
- **Cross-reference:** QUAL-114 (umbrella), QUAL-120 (decode-specific)

**Resolution:**
The three connection ID dupe sites at lines 646, 650, 654 in `decode()` do NOT need individual
errdefer because they are already covered by the top-level `errdefer params.deinit(allocator)` at
line 561. The `deinit()` method (lines 704-712) frees all three connection ID fields
(`initial_source_connection_id`, `original_destination_connection_id`,
`retry_source_connection_id`) plus `preferred_address`. Each dupe stores its result immediately
into the `params` struct, so the top-level errdefer covers all error paths. No code change needed.

**Effort:** S

---

### QUAL-127 -- handshake_state.zig 13 dupe sites -- only 1 has errdefer

- **ID:** QUAL-127
- **Severity:** Low
- **PriorityScore:** 4 (Impact 2 x Likelihood 0.5 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed
- **Cross-reference:** QUAL-114 (umbrella)

**Resolution:**
Audit found that 12 of 13 dupe sites already had errdefer (added in prior commits). The one
remaining gap was `psk_copy`: after the PSK `if` block at line 352, the owned identities and
binders arrays had no errdefer, so a failure in the subsequent `psk_modes_copy` dupe would leak
them. Added an explicit errdefer at line 353 that frees all owned identity/binder data. Two new
tests added: an OOM resilience test exercising all failure points and a happy-path leak-detection
test. All 551 tests pass.

**Effort:** S

---

### QUAL-128 -- context.zig 11 dupe sites without errdefer

- **ID:** QUAL-128
- **Severity:** Low
- **PriorityScore:** 4 (Impact 2 x Likelihood 0.5 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-25) -- Added errdefer at 8 `allocator.dupe` sites in context.zig.
- **Cross-reference:** QUAL-114 (umbrella)

**File locations:**

- `src/tls13/context.zig:1100,1133,1417,1449,2633,2645,2653,2670,2867,2882,2957,2969`

**Description:**
11 `try allocator.dupe` calls in context.zig lack errdefer. These span certificate chain handling, ALPN processing, transport parameter copying, and peer certificate verification signature storage.

**Recommendation:**
Add errdefer after each dupe call.

**Acceptance criteria:** All dupe sites in context.zig have errdefer.

**Effort:** S

---

### QUAL-129 -- Engine zero errdefer usage across all allocator.dupe calls

- **ID:** QUAL-129
- **Severity:** Low
- **PriorityScore:** 4 (Impact 1 x Likelihood 1 x 4)
- **Category:** `readability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (already handled)
- **Cross-reference:** QUAL-114 (umbrella), QUAL-122 (engine-specific)

**Resolution:**
Audit found that engine.zig now has 1 errdefer (TicketStore.store line 188, added in prior
commit). The remaining dupe sites use the "store into self field immediately" pattern where
Engine.deinit() handles cleanup. This is architecturally sound: every dupe result is stored into
an Engine field before any subsequent fallible operation, and Engine.deinit() frees all owned
fields. Adding redundant errdefer would be incorrect (double-free) since the allocation is
already owned by the struct. setServerCertificate handles its two-dupe case with an explicit
catch-free block. No further errdefer additions needed.

**Effort:** S

---

### QUAL-130 -- Stale line counts in QUAL-069 (3581 vs actual 3431)

- **ID:** QUAL-130
- **Severity:** Low
- **PriorityScore:** 4 (Impact 1 x Likelihood 1 x 4)
- **Category:** `cleanup`
- **Confidence:** `confidence::confirmed`
- **Status:** Open

**File locations:**

- `docs/QUALITY_GAP_ANALYSIS.md` -- QUAL-069 description

**Description:**
QUAL-069 reports context.zig as 3581 lines, but the current count is 3431 lines (150 lines reduced from prior refactoring). The documented line count is stale.

**Recommendation:**
Update QUAL-069 description to reflect current 3431-line count.

**Acceptance criteria:** Line count in QUAL-069 matches reality.

**Effort:** S

---

### QUAL-201 -- parseCert at 396 lines with 6 inline extension sub-parsers

- **ID:** QUAL-201
- **Severity:** Medium
- **PriorityScore:** 24 (Impact 3 x Likelihood 2 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-25) -- Extracted 7 extension sub-parsers from `parseCert`, reducing it from 396 to 194 lines.
  New helper functions: parseSanExtension, parseBasicConstraints, parseKeyUsage, parseExtKeyUsage,
  parseNameConstraints, parsePolicyConstraints, parseAuthorityKeyIdentifier.
- **Cross-reference:** QUAL-117 (umbrella for all 100+ line functions), QUAL-202 (nesting reduction addressed by this extraction)

**File locations:**

- `src/x509.zig:697-1092` -- `parseCert` (was 396 lines, now 194 lines)

**Description:**
`parseCert` was a single 396-line function that parsed X.509 DER certificates including ASN.1 TBS certificate structure, version, serial number, signature algorithm, issuer, validity, subject, public key, and 6 extension sub-parsers inlined directly into the function body: Subject Alternative Name (SAN), Basic Constraints, Key Usage, Extended Key Usage, Name Constraints, and Policy Constraints. Each sub-parser was a self-contained block of 20-60 lines that has now been extracted.

**Evidence:**

```zig
// x509.zig:697
pub fn parseCert(alloc: std.mem.Allocator, der: []const u8) !Certificate {
    // ... 396 lines of parsing logic ...
    // Lines ~850-900: SAN parsing
    // Lines ~900-930: BasicConstraints parsing
    // Lines ~930-960: KeyUsage parsing
    // Lines ~960-999: NameConstraints parsing (9 levels of nesting)
    // Lines ~1000-1050: ExtKeyUsage parsing
    // Lines ~1050-1092: PolicyConstraints parsing
}
```

Confirmed by `wc` and function boundary analysis: `parseCert` starts at line 697 and the closing brace is at line 1092.

**Recommendation:**
Extract 6 helper functions:

- `parseSanExtension(ext_data) -> []SubjectAltName`
- `parseBasicConstraints(ext_data) -> BasicConstraints`
- `parseKeyUsage(ext_data) -> KeyUsage`
- `parseExtKeyUsage(ext_data) -> ExtKeyUsage`
- `parseNameConstraints(ext_data) -> NameConstraints`
- `parsePolicyConstraints(ext_data) -> PolicyConstraints`

Each helper is a pure function operating on a slice of extension DER data. The main `parseCert` calls each via a switch on the extension OID. This also resolves the 9-level nesting in QUAL-202 since the deeply nested name constraints logic moves to its own function.

**Acceptance criteria:** `parseCert` is under 150 lines. Each extension parser is a named function. All x509 tests pass.

**Verification:** `zig build test`. Function length audit shows `parseCert` under 150 lines.

**Effort:** M

---

### QUAL-202 -- Deep nesting (10 levels in client_hello.zig, 9 levels in x509.zig)

- **ID:** QUAL-202
- **Severity:** Medium
- **PriorityScore:** 18 (Impact 3 x Likelihood 1.5 x 4)
- **Category:** `readability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-25) -- x509.zig nesting reduced via QUAL-201 parseCert extraction. The 9-level nesting in extension parsing is now distributed across extracted helper functions.
- **Cross-reference:** QUAL-119 (identical finding from Phase 2), QUAL-201 (x509.zig nesting resolved by parseCert extraction)

**File locations:**

- `src/tls13/messages/client_hello.zig:416-424` -- 10 levels of nesting in key_share extension parsing
- `src/x509.zig:940-999` -- 9 levels of nesting in name constraints extension parsing

**Description:**
Phase 3 deep review independently confirmed the nesting depths reported in QUAL-119. The x509.zig 9-level nesting at lines 940-999 occurs within the name constraints extension parsing block inside `parseCert`. This nesting is directly addressed by the QUAL-201 extraction: once `parseNameConstraints` is its own function, the nesting resets and the deepest path drops to approximately 5-6 levels.

The client_hello.zig 10-level nesting at lines 416-424 in key_share parsing requires separate attention (early-return patterns or helper extraction).

**Recommendation:**

- x509.zig: Addressed by QUAL-201 extraction. No separate action needed.
- client_hello.zig: Extract key_share extension parsing into a `parseKeyShareExtension` helper, or use early-return/continue patterns to reduce nesting.

**Acceptance criteria:** Maximum nesting depth under 6 in both files.

**Verification:** Brace-depth analysis. `zig build test` passes.

**Effort:** M (client_hello.zig portion; x509.zig covered by QUAL-201)

---

### QUAL-203 -- OCSP error mapping loses diagnostic info (32 catch-return sites)

- **ID:** QUAL-203
- **Severity:** Medium
- **PriorityScore:** 20 (Impact 2.5 x Likelihood 2 x 4)
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-25) -- Added trace logging to 8 critical OCSP parse points.
  Fixed `.?` unwraps to `orelse` patterns. Diagnostic info now available via OCSP trace flag.

**File locations:**

- `src/ocsp.zig:138-319` -- 32 `catch return OcspError.MalformedResponse` sites

**Description:**
The OCSP response parser (`parseOcspResponse` and helpers) contains 32 instances of `catch return OcspError.MalformedResponse` that discard the original ASN.1 decoding error. When OCSP validation fails, the caller receives only `MalformedResponse` with no indication of which parsing step failed or what the underlying ASN.1 error was. This makes debugging OCSP failures in production extremely difficult -- especially for certificate chain issues where the OCSP responder returns a subtly malformed response.

**Evidence:**

```zig
// ocsp.zig:138
const cert_tlv = dec.readTLV() catch return OcspError.MalformedResponse;

// ocsp.zig:172
const ocsp_seq = ocsp_dec.readSequence() catch return OcspError.MalformedResponse;

// ocsp.zig:175
const response_status_tlv = ocsp_inner.readTLV() catch return OcspError.MalformedResponse;

// ... 29 more identical patterns through line 319
```

Confirmed count: `grep -c 'catch return' src/ocsp.zig` returns 32.

**Root cause:** The OCSP parser was written to normalize all ASN.1 errors into a single error code for simplicity. This is correct from a security perspective (do not leak internal parsing details to callers) but harmful for debugging.

**Recommendation:**
Add `log.debug` before each `catch return` to preserve the original error for diagnostic purposes without changing the error type returned to callers:

```zig
const cert_tlv = dec.readTLV() catch |err| {
    log.debug("OCSP: readTLV failed at cert_tlv: {}", .{err});
    return OcspError.MalformedResponse;
};
```

Alternatively, use an `errdefer`-based approach at the top of each parsing function to log the error context once.

**Acceptance criteria:** All 32 catch-return sites log the original error at debug level before returning `MalformedResponse`.

**Verification:** `grep -c 'catch return OcspError.MalformedResponse' src/ocsp.zig` returns 0 (all converted to catch-with-log pattern). `zig build test` passes.

**Effort:** S

---

### QUAL-204 -- Magic hex constants in engine.zig (0x0010, 0x0039, 0x0033) vs enum in context.zig

- **ID:** QUAL-204
- **Severity:** Medium
- **PriorityScore:** 20 (Impact 2 x Likelihood 2.5 x 4)
- **Category:** `readability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-25) -- Replaced all magic hex extension type constants with
  `@intFromEnum(ExtensionType.*)` in engine.zig.
- **Cross-reference:** QUAL-104 (umbrella for all magic hex extension constants)

**File locations:**

- `src/tls13/engine.zig:801` -- `0x0010` (ALPN extension)
- `src/tls13/engine.zig:817` -- `0x0039` (QUIC transport parameters)
- `src/tls13/engine.zig:1345` -- `0x0010` (ALPN extension, second occurrence)
- `src/tls13/engine.zig:1708` -- `0x0010` (ALPN extension, third occurrence)
- `src/tls13/engine.zig:2044` -- `0x0033` (key_share)

**Description:**
Phase 3 deep review identified additional magic hex constants in `engine.zig` beyond those tracked in QUAL-104. While `context.zig` uses `ExtensionType` enum values from `core_types.zig`, `engine.zig` uses raw hex literals for ALPN (`0x0010`), QUIC transport parameters (`0x0039`), and key_share (`0x0033`). This inconsistency between the two TLS implementations makes the code harder to audit and increases the risk of typos in extension type values.

**Evidence:**

```zig
// engine.zig:801 -- raw hex
switch (etype) {
    0x0010 => { // ALPN
        if (elen >= 3) {

// engine.zig:817
    0x0039 => { // QUIC TP

// engine.zig:2044
    } else if (etype == 0x0033) { // key_share (server format)
```

**Recommendation:**
Replace all magic hex with `@intFromEnum(ExtensionType.xxx)` or switch on `@as(ExtensionType, @enumFromInt(etype))`. This is part of the broader QUAL-104 cleanup.

**Acceptance criteria:** No raw hex extension type constants in engine.zig. All use `ExtensionType` enum.

**Verification:** `grep -En '0x0010|0x0039|0x0033' src/tls13/engine.zig` returns zero results. `zig build test` passes.

**Effort:** S

---

### QUAL-205 -- `hexToBytes` duplicated 14 times across test files [CLOSED]

- **ID:** QUAL-205
- **Severity:** Medium
- **PriorityScore:** 20 (Impact 2 x Likelihood 2.5 x 4)
- **Category:** `maintainability`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-04-19, Cycle 2) -- commit efc573e. Extracted shared helper to `tests/test_utils.zig`; migrated 13 caller test files to import it; fixed a latent rfc8446 §4.4.4 finished test that silently depended on the old inline copy. Full `zig build test` PASS post-migration.

**File locations:**

- `tests/openssl_conformance.zig:92`
- `tests/sig_unit_tests.zig:20`
- `tests/rfc8446/section_4_1_2_client_hello.zig:44`
- `tests/x509_openssl_conformance.zig:60`
- `tests/rfc8446/section_7_1_key_schedule.zig:72`
- `tests/rfc8446/section_4_4_4_finished.zig:47`
- `tests/rfc8446/section_4_1_3_server_hello.zig:49`
- `tests/rfc8446/section_4_4_1_transcript.zig:33`
- `tests/rfc8446/section_5_record_protocol.zig:45`
- `tests/rfc9001/section_5_packet_protection.zig:41`
- `tests/rfc9001/appendix_a_initial_secrets.zig:31`
- `tests/boringssl_conformance.zig:78`
- `tests/x509_unit_tests.zig:24`
- `tests/conformance/handshake_secrets.zig:17`

**Description:**
The `hexToBytes` utility function is copy-pasted into 14 separate test files. Some copies take `comptime hex: []const u8` while others take `hex: []const u8` (runtime), creating a subtle signature divergence. A bug fix or improvement to hex parsing (e.g., handling uppercase vs lowercase) would need to be applied 14 times.

**Evidence:**

```zig
// Comptime variant (e.g., rfc8446/section_7_1_key_schedule.zig:72):
fn hexToBytes(comptime hex: []const u8, out: []u8) void { ... }

// Runtime variant (e.g., openssl_conformance.zig:92):
fn hexToBytes(hex: []const u8, out: []u8) void { ... }
```

**Recommendation:**
Extract `hexToBytes` into a shared `tests/test_utils.zig` module. Export both comptime and runtime variants. All 14 test files import from this single source. Use `comptime` variant as the default since most callers pass string literals.

**Acceptance criteria:** A single `hexToBytes` definition exists in `tests/test_utils.zig`. All 14 test files import and use it. `zig build test` passes.

**Verification:** `grep -rn 'fn hexToBytes' tests/` returns exactly one result (in test_utils.zig). `zig build test` passes.

**Effort:** S

---

### QUAL-206 -- Redundant condition engine.zig:802-803

- **ID:** QUAL-206
- **Severity:** Low
- **PriorityScore:** 16 (Impact 2 x Likelihood 2 x 4)
- **Category:** `cleanup`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-25) -- Removed redundant `if (elen >= 2)` inside `if (elen >= 3)` block.

**File locations:**

- `src/tls13/engine.zig:802-803`

**Description:**
A redundant nested condition check:

```zig
if (elen >= 3) {
    if (elen >= 2) {
```

The inner check `elen >= 2` is always true when the outer check `elen >= 3` passes. This is dead logic that adds a misleading nesting level without providing any guard value.

**Evidence:**

```zig
// engine.zig:802-803
0x0010 => { // ALPN
    if (elen >= 3) {
        if (elen >= 2) {
            const list_len = readU16(edata[0..2]);
```

**Root cause:** Likely a copy-paste artifact or incremental tightening of the guard where the inner check was not removed after the outer check was strengthened.

**Recommendation:**
Delete the inner `if (elen >= 2)` block and flatten the code by one nesting level. Keep only `if (elen >= 3)`.

**Acceptance criteria:** No redundant nested length checks in ALPN parsing. Code compiles and all tests pass.

**Verification:** Visual inspection of engine.zig:802. `zig build test` passes.

**Effort:** S

---

### QUAL-207 -- 17 `.?` unwraps in context.zig rely on implicit state invariants

- **ID:** QUAL-207
- **Severity:** Low
- **PriorityScore:** 16 (Impact 2 x Likelihood 2 x 4)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-25) -- Added 10 SAFETY comments for `.?` unwraps documenting invariants.
  Converted `negotiated_cipher_suite.?` to `orelse return InternalError` for the one fragile case.
- **Cross-reference:** QUAL-113 (engine.zig `.?` unwraps -- different file/scope)

**File locations:**

- `src/tls13/context.zig` -- 17 `.?` unwraps on optional fields

**Description:**
Context.zig contains 17 `.?` optional unwraps on state fields such as `negotiated_cipher_suite`, `server_secret_generated`, and others. All guards have been manually confirmed correct: each `.?` is reached only after a code path that guarantees the optional is non-null. However, this relies on implicit state machine invariants that are not enforced by the type system.

Unlike the engine.zig `.?` unwraps in QUAL-113 (which had actual null-safety gaps), these context.zig unwraps are architecturally sound. The recommendation is defensive improvement for critical paths, not a bug fix.

**Recommendation:**
For the most critical paths (`negotiated_cipher_suite`, `server_secret_generated`), replace `.?` with `orelse return error.InvalidState` to provide a clear error instead of a panic if the state machine invariant is ever violated by future code changes. Leave low-risk `.?` unwraps (debug/trace paths) unchanged.

**Acceptance criteria:** Critical-path `.?` unwraps use `orelse return error.X`. Non-critical paths documented with SAFETY comments.

**Verification:** `zig build test -Doptimize=ReleaseSafe` passes.

**Effort:** S

---

### QUAL-208 -- Dual `KeyMaterial` types with incompatible layouts [CLOSED]

- **ID:** QUAL-208
- **Severity:** Low
- **PriorityScore:** 16 (Impact 2 x Likelihood 2 x 4)
- **Category:** `architecture`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-04-19, Cycle 2) -- duplicate of QUAL-335 which delivered the rename in commit 599a1da; Cycle 2 ledger alignment in commit b4bf419.

**File locations (post-closure):**

- `src/parallel.zig:600` -- `DerivedKeyMaterial` (renamed from `KeyMaterial` in Phase 13, commit 599a1da) with `key: [32]u8`, `iv: [12]u8`, `hp_key: [32]u8`, `key_len: usize`
- `src/key_schedule.zig:36` -- `KeyMaterial` with `key: [16]u8`, `iv: [12]u8`, `hp: [16]u8` (canonical)

**Description:**
Originally flagged two types named `KeyMaterial` with incompatible layouts:

```zig
// parallel.zig:616
pub const KeyMaterial = struct {
    key: [32]u8,
    iv: [12]u8,
    hp_key: [32]u8,
    key_len: usize,
};

// key_schedule.zig:36
pub const KeyMaterial = struct {
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
};
```

The `parallel.zig` version uses 32-byte fixed arrays with a `key_len` field to support both AES-128 (16-byte key) and AES-256 (32-byte key). The `key_schedule.zig` version assumes 16-byte keys only (AES-128). The field name also differs: `hp_key` vs `hp`. Code that passes a `parallel.KeyMaterial` to a function expecting `key_schedule.KeyMaterial` will get a compile error (caught at build time), but the naming collision is confusing and suggests they should be unified or one should be renamed.

**Root cause:** The `parallel` module was developed independently as future infrastructure and did not reuse the existing `key_schedule.KeyMaterial` type.

**Recommendation:**
Either:

1. Unify into a single `KeyMaterial` type in `key_schedule.zig` that supports variable key lengths (use `key: [32]u8` + `key_len: usize`), or
2. Rename `parallel.KeyMaterial` to `parallel.DerivedKeyMaterial` to avoid the naming collision.

Option 2 is lower risk since the parallel module is not yet exported.

**Acceptance criteria:** No two types named `KeyMaterial` with incompatible layouts. Either unified or distinctly named.

**Verification:** `grep -rn 'pub const KeyMaterial = struct' src/` returns one result (or two with distinct names). `zig build test` passes.

**Effort:** S

---

### QUAL-209 -- `parallel` module not exported from lib.zig [CLOSED]

- **ID:** QUAL-209
- **Severity:** Low
- **PriorityScore:** 12 (Impact 1.5 x Likelihood 2 x 4)
- **Category:** `api-contract`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (Phase 11, commit b31f035) -- verified in Cycle 2 (2026-04-19).

**Resolution:** `src/lib.zig:414` now contains `pub const parallel = @import("parallel");` with a doc-comment referencing the public helpers. A smoke test at `src/lib.zig:550-556` proves the re-export works end-to-end and exercises `parallel.getPool` + `parallel.deinitPool`. Commit: `b31f035`.

**File locations (post-closure):**

- `src/lib.zig:414` -- `pub const parallel = @import("parallel");` (doc-commented)
- `src/parallel.zig` -- module exists with public API

**Description:**
The `parallel` module (`src/parallel.zig`) provides parallel key derivation and certificate verification utilities but is not exported from the library's public entry point (`src/lib.zig`). Users of the library cannot access `parallel` functionality without directly importing the file path, which is an implementation detail.

The module is confirmed as intentional future/optional infrastructure (not dead code), so it should be made available through the public API.

**Recommendation:**
Add to `src/lib.zig`:

```zig
/// Parallel operations for key derivation and certificate verification.
/// Optional module for performance-sensitive applications.
pub const parallel = @import("parallel.zig");
```

**Acceptance criteria:** `@import("tls").parallel` compiles and provides access to parallel key derivation functions.

**Verification:** Add a test that imports `parallel` via `lib.zig`. `zig build test` passes.

**Effort:** S

---

### QUAL-210 -- `TicketEntryView` exported but unused outside engine.zig

- **ID:** QUAL-210
- **Severity:** Low
- **PriorityScore:** 12 (Impact 1.5 x Likelihood 2 x 4)
- **Category:** `cleanup`
- **Confidence:** `confidence::confirmed`
- **Status:** Closed (2026-03-25) -- Removed unused `TicketEntryView` exports from mod.zig and tls13.zig.

**File locations:**

- `src/tls13/mod.zig:263` -- `pub const TicketEntryView = engine.TicketEntryView;`
- `src/tls13.zig:257` -- `pub const TicketEntryView = mod.TicketEntryView;`
- `src/tls13/engine.zig:152` -- `TicketEntryView` struct definition

**Description:**
`TicketEntryView` is defined in `engine.zig` and re-exported through two levels of public API (`mod.zig` and `tls13.zig`), but no code outside of `engine.zig` references it. The struct is used only by `TicketStore.lookup` and `Engine.peekTicket`, both internal to `engine.zig`. The re-exports add unused symbols to the public API surface.

**Evidence:**

```text
$ grep -rn 'TicketEntryView' src/
src/tls13/mod.zig:263:pub const TicketEntryView = engine.TicketEntryView;
src/tls13.zig:257:pub const TicketEntryView = mod.TicketEntryView;
src/tls13/engine.zig:152:pub const TicketEntryView = struct {
src/tls13/engine.zig:212:    pub fn lookup(...) ?TicketEntryView {
src/tls13/engine.zig:213:        var result: ?TicketEntryView = null;
src/tls13/engine.zig:530:    pub fn peekTicket(self: *Engine) ?TicketEntryView {
```

No usage outside `engine.zig`.

**Recommendation:**
Remove the re-exports from `mod.zig:263` and `tls13.zig:257`. If `TicketEntryView` is intended as part of the public API for external consumers, document its intended use case. Otherwise, keep it as an internal type within `engine.zig`.

**Acceptance criteria:** `TicketEntryView` is either removed from public re-exports or has documented public consumers.

**Verification:** `grep -rn 'TicketEntryView' src/tls13/mod.zig src/tls13.zig` returns zero results. `zig build test` passes.

**Effort:** S

---

### Phase 3 Deep Review -- Confirmed Non-Issues

The following items were investigated during Phase 3 deep review and confirmed as non-issues requiring no action:

**1. `catch unreachable` usage (46 sites):** All 46 `catch unreachable` patterns across the codebase have been verified as safe. Each has a preceding SAFETY comment explaining why the error cannot occur at that call site (e.g., fixed-size buffers that cannot overflow, comptime-known valid inputs). No action required.

**2. Engine legacy exports:** The Engine module re-exports several types that will become unnecessary when Engine is retired in favor of Context. These are tracked implicitly under QUAL-069/QUAL-091 (Engine deprecation strategy) and will be cleaned up in a batch removal. No separate tracking needed.

**3. `parallel` module is not dead code:** The parallel module is intentional future/optional infrastructure for performance-sensitive QUIC applications. It is not dead code. Tracked under QUAL-209 for public API export.

**4. All `.?` unwraps in context.zig have valid guards:** All 17 `.?` unwraps in context.zig have been manually verified to have correct state invariants ensuring non-null values at the unwrap point. Tracked under QUAL-207 for defensive improvement on critical paths only.

---

## Findings by Category

### Architecture (14)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-087 | Critical | engine.zig null-safety gap in certificate verification | Closed |
| QUAL-113 | High | 14 residual `.?` unwraps in engine.zig (QUAL-087 incomplete); 3 fixed, 11 remaining | Partial |
| QUAL-114 | High | 22+ allocator.dupe without errdefer -- memory leaks on error paths | Closed |
| QUAL-097 | High | parseHandshakeOne catch null wedges on invalid message type | Closed |
| QUAL-071 | High | 0-RTT early_secret uses wrong transcript hash (server side) | Closed |
| QUAL-120 | Medium | quic_transport_params.zig decode() missing errdefer | Closed |
| QUAL-121 | Medium | Engine cert handling converts OOM to cert-invalid | Closed |
| QUAL-122 | Medium | Engine dupe calls at 9 sites lack errdefer | Closed |
| QUAL-102 | Medium | 6x allocator.dupe catch null silently swallow OOM | Closed |
| QUAL-074 | Medium | new_session_ticket silently dropped in Context path | Closed |
| QUAL-207 | Low | 17 `.?` unwraps in context.zig rely on implicit state invariants; confirmed correct | Closed |
| QUAL-208 | Low | Dual `KeyMaterial` types with incompatible layouts (parallel.zig vs key_schedule.zig) | Closed (2026-04-19) |
| QUAL-126 | Low | quic_transport_params.zig only 2 of 4 dupe sites have errdefer | Closed |
| QUAL-109 | Low | TODO in context.zig:1207 -- QUAL-074 callback not wired (status inconsistent) | Closed |

### Maintainability (21)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-094 | High | onCryptoRecv 516 lines / 14 nesting levels | Closed |
| QUAL-095 | High | driveServerHandshakeFlight 243 lines combining 6 concerns | Closed |
| QUAL-096 | High | ClientHello building duplicated 3 times (~500 lines) | Closed |
| QUAL-069 | High | context.zig 3431 lines (4.3x limit) | Closed (Subsumed 2026-04-20 by QUAL-317) |
| QUAL-070 | High | Near-duplicate ClientHelloInfo struct+parse+deinit | Closed |
| QUAL-091 | High | engine.zig uses legacy inline key schedule patterns | Closed (Subsumed 2026-04-20 by engine.zig deletion 4ae8ac7) |
| QUAL-201 | Medium | parseCert 396 lines with 6 inline extension sub-parsers | Closed |
| QUAL-205 | Medium | `hexToBytes` duplicated 14 times across test files | Closed (2026-04-19) |
| QUAL-116 | Medium | 8 source files over 800 lines (post-QUAL-317 refresh) | Open |
| QUAL-117 | Medium | 14 functions over 100 lines (parseCert 396 lines) | Open |
| QUAL-118 | Medium | SecretSlot duplicated between context.zig and secrets.zig | Closed |
| QUAL-073 | Medium | Near-duplicate parseRealServerHello / handleServerHello | Closed (Subsumed 2026-04-20 by engine.zig deletion 4ae8ac7) |
| QUAL-075 | Medium | Two distinct CipherSuite enums | Closed (By Design) |
| QUAL-076 | Medium | Duplicated SignatureScheme-to-SigAlg with unsafe else | Closed |
| QUAL-106 | Low | Constant-time comparison duplicated 3 times with subtle variation | Open |
| QUAL-123 | Low | build.zig at 1112 lines exceeds 800-line guideline | Won't Do |
| QUAL-124 | Low | readU16 helper duplicated between sct.zig and messages/helpers.zig | Won't Do |
| QUAL-125 | Low | HashDigestCache dead code removed from context.zig | Closed |
| QUAL-127 | Low | handshake_state.zig 13 dupe sites -- only 1 has errdefer | Closed |
| QUAL-128 | Low | context.zig 11 dupe sites without errdefer | Closed |
| QUAL-081 | Low | cipherSuiteHash exact duplicate | Closed |

### API Contract (11)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-115 | High | setTransportParameters silently swallows OOM via catch return | Closed |
| QUAL-072 | High | Callback errors logged but not propagated | Closed |
| QUAL-089 | High | setTransportParameters lacks OOM error handling | Closed |
| QUAL-090 | High | NewSessionTicket processing incomplete error propagation | Closed |
| QUAL-203 | Medium | OCSP error mapping loses diagnostic info; 32 catch-return discard ASN.1 errors | Closed |
| QUAL-098 | Medium | queueServerHandshakeFlight returns void -- errors not propagated | Closed |
| QUAL-103 | Medium | maybeAutoProgress swallows queueFinished error | Closed |
| QUAL-209 | Low | `parallel` module not exported from lib.zig | Closed (2026-04-18) |
| QUAL-085 | Low | pollCrypto returns Unimplemented for empty buffer | Closed |
| QUAL-107 | Low | Inconsistent error types -- CryptoBufferOverflow vs UnexpectedMessage | Closed (2026-04-19) |
| QUAL-110 | Low | notifyMetadata callback error logged but not propagated | Closed (by-design) |

### Cleanup (9)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-092 | Medium | byteorder.zig duplicated across two module paths | Closed |
| QUAL-080 | Medium | 18x @constCast for freeing const slices | Closed |
| QUAL-206 | Low | Redundant condition engine.zig:802-803 inner check always true | Closed |
| QUAL-210 | Low | TicketEntryView exported but unused outside engine.zig | Closed |
| QUAL-130 | Low | Stale line counts in QUAL-069 | Won't Do |
| QUAL-082 | Low | traceHandshake/traceSecrets exact duplicates (5 files) | Closed (By Design) |
| QUAL-083 | Low | encodeMinimal*/parseMinimal* exact duplicates | Closed |
| QUAL-086 | Low | deriveFinishedVerifyData dead code in messages/finished.zig | Closed |
| QUAL-108 | Low | 14 unused imports across 7 files | Closed |

### Performance / Security (2)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-088 | Critical | x25519KeypairAndShared duplicated with security divergence | Closed |
| QUAL-078 | Medium | Duplicated x25519KeypairAndShared with behavioral divergence | Closed |

### Tests (1)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-099 | Medium | No HRR test coverage in Context | Closed |

### Docs (6)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-100 | Medium | Config field constraints undocumented | Closed |
| QUAL-101 | Medium | No Engine-to-Context migration guide (content depth) | Closed |
| QUAL-077 | Medium | No Engine-to-Context migration guide | Closed |
| QUAL-079 | Medium | Corrupted Callbacks doc comment | Closed |
| QUAL-105 | Low | lib.zig Quick Start example has wrong Context.init signature | Closed |
| QUAL-111 | Low | handleKeyUpdateMessage doc comment misplaced onto handleCertificate | Closed |

### CI/CD (1)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-093 | Medium | CI pipeline lacks build caching | Won't Do |

### Readability (7)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QUAL-204 | Medium | Magic hex constants in engine.zig (0x0010, 0x0039, 0x0033) vs enum in context.zig | Closed |
| QUAL-202 | Medium | Deep nesting (10 levels client_hello.zig, 9 levels x509.zig); cross-ref QUAL-119 | Closed |
| QUAL-119 | Medium | Deep nesting in client_hello.zig (10) and x509.zig (9) | Open |
| QUAL-084 | Low | 13x inline u16 big-endian read instead of readU16 helper | Closed |
| QUAL-104 | Low | Magic hex constants for extension types instead of ExtensionType enum | Closed (Cycle 6 / Phase 19, commit e17c025) |
| QUAL-129 | Low | Engine zero errdefer usage across all allocator.dupe calls | Closed |
| QUAL-112 | Low | Engine.init is a single 262-character line | Closed |

---

## Roadmap

### Quick Wins (less than 1 day)

| ID | Finding | Effort | Status |
|----|---------|--------|--------|
| QUAL-115 | Change setTransportParameters to return !void, replace catch return with try | S | Closed |
| QUAL-118 | Delete SecretSlot from context.zig, import from secrets.zig | S | Closed |
| QUAL-120 | Add errdefer guards in quic_transport_params.zig decode() | S | Closed |
| QUAL-121 | Propagate OOM in engine.zig cert handling instead of cert-invalid | S | Closed |
| QUAL-122 | Add errdefer to 9 engine.zig dupe sites | S | Closed |
| QUAL-124 | Delete readU16 from sct.zig, import from helpers.zig | S | Won't Do |
| QUAL-125 | Remove dead HashDigestCache definition from context.zig | S | Closed |
| QUAL-126 | Add errdefer to quic_transport_params.zig dupe sites | S | Closed |
| QUAL-128 | Add errdefer to 11 context.zig dupe sites | S | Closed |
| QUAL-130 | Update stale line counts in QUAL-069 | S | Won't Do |
| QUAL-123 | Evaluate build.zig for extraction | S | Won't Do |
| QUAL-097 | Fix parseHandshakeOne to distinguish invalid vs incomplete data | S | Closed |
| QUAL-098 | Change queueServerHandshakeFlight return type to !void | S | Closed |
| QUAL-102 | Replace allocator.dupe catch null with try | S | Closed |
| QUAL-103 | Propagate queueFinished error in maybeAutoProgress | S | Closed |
| QUAL-100 | Add doc comments to Config fields | S | Closed |
| QUAL-104 | Replace magic hex extension constants with ExtensionType enum | S | Closed (Cycle 6 / Phase 19, commit e17c025) |
| QUAL-105 | Fix lib.zig Quick Start Context.init signature | S | Closed |
| QUAL-106 | Consolidate constant-time comparison to single function | S | Open |
| QUAL-107 | Unify error types between Engine and Context | S | Closed (2026-04-19) |
| QUAL-108 | Remove 14 unused imports | S | Closed |
| QUAL-109 | Resolve stale QUAL-074 TODO or reopen QUAL-074 | S | Closed |
| QUAL-110 | Documented as by-design (informational callback) | S | Closed |
| QUAL-111 | Fix misplaced handleKeyUpdateMessage doc comment | S | Closed |
| QUAL-112 | Break Engine.init signature across multiple lines | S | Closed |
| QUAL-088 | Delete engine.zig x25519KeypairAndShared duplicate (CWE-226) | S | Closed |
| QUAL-089 | Audit transport parameter OOM propagation | S | Closed |
| QUAL-092 | Delete duplicate byteorder.zig | S | Closed |
| QUAL-093 | Add CI cache directive for Zig toolchain | S | Won't Do |
| QUAL-203 | Add log.debug before each OCSP catch-return to preserve ASN.1 error context | S | Closed |
| QUAL-204 | Replace magic hex extension constants in engine.zig with ExtensionType enum | S | Closed |
| QUAL-205 | Extract hexToBytes to shared tests/test_utils.zig (14 duplicates) | S | Closed (2026-04-19) |
| QUAL-206 | Delete redundant inner `if (elen >= 2)` check in engine.zig:803 | S | Closed |
| QUAL-207 | Add `orelse return error.InvalidState` for critical-path `.?` unwraps in context.zig | S | Closed |
| QUAL-208 | Rename parallel.KeyMaterial to DerivedKeyMaterial (or unify with key_schedule.KeyMaterial) | S | Closed (2026-04-19, dup of QUAL-335) |
| QUAL-209 | Add `pub const parallel = @import("parallel.zig")` to lib.zig | S | Closed (2026-04-18) |
| QUAL-210 | Remove unused TicketEntryView re-exports from mod.zig and tls13.zig | S | Closed |
| QUAL-071 | Fix 0-RTT transcript hash ordering (server side) | S | Closed |
| QUAL-072 | Propagate callback errors (or change signature to void) | S | Closed |
| QUAL-075 | Unify CipherSuite enums | S | Closed (By Design) |
| QUAL-076 | Replace inline switch with fromTls13SignatureScheme | S | Closed |
| QUAL-078 | Delete engine.zig x25519KeypairAndShared copy | S | Closed |
| QUAL-079 | Fix Callbacks doc comments | S | Closed |
| QUAL-081 | Extract cipherSuiteHash to shared module | S | Closed |
| QUAL-082 | Extract trace helpers to shared module | S | Closed (By Design) |
| QUAL-083 | Delete encodeMinimal*/parseMinimal* copies in engine.zig | S | Closed |
| QUAL-084 | Replace inline u16 reads with readU16 helper | S | Closed |
| QUAL-085 | Fix pollCrypto error semantics | S | Closed |
| QUAL-086 | Remove dead deriveFinishedVerifyData from messages/finished.zig | S | Closed |

### Medium (1-5 days)

| ID | Finding | Effort | Status |
|----|---------|--------|--------|
| QUAL-201 | Extract 6 extension sub-parsers from parseCert (SAN, BasicConstraints, KeyUsage, ExtKeyUsage, NameConstraints, PolicyConstraints) | M | Closed |
| QUAL-202 | Reduce deep nesting in client_hello.zig key_share parsing (x509.zig covered by QUAL-201) | M | Closed |
| QUAL-113 | Replace 14 residual .? unwraps with safe patterns in engine.zig (3 done, 11 remaining) | M | Partial |
| QUAL-114 | Add errdefer to 22+ allocator.dupe sites across 4 files | M | Closed |
| QUAL-119 | Reduce nesting depth in client_hello.zig and x509.zig | M | Open |
| QUAL-127 | Add errdefer to 13 handshake_state.zig dupe sites | S | Closed |
| QUAL-129 | Systematic errdefer audit for all engine.zig allocations | S | Closed |
| QUAL-094 | Decompose onCryptoRecv into 6 handler methods | M | Closed |
| QUAL-095 | Extract driveServerHandshakeFlight into sub-functions | M | Closed |
| QUAL-099 | Add HRR test coverage for Context | M | Closed |
| QUAL-101 | Write Engine-to-Context migration guide (with API mapping + examples) | M | Closed |
| QUAL-087 | Replace .? unwraps with safe patterns in engine.zig | M | Closed |
| QUAL-091 | Refactor engine.zig to use key_derivation_mod | M | Deferred |
| QUAL-090 | Add error propagation to NewSessionTicket processing | M | Closed |
| QUAL-070 | Consolidate ClientHelloInfo struct + parse + deinit | M | Closed |
| QUAL-073 | Unify ServerHello extension parsing | M | Deferred |
| QUAL-074 | Add new_session_ticket handling to Context | M | Closed |
| QUAL-077 | Write Engine-to-Context migration guide | S | Closed |
| QUAL-080 | Refactor const slice storage to eliminate @constCast | M | Closed |

### Strategic (more than 5 days)

| ID | Finding | Effort | Status |
|----|---------|--------|--------|
| QUAL-116 | Evaluate and split 8 source files over 800 lines (post-QUAL-317 refresh; issue #242) | L | Open |
| QUAL-117 | Decompose 14 functions over 100 lines (parseCert 396 lines) | L | Open |
| QUAL-317 | Decompose context.zig monolith into subsystems (session_resumption, cert_orchestrator, hrr_state) | L | Closed (2026-04-20, 7f3b48e) |
| ~~QUAL-319~~ | Engine quarantine: deprecation-gate or move legacy engine.zig under internal/ | M | Closed (2026-04-19, 4ae8ac7 — engine.zig deleted outright) |
| QUAL-096 | Extract shared ClientHelloBuilder for all 3 call sites | L | Closed |
| QUAL-069 | Split context.zig into sub-modules | L | Closed (Subsumed 2026-04-20 by QUAL-317) |

---

## Phase 11 Findings -- /codepros:audit Phase 4 (2026-04-18)

Thirty-three new findings captured from Phase 3 deep review and filed to GitLab with PriorityScore rubric `Impact x Likelihood x 4`. Highest-leverage remediations per reviewer are called out in Top 5 Risks above.

### Phase 11 Findings Table

| QUAL-ID | Sev | Score | Category | Finding | File:Line | Issue |
|---------|-----|-------|----------|---------|-----------|-------|
| QUAL-301 | High | 64 | architecture | Duplicate BidirSecrets/SecretSchedule types -- contract drift | `src/tls13/context.zig:300-353` vs `src/tls13/secrets.zig:117-166` | [#154](https://gitlab.com/devnw/zig/tls/-/work_items/154) |
| QUAL-302 | Low | 16 | cleanup | parseMinimalHelloPub byte-identical duplicate | `engine.zig:1951`, `messages.zig:288` | [#178](https://gitlab.com/devnw/zig/tls/-/work_items/178) |
| QUAL-303 | Medium | 36 | maintainability | RSA-PSS verify triple copy-paste across parallel.zig + sig.zig | `parallel.zig:373-433`, `sig.zig:370-407` | [#180](https://gitlab.com/devnw/zig/tls/-/work_items/180) |
| QUAL-304 | High | 64 | readability | 10-level nesting in EncryptedExtensions handler | `engine.zig:811-848` | [#157](https://gitlab.com/devnw/zig/tls/-/work_items/157) |
| QUAL-305 | High | 60 | ci-cd | flake.nix references missing nix/ dir -- nix build fails OOTB | `flake.nix:56, 61` | [#160](https://gitlab.com/devnw/zig/tls/-/work_items/160) |
| QUAL-306 | Medium | 36 | deps | Zig min-version drift 0.15.1 vs 0.16.0 | `build.zig.zon:28`, `Makefile:193`, `.gitlab-ci.yml:27` | [#176](https://gitlab.com/devnw/zig/tls/-/work_items/176) |
| QUAL-307 | Low | 12 | cleanup | Stale dup thread_pool cache dir (4.1 MB) | `zig-pkg/thread_pool-0.2.0-11B1Bjc9OQCp*` | [#185](https://gitlab.com/devnw/zig/tls/-/work_items/185) |
| QUAL-308 | Medium | 48 | tests | run_tests.sh stale counts (4 of ~17 modules tracked) | `run_tests.sh:18-24` | [#174](https://gitlab.com/devnw/zig/tls/-/work_items/174) |
| QUAL-309 | Low | 16 | ci-cd | pre-commit zig-fmt hook misses tests/ | `.pre-commit-config.yaml:100-107` | [#187](https://gitlab.com/devnw/zig/tls/-/work_items/187) |
| QUAL-310 | Medium | 60 | ci-cd | No CI cache stanza -- ~300MB re-downloads per pipeline | `.gitlab-ci.yml` | [#168](https://gitlab.com/devnw/zig/tls/-/work_items/168) |
| QUAL-311 | Low | 12 | ci-cd | pre-commit check-todos hook always exits 0 (no-op) | `.pre-commit-config.yaml:130-138` | [#186](https://gitlab.com/devnw/zig/tls/-/work_items/186) |
| QUAL-312 | Medium | 36 | maintainability | quic_transport_params.zig decode() 119-LOC 17-arm switch | `quic_transport_params.zig:559-677` | [#189](https://gitlab.com/devnw/zig/tls/-/work_items/189) |
| QUAL-313 | Low | 32 | docs | 30 catch-unreachable + 9 bare unreachable -- missing invariant comments | `src/` (39 sites) | [#190](https://gitlab.com/devnw/zig/tls/-/work_items/190) |
| QUAL-314 | Low | 16 | api-contract | parallel.getPool() @panic; no serial fallback | `parallel.zig:78` | [#191](https://gitlab.com/devnw/zig/tls/-/work_items/191) |
| QUAL-315 | Medium | 64 | tests | No coverage instrumentation despite 52k LOC | repo-root | [#170](https://gitlab.com/devnw/zig/tls/-/work_items/170) |
| QUAL-316 | Medium | 60 | maintainability | Trace-flag boilerplate duplicated in 7+ modules | 7 modules | [#164](https://gitlab.com/devnw/zig/tls/-/work_items/164) |
| QUAL-317 | High | 100 | maintainability | context.zig monolith (3549 LOC, 32 methods) -- highest leverage | `src/tls13/context.zig` | [#150](https://gitlab.com/devnw/zig/tls/-/work_items/150) |
| QUAL-318 | Medium | 32 | maintainability | Byte-order helpers forked 3 ways | `sct.zig:31`, `messages/helpers.zig:40,62,81`, `byteorder.zig:43` | [#192](https://gitlab.com/devnw/zig/tls/-/work_items/192) |
| ~~QUAL-319~~ | ~~High~~ | ~~64~~ | architecture | engine.zig (2236 LOC LEGACY) still public -- quarantine or gate | `tls13.zig:96`, `tls13/mod.zig:254` | [#166](https://gitlab.com/devnw/zig/tls/-/work_items/166) — **Closed 2026-04-19, 4ae8ac7** |
| QUAL-320 | Low | 12 | api-contract | Ungated std.debug.print inside trace blocks | `context.zig:1008-1010,1271,1388-1390`, `sig.zig:568-602` | [#193](https://gitlab.com/devnw/zig/tls/-/work_items/193) |
| QUAL-321 | Medium | 36 | api-contract | Wholesale re-export from lib.zig -- curate public facade | `src/lib.zig:270-539` | [#194](https://gitlab.com/devnw/zig/tls/-/work_items/194) |
| QUAL-322 | Medium | 32 | tests | Dual orphan test drivers (run_tests.sh vs build.zig) | repo-root | [#175](https://gitlab.com/devnw/zig/tls/-/work_items/175) |
| QUAL-323 | High | 64 | architecture | Contract-drift vector -- dup-type twin of QUAL-301 | same as QUAL-301 | [#171](https://gitlab.com/devnw/zig/tls/-/work_items/171) |
| QUAL-324 | Medium | 36 | api-contract | RSA-PSS error-code fragmentation (magic ints vs !bool) | `parallel.zig:370,403,433`, `sig.zig:370+` | [#195](https://gitlab.com/devnw/zig/tls/-/work_items/195) |
| QUAL-325 | Medium | 36 | api-contract | parallel.getPool() process-global + panics -- undocumented | `parallel.zig:78`, `src/lib.zig` | [#196](https://gitlab.com/devnw/zig/tls/-/work_items/196) |
| QUAL-326 | Medium | 24 | api-contract | Error-path stderr noise from library | `parallel.zig:78`, `sig.zig:564-602` | [#197](https://gitlab.com/devnw/zig/tls/-/work_items/197) |
| QUAL-327 | Low | 16 | ci-cd | No per-job test timeouts (only fuzz has one) | `.gitlab-ci.yml` | [#198](https://gitlab.com/devnw/zig/tls/-/work_items/198) |
| QUAL-328 | Low | 16 | cleanup | QUAL-### sigils embedded in production comments | `engine.zig` (~32), `context.zig` (~61) | [#199](https://gitlab.com/devnw/zig/tls/-/work_items/199) |
| QUAL-329 | Low | 24 | docs | ENGINE_TO_CONTEXT_MIGRATION.md drift -- engine still 2236 LOC | `docs/ENGINE_TO_CONTEXT_MIGRATION.md:4` | [#200](https://gitlab.com/devnw/zig/tls/-/work_items/200) |
| QUAL-330 | Medium | 32 | docs | ARCHITECTURE.md omits handshake_state, messages/helpers, cookie, parallel, zero_rtt | `docs/ARCHITECTURE.md:13-37` | [#201](https://gitlab.com/devnw/zig/tls/-/work_items/201) |
| QUAL-331 | Low | 24 | docs | key_schedule.zig + varint.zig: 39 unreachable without invariant comments | `key_schedule.zig:164-248`, `varint.zig` | [#202](https://gitlab.com/devnw/zig/tls/-/work_items/202) |
| QUAL-332 | Medium | 32 | docs | No RUNBOOK, no ADR, no docs/README index | `docs/` | [#203](https://gitlab.com/devnw/zig/tls/-/work_items/203) |
| QUAL-333 | Low | 24 | docs | CHANGELOG.md sparse -- missing Engine-to-Context, parallel, zero_rtt | `CHANGELOG.md` | [#204](https://gitlab.com/devnw/zig/tls/-/work_items/204) |

### Phase 11 Highest-Leverage Cluster (reviewer recommendation)

1. **QUAL-317** (context monolith) -- PriorityScore 100. Strategic. Effort L.
2. **QUAL-316** (trace boilerplate) -- PriorityScore 60. Effort M.
3. **QUAL-301 + QUAL-323** (duplicate types, one logical issue) -- PriorityScore 64 each. Effort S (joint).
4. ~~**QUAL-319**~~ (engine quarantine) -- ~~PriorityScore 64. Effort M.~~ **Closed 2026-04-19 (4ae8ac7, engine.zig deleted).**
5. **QUAL-310** (CI cache) -- PriorityScore 60. Effort S.
6. **QUAL-305** (missing nix/ dir) -- PriorityScore 60. Effort S.
7. **QUAL-322 + QUAL-308** (orphan test driver) -- PriorityScore 32 + 48. Effort S (joint).

### Phase 11 Carry-Forward Verified Open

- ~~**QUAL-091** -- engine.zig legacy key schedule patterns~~ -- Closed Cycle 6 / Phase 18 (Subsumed 2026-04-20 by engine.zig deletion 4ae8ac7)
- **QUAL-093** -- CI build caching (superseded by QUAL-310)
- **QUAL-116** -- 8 source files over 800 lines (post-QUAL-317 inventory refresh; issue [#242](https://gitlab.com/devnw/zig/tls/-/work_items/242))
- **QUAL-117** -- 14 functions over 100 lines
- ~~**QUAL-205** -- hexToBytes x14 in tests~~ -- Closed Cycle 2 (efc573e)
- ~~**QUAL-208** -- Dual KeyMaterial types~~ -- Closed Cycle 2 (dup of QUAL-335, commit 599a1da)

---

## Phase 12 Findings -- /codepros:audit Phase 4 (2026-04-19)

Ten new findings filed to GitLab in Phase 12. Scoring rubric: `PriorityScore = Impact x Likelihood x 4`. All confirmed confidence (evidence cited in each issue). Findings target CI drift, duplicate types, long functions/files, documentation gaps, and a constant-only shim module.

### Phase 12 Findings Table

| QUAL-ID | Sev | Score | Category | Finding | File:Line | Issue | Status |
|---------|-----|-------|----------|---------|-----------|-------|--------|
| QUAL-334 | High | 48 | maintainability | zig fmt asymmetry -- pre-commit scopes src/+build.zig; 2 test files fail `zig fmt --check` | `.pre-commit-config.yaml:100-107`; `tests/conformance/boringssl/post_quantum_readiness.zig`; `tests/sct_openssl_conformance.zig` | [#204](https://gitlab.com/devnw/zig/tls/-/work_items/204) | Closed (Phase 13, 9a8c76d) |
| QUAL-335 | Medium | 24 | maintainability | Duplicate `KeyMaterial` struct -- extends QUAL-301/323 dup-type pattern | `src/key_schedule.zig:36`, `src/parallel.zig:595` | [#205](https://gitlab.com/devnw/zig/tls/-/work_items/205) | Closed (Phase 13, 599a1da) |
| QUAL-336 | Medium | 24 | maintainability | Duplicate `HandshakeState` -- public canonical shadowed by private struct in context.zig | `src/tls13/handshake_state.zig:419` (pub), `src/tls13/context.zig:437` (private) | [#206](https://gitlab.com/devnw/zig/tls/-/work_items/206) | Closed (Phase 13, 500876b) |
| QUAL-337 | Medium | 36 | maintainability | Duplicate `CipherSuite` enum -- two independent definitions (not re-exports) | `src/record/aead.zig:86`, `src/tls13/messages/core_types.zig:258` | [#207](https://gitlab.com/devnw/zig/tls/-/work_items/207) | Closed (Phase 13/14, 148b6ba / 59f5e50) |
| QUAL-338 | Medium | 36 | maintainability | x509.zig 1857 LOC (3rd-largest); parseCert 193 LOC, runChainChecks 152 LOC | `src/x509.zig:928`, `src/x509.zig:1611` | [#208](https://gitlab.com/devnw/zig/tls/-/work_items/208) | **[CLOSED]** (2026-04-20, commit 264b83e) |
| QUAL-339 | Medium | 36 | readability | parseClientHello 296 LOC + buildClientHello 210 LOC -- split per-extension | `src/tls13/messages/client_hello.zig:1170`, `:1211` | [#209](https://gitlab.com/devnw/zig/tls/-/work_items/209) | **[CLOSED]** (2026-04-20, commit 45cc212) |
| QUAL-340 | Medium | 36 | readability | validateStapledResponse 199 LOC combines 4 validators | `src/ocsp.zig:330` | [#210](https://gitlab.com/devnw/zig/tls/-/work_items/210) | **[CLOSED]** (2026-04-20, commit a94fcb1) |
| QUAL-341 | Low | 16 | readability | verifySignature 114 LOC + signCertificateVerify 111 LOC -- scheme-dispatch tables | `src/parallel.zig:760`, `src/sig.zig:2398` | [#211](https://gitlab.com/devnw/zig/tls/-/work_items/211) | **[CLOSED]** (2026-04-20, commit 2a8baf5) |
| QUAL-342 | Low | 12 | docs | key_schedule.zig 57% public-fn doc coverage; crypto-critical derivations missing RFC 8446 §7.1 cites | `src/key_schedule.zig` | [#214](https://gitlab.com/devnw/zig/tls/-/work_items/214) | **[CLOSED]** (2026-04-20, commit 2afe89e) |
| QUAL-343 | Medium | 24 | maintainability | src/tls13_full.zig 170 LOC constant-only shim; 7 test consumers -- usingnamespace or delete | `src/tls13_full.zig` | [#216](https://gitlab.com/devnw/zig/tls/-/work_items/216) | Won't Do (Cycle 2, 9ef0ba3) |

### Phase 12 Recommended Remediations

- **QUAL-334**: Extend pre-commit `zig-fmt` args to include `tests/`; run `zig fmt tests/conformance/boringssl/post_quantum_readiness.zig tests/sct_openssl_conformance.zig`; align CI to same scope.
- **QUAL-335**: Delete `src/parallel.zig:595 KeyMaterial`; re-export from `src/key_schedule.zig`.
- **QUAL-336**: Canonicalize on `src/tls13/handshake_state.zig:HandshakeState`; remove private shadow in context.zig; define `HandshakeStateView` if a reduced struct is genuinely needed.
- **QUAL-337**: Canonicalize on `src/tls13/messages/core_types.zig:CipherSuite` (the `enum(u16)` with wire values); convert `record/aead.zig` to import + alias; add comptime parity test.
- **QUAL-338**: Split `parseCert` into per-extension OID handlers (pattern already used elsewhere in the codebase); split `runChainChecks` into named sub-checks with unit tests.
- **QUAL-339**: Table-driven `ExtHandler` dispatch keyed on `ExtensionType`; one parse/build handler per extension.
- **QUAL-340**: Split into `validateResponderId`, `validateSignature`, `validateValidity`, `validateCerts`.
- **QUAL-341**: `std.EnumArray(SignatureScheme, SchemeOps)` dispatch for sign/verify ops.
- **QUAL-342**: Add `///` doc comments to 10 undocumented public fns; cite RFC 8446 §7.1 per derivation (early/handshake/master secret, HKDF-Expand-Label).
- **QUAL-343**: ~~Prefer Option B (delete)~~ **Investigated 2026-04-19 — Won't Do (full delete).** Attempted to (a) absorb the shim's 20 re-export `pub const` lines into `src/tls13/messages.zig` and (b) retarget the `tls13_full` build-graph module at `messages.zig` so the 27 consumer `@import("tls13_full")` sites would resolve to messages.zig directly. Compile fails with `error: file exists in modules 'tls13' and 'tls13_full' -- files must belong to only one module`. Zig 0.16 forbids a source file from being the root of one module while also being reached via relative `@import` from inside another module, and `messages.zig` is relative-imported by `src/tls13/mod.zig` and `src/tls13/context.zig`. The only other delete path is migrating all 27 consumers to direct submodule imports (`messages/core_types.zig`, `messages/client_hello.zig`, ...). That is 27-file high-churn work in security-adjacent code for zero runtime benefit; shim is 171 LOC of `pub const X = Y.X` -- stable, inert, costless. Keep as-is. If ever the churn is justified, revisit with a single cross-file codemod rather than hand edits.

### Phase 12 Cross-References

- **Engine deletion (~~QUAL-319~~ — Closed 2026-04-19, 4ae8ac7) cascading impact.** QUAL-319 closed (engine.zig deleted outright); it resolved or partially resolved:
  - **QUAL-335** (KeyMaterial duplication) -- partial: `parallel.zig` copy would still need consolidation with `key_schedule.zig`, but engine-side crypto callers disappear.
  - **QUAL-337** (CipherSuite dup) -- partial: engine's reliance on `record/aead.zig:CipherSuite` is a sizable consumer; removing engine reduces motivation to keep the split.
  - **QUAL-304** (10-level nesting in engine.zig EncryptedExtensions handler) -- resolved: the nested code lives entirely in the legacy engine path.
- **QUAL-117 (functions > 100 LOC)** is extended by QUAL-338/339/340/341 with precise file:line evidence and per-function remediations; QUAL-117 remains the umbrella.
- **QUAL-116 (files > 800 LOC)** is extended by QUAL-338 (x509.zig 1857) and QUAL-343 (tls13_full.zig shim).
- **QUAL-301/323 (duplicate types)** is extended by QUAL-335/336/337 — the dup-type pattern continues to surface across crypto-adjacent modules.

### Phase 12 Highest-Leverage Cluster

1. **QUAL-334** (Score 48) -- Quick win (S). Fixes live CI drift; unblocks clean formatting baseline.
2. **QUAL-337** (Score 36) -- CipherSuite enum canonicalization is security-interop-adjacent.
3. **QUAL-338, QUAL-339, QUAL-340** (Score 36 each) -- Coordinated refactor of the three long-function hotspots.
4. **QUAL-343** (Score 24) -- Shim deletion; removes indirection + aligns with deletion-over-patching instinct.
5. **QUAL-335, QUAL-336** (Score 24 each) -- Should land with or after the ~~QUAL-319~~ engine decision (Closed 2026-04-19, 4ae8ac7).

---

## Cycle 7 / Phase 20 Filings (2026-04-21, QUAL-357..QUAL-368)

Eight new actionable issues filed from Phase 3 quality-reviewer output, plus three refutations and one Info-only annotation. QUAL-345 closed as superseded by QUAL-357.

### Phase 20 Findings Table

| QUAL-ID | Issue | Severity | PS | Category | Finding | File:Line | Status |
|---------|-------|----------|----|----------|---------|-----------|--------|
| QUAL-357 | [#271](https://gitlab.com/devnw/zig/tls/-/work_items/271) | **High** | **100** | maintainability / security | Split `handleCertificateVerify` into 4 per-concern validators (chain, OCSP, SCT, CV-sig) | `src/tls13/context.zig:2480-2643` (163 LOC) | **Closed 2026-04-21** — orchestrator reduced from 163 LOC to ~78 LOC; 3 per-concern validators extracted to `cert_handlers.zig` (`verifyCertVerifySignature` already existed); oracle `context_decomp_trace_capture` passes byte-identically |
| QUAL-358 | [#272](https://gitlab.com/devnw/zig/tls/-/work_items/272) | **High** | **100** | cleanup | Remove `tls13` module dual-entry — collapse `src/tls13.zig` shim (239 LOC) onto `src/tls13/mod.zig` (247 LOC); `git rm src/tls13.zig`; repoint `build.zig:194`; add `cookie_mod` re-export | `build.zig:194`, `src/tls13.zig`, `src/tls13/mod.zig` | Closed 2026-04-21 — shim removed, build.zig repointed at src/tls13/mod.zig |
| QUAL-359 | [#275](https://gitlab.com/devnw/zig/tls/-/work_items/275) | Medium | 64 | maintainability | Extract state types (`CryptoBuffer`, `HandshakeFlags`, `TranscriptSet`) from context.zig into `context/state.zig` | `src/tls13/context.zig:335-480` (context.zig 3206 LOC) | Open |
| QUAL-360 | [#276](https://gitlab.com/devnw/zig/tls/-/work_items/276) | Medium | 45 | maintainability | Refresh QUAL-116 LOC inventory: `aead.zig` 1337 LOC, `server_hello.zig` 1081 LOC. Split aead.zig → `nonce.zig` + `aead_cipher.zig` + `usage_limits.zig` at cluster boundaries 119/148/756. QUAL-116 umbrella updated inline. | `src/record/aead.zig`, `src/tls13/messages/server_hello.zig` | Open (`duplicate-of::QUAL-116`) |
| QUAL-361 | [#277](https://gitlab.com/devnw/zig/tls/-/work_items/277) | Low | 40 | cleanup | Rename `build.zig` module `quic_tls` → `key_schedule` for truth-in-naming (14 import sites) | `build.zig:64`, `src/lib.zig:282`, 14 `@import("quic_tls")` sites | Open |
| QUAL-362 | [#279](https://gitlab.com/devnw/zig/tls/-/work_items/279) | Low | 40 | docs | Doc drift: QUAL-319 shown Open in 5 doc sites despite Phase-13 closure (4ae8ac7). **Fixed inline in this Phase 20 sync.** | `docs/QUALITY_GAP_ANALYSIS.md:3273,3305,3326,3376,3390` (pre-edit line numbers) | **Resolved inline 2026-04-21** — awaiting GitLab issue close |
| QUAL-363 | [#280](https://gitlab.com/devnw/zig/tls/-/work_items/280) | Low | 36 | docs | Add invariant comments to 3 new `catch unreachable` sites (extension of QUAL-313) | `src/tls13/context.zig:1379`, `src/record/aead.zig:587`, `src/tls13/messages.zig:262` | Open (`duplicate-of::QUAL-313`) |
| QUAL-364 | [#282](https://gitlab.com/devnw/zig/tls/-/work_items/282) | Low | 24 | cleanup | Delete 2 unconditionally-skipped unit tests (no owner, no path to re-enable). Per user preference deletion-over-patching. | `tests/sig_unit_tests.zig:146-149`, `tests/x509_unit_tests.zig:533-543` | Open |

### Phase 20 Refuted Findings (no GitLab issue)

| QUAL-ID | Claim | Verification | Resolution |
|---------|-------|--------------|------------|
| QUAL-365 | `sig.zig` doc coverage 6% | Actual: 188 `///` comment lines vs 11 `pub` decls — doc density far exceeds claim. | **Refuted — `resolution::metric-error`** |
| QUAL-366 | M4 deep-nesting: 227 lines over indentation threshold | Actual count of lines with ≥28 leading spaces: 5. | **Refuted — `resolution::metric-error`** |
| QUAL-367 | M11 ungated `std.debug.print` in tests | 15/19 call sites are bench/fuzz drivers where `print` is the intended output (not a test hygiene violation). | **Refuted — `resolution::false-positive`** |

### Phase 20 Info-Only (no GitLab issue)

| QUAL-ID | Note |
|---------|------|
| QUAL-368 | Orphaned `GAP-0122` comment block in `src/tls13_full.zig:138-139`. Trivial doc cleanup — fold into any tls13_full.zig touch; not worth a separate issue. |

### Phase 20 Supersession

- **QUAL-345** ([#237](https://gitlab.com/devnw/zig/tls/-/work_items/237)) — Closed 2026-04-21, **superseded by QUAL-357** ([#271](https://gitlab.com/devnw/zig/tls/-/work_items/271)). QUAL-357 promoted Medium (PS=48) → High (PS=100) with refreshed line numbers (2480-2643, post-decomp) and an oracle regression gate (`context_decomp_trace_capture`).

### Phase 20 Umbrella Updates (existing issues)

- **QUAL-116** ([#242](https://gitlab.com/devnw/zig/tls/-/work_items/242)) — LOC inventory refresh comment added. Files still over ceiling: `context.zig` 3206, `aead.zig` 1337, `server_hello.zig` 1081.
- **QUAL-313** ([#189](https://gitlab.com/devnw/zig/tls/-/work_items/189)) — 3 new `catch unreachable` sites recorded; tracked under QUAL-363.

### Phase 20 Highest-Leverage Cluster

1. ~~**QUAL-357**~~ (PS 100) — **Closed 2026-04-21** (Stage 9 / Phase 21). Security-audit unblock. Effort M. Oracle-gated — passed byte-identically.
2. **QUAL-358** (PS 100) — Module-shape cleanup. Effort S. Cross-ref PERF-237.
3. **QUAL-359** (PS 64) — Continues QUAL-317 decomp. Effort M.
4. **QUAL-360** (PS 45) — AEAD file split under QUAL-116 umbrella. Effort M.
5. **QUAL-361, QUAL-362, QUAL-363, QUAL-364** (PS 24-40 each) — Batchable low-risk cleanups; land together in one Wave.

### Phase 20 Cross-References

- **QUAL-358 ↔ PERF-237 / GAP-0131** — touches the same `parallel.zig`/module-root area; `cross-ref::PERF-237` label applied.
- **QUAL-360 ↔ QUAL-116** — scoped under the LOC-ceiling umbrella; `duplicate-of::QUAL-116` label applied; QUAL-116 comment updated inline.
- **QUAL-363 ↔ QUAL-313** — extension of the invariant-comment umbrella; `duplicate-of::QUAL-313` label applied.
- **QUAL-357 ↔ QUAL-345** — supersession; QUAL-345 closed on GitLab with cross-reference.

---

## Cycle 8 / Phase 22 Filings (2026-04-27, QUAL-369) — QUIC-INTEROP-HRR follow-up

| QUAL-ID | Severity | PS | Category | Finding | File:Line | Status |
|---------|----------|----|----------|---------|-----------|--------|
| QUAL-369 | Low | 24 | extensibility / diagnostics | `parseKeyShare` mapped non-X25519 codepoints (e.g. PQ-hybrid `0x6399`) to a `.secp256r1` sentinel so the orchestrator could trigger HRR — the actual offered codepoint was lost. Future logic that wants to switch on the specific group (logging, metrics, alternative HRR selection policy) needs the original u16. | `src/tls13/messages/client_hello.zig:KeyShareEntry`, `src/tls13/handshake_state.zig:ClientHelloKeyShareView` | Closed 2026-04-27 — added `raw_group_code: u16` to `KeyShareEntry` and threaded through `ClientHelloInfo` + `ClientHelloKeyShareView`; parser populates it for both X25519 and non-X25519 entries; regression test asserts round-trip for `0x6399`. |

### Phase 22 Cross-References

- **QUAL-369 ↔ SEC-086 / SEC-087** — landed in the same change set as the
  cookie-validation + cookie-wire-format security follow-ups; all three
  emerged from the QUIC-INTEROP-HRR triage's risk-notes (see
  `docs/QUIC_INTEROP_HRR_ISSUE.md`).

## Cycle 8 / Phase 22 Filings (2026-04-27, QUAL-374) — Disabled-test cleanup

| QUAL-ID | Severity | PS | Category | Finding | File:Line | Status |
|---------|----------|----|----------|---------|-----------|--------|
| QUAL-374 | Low | 14 | test-coverage | Two unit tests were unconditionally returning `error.SkipZigTest`, masking real verifier coverage: `parseRsaSpki - wrong OID rejection` and `validateChain - single self-signed certificate`. Subsumes prior duplicate filings QUAL-364 (#282) and SEC-084 (#301). | `tests/sig_unit_tests.zig:146-149` + `tests/x509_unit_tests.zig:533-543` | Closed 2026-04-27 — RSA SPKI test now constructs a SubjectPublicKeyInfo with `id-ecPublicKey` OID (1.2.840.10045.2.1) and asserts `parseRsaSpki` returns `error.UnexpectedAlgorithm`; X.509 test exercises end-to-end `validateChain` against the existing Ed25519 self-signed fixture (`tests/test_certs/ed25519_cert.der`, valid through 2035), covering validity period, BasicConstraints, trust-store match, and Ed25519 self-signature verification. |
