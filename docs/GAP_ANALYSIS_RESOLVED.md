# Gap Analysis -- Resolved

> Items moved here from `docs/GAP_ANALYSIS.md` when their tracking gap is resolved.
> The underlying work may still be tracked by separate GitLab issues.

---

## Iterative appsec + codepros review run (2026-06-10)

Three review rounds (`/security:appsec-review` + `/codepros:audit`) iterated to
convergence; every finding below was closed with a failing-first regression
test and the full suite green under Debug and ReleaseFast. IDs are referenced
in code comments and the named tests.

| ID | Sev | Title | Resolution |
|----|-----|-------|------------|
| APPSEC-2026-06-10-01 | High | ASN.1/X.509 `off + attacker_len` length-overflow OOB/DoS | Bounds-check `len > buf.len - off` before the add at `asn1.readTLV`, `x509.parseSpki`, `x509.parseCert`. Test: `tests/security/appsec01_asn1_length_overflow.zig`. |
| NEWGAP-01 | High | RSA PKCS#1 v1.5 certificate/OCSP signatures unverifiable | `sig.rsaPkcs1VerifyGeneric` + `verifyCertSig` dispatch for sha256/384/512WithRSAEncryption (cert sigs only; CertificateVerify still rejects PKCS#1 v1.5). Tests in `tests/x509_unit_tests.zig`. |
| NEWGAP-05 | Med | Duplicate unknown extensions accepted in ServerHello/HRR helper parsers | Raw-`u16` tracking in `server_hello_parsers.zig` + `hello_retry.zig`. |
| NEWGAP-06 | Med | Client did not validate ServerHello `legacy_session_id_echo` / `legacy_version` | `handleServerHello` rejects non-empty echo (`IllegalSessionIdEcho`) and non-0x0303 version (`IllegalLegacyVersion`). Test: `tests/security/newgap06_07_serverhello_hardening.zig`. |
| NEWGAP-07 (= QUAL-387) | Med | Live `handleServerHello` duplicate-unknown-extension bypass (EnumSet) | Converted to raw-`u16` seen-list + `TooManyExtensions` cap. |
| NEWGAP-08 (incl. QUAL-392) | Med | HelloRetryRequest skipped §4.1.3/§4.1.4 field MUST-checks | `parseHelloRetryRequest`/`handleHelloRetryRequest` enforce legacy_version, empty session_id, compression, cipher-in-offered + ServerHello2 cipher-match. Test: `tests/security/newgap08_hrr_field_checks.zig`. |
| NEWGAP-02 | Med | ECDSA P-521 enum present, no verifier | Documented out-of-scope (no Zig 0.16 stdlib primitive), fail-closed; `docs/RFC_COVERAGE.md`. |
| NEWGAP-03 / NEWGAP-04 | Low | Stale algorithm/validation doc comments; stale RFC_COVERAGE rows | Corrected in `core_types.zig`, `certificate_verify.zig`, `x509.zig`, `docs/RFC_COVERAGE.md`. |
| APPSEC-04 / QUAL-386 | Low | Extension capacity cap conflated with duplicate; inconsistent error taxonomy | Added `error.TooManyExtensions`; unified to `DuplicateExtension` across parsers. |
| QUAL-381 / QUAL-382 | High/Med | Dead `performKeyUpdate*` (bypassed GAP-0135 budget); dead entropy `Reservoir` | Removed. |
| QUAL-383/384/385 | Med/Low | Non-compilable lib.zig API examples; stale version | Corrected + version test. |
| QUAL-388/389/390 | Low/Info | Dead `validateChainAndLeaf`; RSA-verify near-dup; magic `[64]u16` | Deleted; cross-ref comment; centralized as `core_types.MAX_EXTENSION_TYPES`. |
| QUAL-391 | Low | ServerHello bad compression returned `unexpected_message` not `illegal_parameter` | Typed `IllegalCompressionMethods`; stale comment removed. |
| PERF-262 | P2 | Issuer cert re-parsed in OCSP-staple validation | `validateChainReturnLeafAndIssuer` returns + reuses the issuer. See `docs/PERF_GAP_ANALYSIS.md` Cycle 10. |

Round 5 (comprehensive whole-codebase sweep) closures:

| ID | Sev | Title | Resolution |
|----|-----|-------|------------|
| R5-01 | **Critical** | CertificateVerify verified over the wrong transcript (CV folded before verification) | Exclude `certificate_verify` from the pre-dispatch transcript fold and fold it AFTER its signature is verified, like Finished (RFC 8446 §4.4.3/§4.4.4). Adds a secure end-to-end loopback regression test (no such test existed, which is why it went undetected). |
| QUAL-394 | Med | `fromHandshakeError` internal_error default observable for ~20 parse errors after the QUAL-393 inversion | Explicit RFC §6.2 mappings: malformed/length → decode_error; semantic → illegal_parameter; InvalidSignature → decrypt_error; cert/OCSP/SCT → bad_certificate; etc. |
| NEWGAP-09 | Med | EncryptedExtensions accepted forbidden extensions (§4.3.1) | Denylist → `error.ForbiddenExtension` (illegal_parameter). |
| NEWGAP-11 | Med | Server accepted a ClientHello missing quic_transport_parameters (RFC 9001 §8.2) | Reject absent extension → `MissingTransportParameters` (missing_extension). |
| NEWGAP-10 | Low | certificate_request_context not validated (§4.4.2) | Reject non-empty context → `IllegalCertificateRequestContext` (illegal_parameter). |
| NEWGAP-12 | Low | CertificateRequest accepted without signature_algorithms (§4.3.2) | Reject → `MissingSignatureAlgorithms` (missing_extension). |
| NEWGAP-13 | Low | No-change HelloRetryRequest accepted (§4.1.4 retry loop) | Reject same-group, no-cookie HRR → `HrrNoChange` (illegal_parameter). |
| NEWGAP08-N1 | Low | Client cipher-suite rejection used handshake_failure not illegal_parameter (§4.1.3/§4.1.4) | New `IllegalCipherSuiteSelected` (illegal_parameter) at 5 client sites. |
| NEWGAP-15 | Low | Malformed-KeyUpdate alert code internal_error not decode_error | Folded into the QUAL-394 decode_error group. |
| QUAL-391/393/395 | Med/Low | ServerHello compression alert; dispatcher alert-map drift; stale dispatcher comment | Fixed (see round-3/4 rows and QUAL-394). |

Round 6 (convergence sweep) closure:

| ID | Sev | Title | Resolution |
|----|-----|-------|------------|
| R6-01 | Med | mTLS server derived application/exporter secrets over the wrong transcript (included client Cert/CV) | Snapshot Transcript-Hash(CH...serverFinished) when the server folds its Finished (`TranscriptSet.app_secret_hash`) and derive §7.1/§7.5 secrets from it; the client path already derived at server-Finished arrival. Adds a pure-loopback mTLS regression asserting the peers install matching application secrets (closes the mTLS end-to-end test gap). Sibling of R5-01. |

**Deferred / tracked (open, with rationale):**

- **NEWGAP-14 (Low) — explicit handshake message-ordering state machine.** The
  dispatcher enforces role + encryption-level gating, and the security-relevant
  orderings are already enforced by data dependencies (duplicate ServerHello via
  `client_priv` consumption; CertificateVerify requires a prior Certificate;
  Finished requires the Handshake recv secret; a skipped EncryptedExtensions
  surfaces as missing QUIC transport params). The residual exposure is
  acceptance of certain reordered/duplicated *intermediate* messages without an
  explicit `unexpected_message`. An explicit per-message expected-next state
  machine is a tracked hardening item, deferred to avoid destabilizing the
  handshake for a Low, well-mitigated finding.

APPSEC-02/03 (GAP-0135 doc inconsistency; already-fixed unknown-ext dup bypass)
were reconciled in `docs/GAP_ANALYSIS.md` and `docs/SECURITY_REVIEW_NOTES.md`.

Later rounds (3-4) of the same iterative review surfaced and closed adjacent
RFC-MUST gaps:

| ID | Sev | Title | Resolution |
|----|-----|-------|------------|
| QUAL-393 | Med | Dispatcher error→alert allowlist drifted; new typed errors aborted without a fatal alert | `handleHandshakeMessage` now routes all errors through `failAlert` (the authoritative `fromHandshakeError` map) except the alert-layer pass-throughs; eliminates the drift class. |
| NEWGAP-09 | Med | EncryptedExtensions did not reject forbidden extensions (§4.3.1) | Denylist of CH/SH/HRR/CR-only extension types → `error.ForbiddenExtension` (illegal_parameter). |
| NEWGAP-10 | Low | `certificate_request_context` not validated (§4.4.2) | `handleCertificate`/`handleClientCertificate` reject a non-empty context → `error.IllegalCertificateRequestContext` (illegal_parameter). |
| NEWGAP08-N1 | Low | Client cipher-suite rejection used `handshake_failure` not `illegal_parameter` (§4.1.3/§4.1.4) | New `error.IllegalCipherSuiteSelected` (illegal_parameter) for the 5 client selection-rejection sites; server-side `NoCipherSuite`→`handshake_failure` unchanged. |

---

## Cycle 9 / Phase 4 Gap Closure (2026-04-27)

Phase 4 gap-issue-tracker sync. No code commits this cycle — moves are
status-only (the underlying code resolutions had already landed in
prior cycles; this sync moves the ledger to reflect that). Two GAP-*
items move to RESOLVED:

### GAP-0106: zig build bench broken locally [RESOLVED]

- **Issue:** [#142](https://gitlab.com/devnw/zig/tls/-/issues/142) (closed)
- **Category:** CI-CD
- **Severity:** Low
- **Resolution:** Bench harness rebuilt for Zig 0.16. `zig build bench`
  produces 13 named rows. The CI-exercise criterion is delegated to
  PERF-236 (#265).
- **Evidence:**
  - `tests/bench.zig:25-37` — `nowMonotonicNs` via `clock_gettime`
    (replacing the removed `std.time.Timer` 0.15.x API).
  - `tests/bench.zig:51-60` — `perfFence` replacing the removed `@fence`
    builtin.
  - GitLab #142 closed prior to this sync; ledger now aligned.
- **Cross-ref:** PERF-236 (#265) — "CI exercises bench" tracking.
- **Resolved date:** 2026-04-27

### GAP-0110: 10-level nesting in EE handler [RESOLVED]

- **Issue:** [#146](https://gitlab.com/devnw/zig/tls/-/issues/146) (closed)
- **Category:** Code Quality / Readability
- **Severity:** Medium
- **Resolution:** Engine deletion (commit `4ae8ac7`) subsumed the
  original 10-level demux site. The current EncryptedExtensions handler
  uses a flat per-extension dispatcher with `std.EnumSet` tracking and
  depth ≤ 3 — well under the original ≤ 3 acceptance bar.
- **Evidence:**
  - Original site: `src/tls13/engine.zig:815-848` (gone via commit
    `4ae8ac7`).
  - Current handler: `src/tls13/messages/encrypted_extensions.zig`
    (266 LOC) with flat per-ext dispatch via
    `std.EnumSet(core_types.ExtensionType).initEmpty()` at `:220`.
  - Max nesting in current EE handler: 3 levels (validated via reading
    the file).
- **Cross-ref:** SEC-092 (closed) for the dup-ext gating that landed
  alongside the demux flattening.
- **Resolved date:** 2026-04-27

---

## Cycle 8 / Phase 22 Gap Closure (2026-04-27)

Execution of the Phase 22 plan (10 gap items in implementation order). All
landed in 11 code commits + 1 doc commit on `main`. Verifier (`zig build`,
`zig build test`) PASS; full suite green; pre-commit hooks pass on every
commit (including markdownlint, zig fmt, commitizen). Per-gap evidence:

### SEC closures (2 new + 1 subsumed)

- **SEC-088** (#323) — Closed (commit a941970). ClientHello
  `legacy_compression_methods` enforcement (RFC 8446 §4.1.2): parser
  returns typed `error.IllegalCompressionMethods` for any shape other
  than `[0x00]`; ServerHello handler rejects non-zero compression byte.
  Tests at `tests/security/sec088_clienthello_compression.zig` (4 cases).
- **SEC-092** (#296, subsumes SEC-078) — Closed (commit ab1f781). EE
  parser, SH `validateSupportedVersions`, SH `parsePskExtension`, and
  the inline ServerHello extension walk in `handleServerHello` all
  reject duplicate extension types via `EnumSet(ExtensionType)` per
  RFC 8446 §4.2. Tests at `tests/security/sec092_ee_dup_ext.zig` (3) +
  three new in-file tests on `server_hello_parsers.zig`.

### GAP closures (2 new)

- **GAP-0138** (#302) — Closed (commit aa9254b). Handshake errors now
  queue fatal alerts per RFC 8446 §6.2 via a `failAlert` helper +
  `dispatchHandshake` wrapper; alert mapping handled by
  `alert.fromHandshakeError`. Tests at
  `tests/security/gap0138_handshake_alert_emit.zig` assert outbound
  CryptoBuffer payloads (level=2, expected description) and
  `Context.phase == .terminated`.
- **GAP-0139** (#303) — Closed (commit aabbb74). CertificateRequest
  level + post-handshake-auth gate: Initial reject; Handshake accept
  during initial; Application accept only with new
  `Config.post_handshake_auth = true` AND completed phase. Tests at
  `tests/security/gap0139_certreq_level_gate.zig` (4 cases).

### QUAL closures (1 new + 2 subsumed)

- **QUAL-374** (subsumes QUAL-364 #282 + SEC-084 #301) — Closed
  (commit 23df917). Two unconditionally-skipping tests replaced with
  real coverage:
  - `tests/sig_unit_tests.zig` `parseRsaSpki - wrong OID rejection`
    now constructs an SPKI with `id-ecPublicKey` (1.2.840.10045.2.1).
  - `tests/x509_unit_tests.zig` `validateChain - single self-signed
    certificate` runs against the existing Ed25519 fixture.

### PERF closures (2 new + 1 ADR)

- **PERF-249** (#315) — Closed (commit 2502b80). Outbound CryptoBuffer
  paths in `src/tls13/context.zig` (`appendOutbound`, `sendCloseNotify`,
  `sendFatalAlert`, KeyUpdate emit) now call `ensureUnusedCapacity`
  before `appendSlice`. Regression at `tests/perf/test_outbound_allocs.zig`
  asserts ≤2 outbound resizes per workload via `CountingAllocator`.
- **PERF-255** (#320) — Closed (commit 6298477). `Transcript.clone()`
  added (zero-cost: SHA-256/SHA-384 state is value-copyable). PSK-binder
  path now hashes the truncated CH prefix into the main transcript
  exactly once and clones for the binder digest. Regression in
  `src/tls13/transcript.zig` confirms `clone()+update(rest)` matches
  `update(full)` on both SHA-256 and SHA-384.
- **PERF-229** (P0, #243) — Closed (ADR-0002 Accepted 2026-04-27,
  commit 25c3690). Status flipped from Deferred to Closed; ADR-0002
  status flipped from Proposed to Accepted with guidance-first
  strategy (option c) preserved; `README.md` Performance note +
  `RUNBOOK.md` guidance already in place; `benchEcdsaP256Verify`
  continues guarding regressions.
- **PERF-237b / GAP-0131** (#278 / #267) — Closed (commit 14b73a6;
  semver MAJOR -> 0.2.0). `src/parallel.zig` (997 LOC) deleted; the
  `pub const parallel = @import("parallel");` re-export and smoke
  test stripped from `src/lib.zig`; `parallel_mod` wiring removed
  from `build.zig`; `tests/fuzz/rsa_pss_verify.zig` migrated to
  `sig.rsaPssVerifyGeneric`; `build.zig.zon` bumped to 0.2.0;
  `CHANGELOG.md` migration notes added. Cascade closures (deletion
  subsumption): #180, #190, #195, #200, #248, #263, #267, #278.

### Scope-creep deferred (1)

- **QUAL-351** (#245) — remains **Open / Deferred** with a refined
  evidence note (commit d482da4). Closure requires coordinated changes
  across `ClientPriv` field, `ClientHelloParams.client_pub`, the
  `buildKeyShare` extension handler, `handleServerHello` ECDHE compute,
  `sendClientHello2` HRR rekey, and the server-side `scalarmult` site;
  P256 ECDH is not in `std.crypto.dh`. Defer to a dedicated wave.

---

## Cycle 6 / Phase 19 Gap Closure (2026-04-20)

Execution of Cycle 5 / Phase 17 audit findings. 17 cross-ledger closures + 1 Won't-Do landed across 17 code commits + 1 doc commit on `main`. Verifier (gap-closer-verifier, APPROVED): `zig build` PASS, `zig build test` 668/668 PASS (+9 new tests), both oracles byte-identical (context-decomp + client_hello ExtHandler), `zig fmt --check` clean, pre-commit clean. No GAP-* ledger items touched this cycle; all closures are on the QUAL / SEC / PERF ledgers.

### QUAL closures (6 + 1 Won't-Do)

- **QUAL-104** ([#112](https://gitlab.com/devnw/zig/tls/-/work_items/112)) — Closed (commit e17c025). 2 residual magic-hex `0x0033` sites at `src/tls13/context.zig:2035` and `src/tls13/context/hello_retry.zig:120` replaced with `@intFromEnum(ExtensionType.key_share)`. Also closes QUAL-349 (overlapping finding).
- **QUAL-346** ([#238](https://gitlab.com/devnw/zig/tls/-/work_items/238)) — Closed (commit 8c7ced3). Atomic handshake traffic-secret pair install via `errdefer` rollback in both client and server install paths (`context.zig:2094-2096` + symmetric server).
- **QUAL-348** ([#240](https://gitlab.com/devnw/zig/tls/-/work_items/240)) — Closed (commit 21d6c77). `Context` struct + `HandshakePhase` enum docstrings landed (`context.zig:487`).
- **QUAL-349** ([#241](https://gitlab.com/devnw/zig/tls/-/work_items/241)) — Closed (commit e17c025; same commit as QUAL-104).
- **QUAL-352** ([#246](https://gitlab.com/devnw/zig/tls/-/work_items/246)) — Closed (commit 1447ab5). `ApiError` vs `HandshakeError` taxonomy documented inline.
- **QUAL-353** ([#248](https://gitlab.com/devnw/zig/tls/-/work_items/248)) — Closed (commit cf11e31). `parallel.getPool` docstring now covers process-global lifecycle, panic semantics, deinit expectations.
- **QUAL-356** ([#254](https://gitlab.com/devnw/zig/tls/-/work_items/254)) — Closed (commit 8c69643). `handleCertificate` infallibility invariant documented; fragile "No errdefer needed" comment replaced by explicit contract.
- **QUAL-347** ([#239](https://gitlab.com/devnw/zig/tls/-/work_items/239)) — **Won't Do** (commit 3a42503). `computeExpectedBinder` / `computeBinderTranscriptHash` in `psk_selection.zig` are **not** dead code — 5 production call sites at lines 410, 447, 490, 556, 596 perform PSK binder validation per RFC 8446 §4.2.11. Audit finding was incorrect.

### SEC closures (8)

- **SEC-066** ([#253](https://gitlab.com/devnw/zig/tls/-/issues/253)) — Closed (commit 159d17b). ClientHello duplicate-extension guard via `EnumSet`; regression test at `tests/security/sec066_clienthello_dup_ext.zig`.
- **SEC-067** ([#256](https://gitlab.com/devnw/zig/tls/-/issues/256)) — Closed (commit f3dced5). `AntiReplayWindow.add` TOCTOU fixed with mutex.
- **SEC-068** ([#258](https://gitlab.com/devnw/zig/tls/-/issues/258)) — Closed (commit b24bf0a). QUIC TP duplicate CID guard; regression test at `tests/security/sec068_tp_dup_cid.zig`.
- **SEC-069** ([#259](https://gitlab.com/devnw/zig/tls/-/issues/259)) — Closed (commit 98d7fca). Cert signature-algorithm OID matched by canonical full-length equality.
- **SEC-070** ([#261](https://gitlab.com/devnw/zig/tls/-/issues/261)) — Closed (commit 528df91). OCSP `parseStatus` now requires single-byte ENUMERATED payload.
- **SEC-071** ([#262](https://gitlab.com/devnw/zig/tls/-/issues/262)) — Closed (commit ed4f714). CertificateRequest duplicate `signature_algorithms` now rejected.
- **SEC-072** ([#264](https://gitlab.com/devnw/zig/tls/-/issues/264)) — Closed (commit 342775f). `SecretSlot` zeroizes prior secret on overwrite.
- **SEC-073** ([#266](https://gitlab.com/devnw/zig/tls/-/issues/266)) — Closed (commit d081000). `parsed_count` ownership state machine documented; sentinel pattern contract formalized.

### PERF closures (3)

- **PERF-230** ([#247](https://gitlab.com/devnw/zig/tls/-/issues/247)) — Closed (commit 821e929). ThreadPool capped at `min(getCpuCount(), 16)`.
- **PERF-231** ([#251](https://gitlab.com/devnw/zig/tls/-/issues/251)) — Closed (commit 5a048dc). `Transcript.snapshot` honors `locked_hash`.
- **PERF-234** ([#260](https://gitlab.com/devnw/zig/tls/-/issues/260)) — Closed (commit a77bb54). `Context.processCrypto` pre-allocates via `ensureTotalCapacity`.

### Deferred (9, separate work streams — NOT closed this cycle)

- **QUAL-344, QUAL-345, QUAL-350** — Wave 4 client-handler decomposition refactors (multi-file).
- **QUAL-354** — Wave 5 `build.zig` split.
- **QUAL-351** — X25519 / `supported_groups` correctness; feature work.
- **QUAL-355, QUAL-315** — ADRs (context.zig decomp ADR; coverage tooling choice).
- **SEC-065** (confidential) — 0-RTT `PersistentAntiReplayStore` wiring; Config API mini-epic.
- **PERF-229** (P0) — ECDSA-P256 stdlib ADR.
- **PERF-232, PERF-233, PERF-235, PERF-236** — bench harness + CI perf gate stream.

## Cycle 6 / Phase 18 Gap Sync (2026-04-20)

Doc-drift sweep — tracker/ledger alignment only (no GAP-*items moved here this
cycle; GAP-0106 remains Open as the sole non-resolved GAP-* item). The QUAL-*
closures listed below are mirrored in `docs/QUALITY_GAP_ANALYSIS.md` Cycle 6
section.

- **QUAL-069** ([#65](https://gitlab.com/devnw/zig/tls/-/work_items/65)) —
  Closed/Subsumed by QUAL-317 (context.zig decomposition, commits 0841721 /
  7f3b48e). Residual file-size concern tracked under QUAL-116.
- **QUAL-073** ([#69](https://gitlab.com/devnw/zig/tls/-/work_items/69)) —
  Closed/Subsumed by engine.zig deletion (commit 4ae8ac7).
- **QUAL-091** ([#90](https://gitlab.com/devnw/zig/tls/-/work_items/90)) —
  Closed/Subsumed by engine.zig deletion (commit 4ae8ac7).
- **QUAL-104** ([#112](https://gitlab.com/devnw/zig/tls/-/work_items/112)) —
  Reopened (not resolved). 2 residual `0x0033` (key_share) sites at
  `src/tls13/context.zig:2035` and `src/tls13/context/hello_retry.zig:120`.
- **QUAL-116** ([#242](https://gitlab.com/devnw/zig/tls/-/work_items/242)) —
  Filed (previously ledger-only). Remains Open.
- **QUAL-315** ([#170](https://gitlab.com/devnw/zig/tls/-/work_items/170)) —
  Promoted Deferred → actionable-Open with kcov tooling recommendation.

## Pre-Phase Closures

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

## Phase 9 Closures (2026-03-24)

### SEC-009: x25519KeypairAndShared returns value instead of error on failure [CLOSED]

- **Issue:** N/A
- **Category:** Security / Error Handling
- **Resolution:** Function now returns `X25519Error!X25519Result` error union. Callers are forced
  to handle the error at compile time via Zig's error handling.
- **Evidence:** `src/tls13/messages.zig:228-248`
- **Resolved date:** 2026-03-24

### SEC-045: @ptrCast on PSK binder/identity bypasses type safety [CLOSED]

- **Issue:** N/A
- **Category:** Security / Type Safety
- **Resolution:** Replaced `@ptrCast` with explicit field-by-field conversion for PSK identities,
  binders, and ALPN lists.
- **Evidence:** `src/tls13/context.zig:452-489`
- **Resolved date:** 2026-03-24

### SEC-039: Handshake trace may leak error details in production [CLOSED]

- **Issue:** N/A
- **Category:** Security / Logging
- **Resolution:** Added `@compileError` guard for `handshake_trace_enabled` in release builds,
  matching the pattern used for `sig_trace_enabled` and `secret_trace_enabled`.
- **Evidence:** `src/tls13/context.zig:121-126`
- **Resolved date:** 2026-03-24

### SEC-010: OCSP digest comparison uses std.mem.eql [WON'T DO]

- **Issue:** N/A
- **Category:** Security / Timing Side-channel
- **Resolution:** Won't Do. Non-secret public data (certificate hashes). `std.mem.eql` is
  appropriate for non-secret comparisons.
- **Resolved date:** 2026-03-24

### SEC-011: Downgrade sentinel detection uses std.mem.eql [WON'T DO]

- **Issue:** N/A
- **Category:** Security / Timing Side-channel
- **Resolution:** Won't Do. Sentinel values are public RFC 8446 constants. Timing leakage
  does not benefit an attacker.
- **Resolved date:** 2026-03-24

### SEC-012: Debug trace logs private key scalar [WON'T DO]

- **Issue:** N/A
- **Category:** Security / Information Disclosure
- **Resolution:** Won't Do. Compile-time guard already prevents this trace in release builds.
  The existing `@compileError` pattern is effective.
- **Resolved date:** 2026-03-24

### SEC-013: @intCast in DER encoding [WON'T DO]

- **Issue:** N/A
- **Category:** Security / Integer Safety
- **Resolution:** Won't Do. P-256 DER lengths always fit u8. Zig's `@intCast` is runtime
  bounds-checked, providing defense-in-depth.
- **Resolved date:** 2026-03-24

### SEC-038: Global mutable TrustStore TOCTOU window [WON'T DO]

- **Issue:** N/A
- **Category:** Security / Race Condition
- **Resolution:** Won't Do. Benign; Zig lacks dynamic library unloading. Trust store changes
  during active handshakes are administrative operations with negligible practical risk.
- **Resolved date:** 2026-03-24

### QUAL-114: 22+ allocator.dupe without errdefer [CLOSED]

- **Issue:** [#119](https://gitlab.com/devnw/zig/tls/-/work_items/119)
- **Category:** Code Quality / Error Handling
- **Resolution:** All 4 files verified: engine.zig (12 sites, QUAL-122/129), context.zig
  (11 sites, QUAL-128), handshake_state.zig (13 sites, QUAL-127), quic_transport_params.zig
  (4 sites, QUAL-126). All sites either have explicit errdefer or use store-into-self pattern.
- **Evidence:** QUAL-122, QUAL-126, QUAL-127, QUAL-128, QUAL-129 all closed
- **Resolved date:** 2026-03-24

### QUAL-118: SecretSlot struct duplicated [CLOSED]

- **Issue:** N/A
- **Category:** Code Quality / Deduplication
- **Resolution:** context.zig now imports SecretSlot from secrets.zig instead of maintaining
  a local duplicate definition.
- **Evidence:** `src/tls13/context.zig:287`
- **Resolved date:** 2026-03-24

### QUAL-125: HashDigestCache dead code removed [CLOSED]

- **Issue:** N/A
- **Category:** Code Quality / Dead Code
- **Resolution:** Removed 23-line unused HashDigestCache definition from context.zig.
  The canonical definition lives in transcript.zig.
- **Evidence:** `src/tls13/context.zig` (23 lines removed)
- **Resolved date:** 2026-03-24

### QUAL-124: readU16 helper duplicated [WON'T DO]

- **Issue:** N/A
- **Category:** Code Quality / Deduplication
- **Resolution:** Won't Do. sct.zig intentionally avoids tls13 imports (documented in code).
  Trivial one-liner not worth introducing a cross-module dependency.
- **Resolved date:** 2026-03-24

### PERF-045: hkdfLabel still allocates via FBA [CLOSED]

- **Issue:** N/A
- **Category:** Performance / Allocation
- **Resolution:** Direct stack buffer at `src/key_schedule.zig:312` replaces FBA allocation.
  No allocator parameter needed. ~30-120ns savings per handshake.
- **Evidence:** `src/key_schedule.zig:312`
- **Resolved date:** 2026-03-24

### PERF-037: Redundant leaf cert re-parse [CLOSED]

- **Issue:** [#118](https://gitlab.com/devnw/zig/tls/-/issues/118)
- **Category:** Performance / Redundant Work
- **Resolution:** Single parse shared for OCSP validation and signature verification.
  ~15-30us savings per handshake.
- **Evidence:** `src/tls13/context.zig:2749`
- **Resolved date:** 2026-03-24

### PERF-038: sendClientFinished 3-4 allocating encodeHandshake calls [CLOSED]

- **Issue:** [#120](https://gitlab.com/devnw/zig/tls/-/issues/120)
- **Category:** Performance / Allocation
- **Resolution:** `appendOutboundFramed` replaces 4 `encodeHandshake` calls. Zero-alloc
  client flight encoding achieved.
- **Evidence:** `src/tls13/context.zig:2391-2448`
- **Resolved date:** 2026-03-24

### PERF-019: Extension buffers built separately then appended [CLOSED]

- **Issue:** [#104](https://gitlab.com/devnw/zig/tls/-/issues/104)
- **Category:** Performance / Allocation
- **Resolution:** sendClientHello2 uses appendOutboundFramed for zero-alloc framing.
  Extension building was already optimized in prior rounds. Partial closure.
- **Evidence:** `src/tls13/context.zig:1618`
- **Resolved date:** 2026-03-24

### PERF-021: Nested O(n*m) cipher suite negotiation loops [WON'T DO]

- **Issue:** N/A
- **Category:** Performance / Algorithm Complexity
- **Resolution:** Won't Do. Acceptable at current sizes (TLS 1.3 defines only 5 cipher suites;
  lists are 3-5 items; ~10-50ns total). Not worth bitset complexity.
- **Resolved date:** 2026-03-24

### PERF-033: No CI performance regression detection [WON'T DO]

- **Issue:** N/A
- **Category:** Performance / CI Infrastructure
- **Resolution:** Won't Do. CI infrastructure concern, not library code.
- **Resolved date:** 2026-03-24

### PERF-044: Benchmark uses page_allocator [WON'T DO]

- **Issue:** N/A
- **Category:** Performance / Test Infrastructure
- **Resolution:** Won't Do. Test infrastructure only; does not affect library code.
- **Resolved date:** 2026-03-24

### GAP-0076: CRL distribution point checking absent [WON'T DO]

- **Issue:** N/A
- **Category:** General / Feature
- **Resolution:** Won't Do. By design; OCSP stapling is the chosen revocation checking
  alternative. Documented in x509.zig.
- **Resolved date:** 2026-03-24

### GAP-0077: Minimal ClientHello/ServerHello encoders [WON'T DO]

- **Issue:** N/A
- **Category:** General / Legacy Code
- **Resolution:** Won't Do. Will resolve via Engine deprecation (PERF-026). These minimal
  encoders exist only in the legacy Engine path.
- **Resolved date:** 2026-03-24

### GAP-0092: GitLab issue #12 false claims [WON'T DO]

- **Issue:** [#133](https://gitlab.com/devnw/zig/tls/-/issues/133)
- **Category:** General / Issue Tracker Maintenance
- **Resolution:** Won't Do. Issue tracker maintenance tracked by Issue #133.
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

---

## Phase 10 Closures (2026-03-25)

### GAP-0095: PSK conformance test compile error -- duplicate const Secret [CLOSED]

- **Issue:** N/A
- **Category:** Bug / Test
- **Resolution:** Removed duplicate `const Secret = ks.Secret;` at line 87. Conformance tests went
  from 435 to 449 passing (14 PSK tests unblocked).
- **Evidence:** `tests/conformance/boringssl/psk_handshake.zig:87` (duplicate removed)
- **Resolved date:** 2026-03-25

### GAP-0096: README test count stale [CLOSED]

- **Issue:** N/A
- **Category:** Docs
- **Resolution:** Updated README test counts from 853 to 1000 (551 unit + 449 conformance).
  Updated Zig version from 0.14.0+ to 0.15.1.
- **Evidence:** `README.md:81,85-88,97`
- **Resolved date:** 2026-03-25

### GAP-0093: 3 skipped tests indicate incomplete coverage [WON'T DO]

- **Issue:** [#134](https://gitlab.com/devnw/zig/tls/-/issues/134)
- **Category:** Test
- **Resolution:** Won't Do. 2 of 3 skipped tests require Zig stdlib features not yet available
  (Ed25519 cert sig verification, ChaCha20-Poly1305 build-dependent). RSA SPKI test data is a
  fixture issue, not a code defect. No security or functional impact.
- **Resolved date:** 2026-03-25

### GAP-0099: 19 GitLab issues remain open despite documented resolution [WON'T DO]

- **Issue:** N/A
- **Category:** Docs / Tracking
- **Resolution:** Won't Do. Issue tracker maintenance is a separate administrative task from
  code quality and security gap closure. Code changes are merged and verified.
- **Resolved date:** 2026-03-25

### SEC-050: Private key not zeroed on error in startClientHandshake [CLOSED]

- **Issue:** N/A
- **Category:** Security / Key Material Zeroization
- **Resolution:** Added `defer secureZero` for X25519 private key in `startClientHandshake` and
  `sendClientHello2`. Private keys now zeroed on all exit paths (success and error).
- **Evidence:** `src/tls13/context.zig` -- defer secureZero in startClientHandshake and sendClientHello2
- **Resolved date:** 2026-03-25

### SEC-055: client_priv retained after DH computation [CLOSED]

- **Issue:** N/A
- **Category:** Security / Key Material Zeroization
- **Resolution:** Zeroed `client_priv` after DH computation in `handleServerHello`. Private key
  no longer retained in Context until `deinit()`.
- **Evidence:** `src/tls13/context.zig` -- secureZero in handleServerHello after DH
- **Resolved date:** 2026-03-25

### SEC-049: Missing @compileError guards on 4 trace flags [CLOSED]

- **Issue:** N/A
- **Category:** Security / Information Disclosure Defense-in-Depth
- **Resolution:** Added `@compileError` guards on all 4 trace flags in `engine.zig`, `transcript.zig`,
  `messages.zig`, and `ocsp.zig`, matching the existing `context.zig` pattern.
- **Evidence:** `src/tls13/engine.zig`, `src/tls13/transcript.zig`, `src/tls13/messages.zig`, `src/ocsp.zig`
- **Resolved date:** 2026-03-25

### SEC-054: Memory leak in parseClientHello on error paths [CLOSED]

- **Issue:** N/A
- **Category:** Security / Memory Safety
- **Resolution:** Added errdefer for all allocated slices in `parseClientHello`. Memory properly
  cleaned on all error paths, preventing DoS via repeated malformed ClientHellos.
- **Evidence:** `src/tls13/messages/client_hello.zig` -- errdefer at all allocator.dupe sites
- **Resolved date:** 2026-03-25

### SEC-052: ASN.1 readInteger silent truncation >8 bytes [CLOSED]

- **Issue:** N/A
- **Category:** Security / Integer Safety
- **Resolution:** Added `IntegerOverflow` guard in `readInteger` for values >8 bytes. Rejects
  oversized integers instead of silent truncation.
- **Evidence:** `src/asn1.zig` -- IntegerOverflow error return for len > 8
- **Resolved date:** 2026-03-25

### QUAL-206: Redundant condition in engine.zig [CLOSED]

- **Issue:** N/A
- **Category:** Code Quality / Cleanup
- **Resolution:** Removed redundant `if (elen >= 2)` inside `if (elen >= 3)` block in engine.zig.
- **Evidence:** `src/tls13/engine.zig` -- inner check removed
- **Resolved date:** 2026-03-25

### QUAL-204: Magic hex constants in engine.zig [CLOSED]

- **Issue:** N/A
- **Category:** Code Quality / Readability
- **Resolution:** Replaced all magic hex extension type constants (0x0010, 0x0039, 0x0033, etc.)
  with `@intFromEnum(ExtensionType.*)` in engine.zig.
- **Evidence:** `src/tls13/engine.zig` -- all hex constants replaced with enum references
- **Resolved date:** 2026-03-25

### QUAL-210: TicketEntryView exported but unused [CLOSED]

- **Issue:** N/A
- **Category:** Code Quality / Cleanup
- **Resolution:** Removed unused `TicketEntryView` exports from `mod.zig` and `tls13.zig`.
- **Evidence:** `src/tls13/mod.zig`, `src/tls13.zig` -- exports removed
- **Resolved date:** 2026-03-25

### QUAL-128: context.zig 11 dupe sites without errdefer [CLOSED]

- **Issue:** N/A
- **Category:** Code Quality / Error Handling
- **Resolution:** Added errdefer at 8 `allocator.dupe` sites in context.zig that lacked coverage.
- **Evidence:** `src/tls13/context.zig` -- errdefer added at dupe sites
- **Resolved date:** 2026-03-25

### QUAL-207: 17 .? unwraps in context.zig [CLOSED]

- **Issue:** N/A
- **Category:** Code Quality / Safety
- **Resolution:** Added 10 SAFETY comments for `.?` unwraps documenting invariants. Converted
  `negotiated_cipher_suite.?` to `orelse return InternalError` for the one case that could fail.
- **Evidence:** `src/tls13/context.zig` -- SAFETY comments + orelse conversion
- **Resolved date:** 2026-03-25

### QUAL-201: parseCert 396 lines with inline extension sub-parsers [CLOSED]

- **Issue:** N/A
- **Category:** Code Quality / Maintainability
- **Resolution:** Extracted 7 extension sub-parsers from `parseCert`, reducing it from 396 to 194 lines.
  New helper functions: parseSanExtension, parseBasicConstraints, parseKeyUsage, parseExtKeyUsage,
  parseNameConstraints, parsePolicyConstraints, parseAuthorityKeyIdentifier.
- **Evidence:** `src/x509.zig` -- parseCert 396->194 lines; 7 new helper functions
- **Resolved date:** 2026-03-25

### QUAL-202: Deep nesting in x509.zig addressed by parseCert extraction [CLOSED]

- **Issue:** N/A
- **Category:** Code Quality / Readability
- **Resolution:** Nesting depth in x509.zig reduced as a direct consequence of QUAL-201 extraction.
  The 9-level nesting in extension parsing is now distributed across extracted helper functions.
- **Evidence:** `src/x509.zig` -- nesting reduced via QUAL-201 extraction
- **Resolved date:** 2026-03-25

### QUAL-203: OCSP error mapping loses diagnostic info [CLOSED]

- **Issue:** N/A
- **Category:** Code Quality / API Contract
- **Resolution:** Added trace logging to 8 critical OCSP parse points. Fixed `.?` unwraps to
  `orelse` patterns for additional safety. Diagnostic info now available via OCSP trace flag.
- **Evidence:** `src/ocsp.zig` -- trace logging at 8 parse points
- **Resolved date:** 2026-03-25

### QUAL-093: CI pipeline lacks build caching [WON'T DO]

- **Issue:** [#94](https://gitlab.com/devnw/zig/tls/-/work_items/94)
- **Category:** CI-CD / Infrastructure
- **Resolution:** Won't Do. CI pipeline caching is infrastructure configuration, not library code.
  Outside scope of security and quality gap closure.
- **Resolved date:** 2026-03-25

### QUAL-130: Stale line counts in QUAL-069 [WON'T DO]

- **Issue:** N/A
- **Category:** Code Quality / Cleanup
- **Resolution:** Won't Do. Cosmetic doc update of a deferred item. The actual line count is
  documented accurately in the QUAL-069 Line Count Update section.
- **Resolved date:** 2026-03-25

### QUAL-123: build.zig over 800 lines [WON'T DO]

- **Issue:** N/A
- **Category:** Code Quality / Maintainability
- **Resolution:** Won't Do. Large build.zig files are idiomatic for Zig projects with many test
  targets. The file is well-structured with clear section organization.
- **Resolved date:** 2026-03-25

### PERF-202: sendKeyUpdate allocates 5-byte buffer [CLOSED]

- **Issue:** N/A
- **Category:** Performance / Allocation
- **Resolution:** sendKeyUpdate uses inline 5-byte stack buffer instead of heap allocation
  via encodeHandshake.
- **Evidence:** `src/tls13/context.zig` -- inline stack buffer for KeyUpdate
- **Resolved date:** 2026-03-25

### PERF-203: HRR client path uses allocating encodeHandshake [CLOSED]

- **Issue:** N/A
- **Category:** Performance / Allocation
- **Resolution:** HRR client path uses stack header for transcript update instead of allocating
  via encodeHandshake.
- **Evidence:** `src/tls13/context.zig:1532` -- stack buffer replaces heap alloc
- **Resolved date:** 2026-03-25

### PERF-204: HRR server path uses allocating encodeHandshake [CLOSED]

- **Issue:** N/A
- **Category:** Performance / Allocation
- **Resolution:** HRR server path uses stack header + appendOutboundFramed instead of allocating
  via encodeHandshake.
- **Evidence:** `src/tls13/context.zig:1649` -- stack buffer + appendOutboundFramed
- **Resolved date:** 2026-03-25

### PERF-042: Per-cert allocator.dupe in handleCertificate loop [CLOSED]

- **Issue:** N/A
- **Category:** Performance / Allocation
- **Resolution:** handleCertificate uses single contiguous buffer for cert chain instead of
  per-cert allocator.dupe calls. Batch allocation replaces N individual allocations.
- **Evidence:** `src/tls13/context.zig` -- single contiguous cert chain buffer
- **Resolved date:** 2026-03-25

### PERF-016: Global trust store RwLock contention [CLOSED]

- **Issue:** N/A
- **Category:** Performance / Contention
- **Resolution:** Cached trust store in Context avoids RwLock on every handshake. Trust store
  is read once during Context initialization and cached locally.
- **Evidence:** `src/tls13/context.zig` -- cached trust store field
- **Resolved date:** 2026-03-25

### PERF-041: Zero-capacity ArrayList in validateChain name constraints [CLOSED]

- **Issue:** N/A
- **Category:** Performance / Allocation
- **Resolution:** ArrayList pre-sized to 4 in validateChain name constraints, avoiding
  immediate reallocation on first append.
- **Evidence:** `src/x509.zig` -- initCapacity(allocator, 4) for name constraint lists
- **Resolved date:** 2026-03-25

### PERF-043: Context struct hot/cold field mixing [CLOSED]

- **Issue:** N/A
- **Category:** Performance / Cache Locality
- **Resolution:** Context struct fields reordered hot->warm->cold for improved cache locality.
  Hot fields (phase, hash_kind, transcripts) grouped at struct top.
- **Evidence:** `src/tls13/context.zig` -- field reordering
- **Resolved date:** 2026-03-25

### PERF-206: Benchmark suite lacks allocation tracking [WON'T DO]

- **Issue:** N/A
- **Category:** Performance / Test Infrastructure
- **Resolution:** Won't Do. Test infrastructure only; does not affect library code or runtime
  performance. Allocation tracking is a benchmark enhancement, not a code defect.
- **Resolved date:** 2026-03-25

---

## Phase 12 Closures (2026-04-19)

### GAP-0100: Remote DoS via @enumFromInt on unfiltered signature_algorithms entry [RESOLVED]

- **Issue:** [#136](https://gitlab.com/devnw/zig/tls/-/issues/136) (closed)
- **Category:** Security (REGRESSION)
- **Resolution:** Unchecked `@enumFromInt(alg)` replaced with a bounded exhaustive switch over valid `SignatureScheme` tags at `src/tls13/messages/client_hello.zig:406`. The ~2063-value attack surface over `0x0401..=0x080b` is eliminated; unknown values are silently skipped.
- **Evidence:**
  - `src/tls13/messages/client_hello.zig:406` -- bounded switch replaces unchecked `@enumFromInt`
  - Phase 3 gap-detector confirmed the fix
  - Fuzz/exhaustive u16 sweep of the sig_algs extension no longer panics
- **Resolved date:** 2026-04-19

### GAP-0101: 32-bit DoS via @intCast(varint length) before bounds check [RESOLVED]

- **Issue:** [#137](https://gitlab.com/devnw/zig/tls/-/issues/137) (closed)
- **Category:** Security
- **Resolution:** `@intCast(length)` hoisted to after a u64 bounds check against `data.len - offset` at `src/quic_transport_params.zig:581-584`. On 32-bit targets (`usize=u32`) a varint length of 2^32 or larger now returns `error.Truncated` cleanly instead of panicking in ReleaseSafe or hitting UB in ReleaseFast.
- **Evidence:**
  - `src/quic_transport_params.zig:581-584` -- u64 bounds check precedes the cast
  - Phase 3 gap-detector confirmed the fix
  - Acceptance test `length = 0x1_0000_0000` -> `error.Truncated`, no panic
- **Resolved date:** 2026-04-19

---

## Phase 13 Closures (2026-04-19) — Gap-Close Run

**34 commits landed on `main` closing 51 items across GAP/QUAL/PERF/SEC ledgers.** Verifier (Step 3 gap-closer-verifier 2026-04-19): `zig build` PASS, `zig build test` 586/588, `zig fmt --check` clean. LOC delta: **−1403 net**; keystone change was commit `4ae8ac7` deleting `src/tls13/engine.zig` (-2283 LOC).

Full detail retained in `docs/GAP_ANALYSIS.md` under each gap's Resolution field. This section archives the tracking-level closure record.

### GAP closures (16) — Phase 13

| Gap-ID | Closing commit | Summary |
|--------|----------------|---------|
| GAP-0107 | 674fbee | BidirSecrets/SecretSchedule canonicalized in `src/tls13/secrets.zig`; duplicates removed from `context.zig`. |
| GAP-0108 | 4ae8ac7 | `parseMinimalHelloPub` dup removed via full `src/tls13/engine.zig` deletion. |
| GAP-0110 | 4ae8ac7 | 10-level nesting in engine EE handler — file deleted (partial closure; any analogous nesting in context.zig tracked separately). |
| GAP-0113 | f0b02fb | Stale thread_pool cache dir removed from working tree (`du -sh zig-pkg/`: 12.5M → 8.4M). |
| GAP-0114 | 8b24c54 | Deleted stale `run_tests.sh` + `README_TESTS`; `build.zig` is sole driver. |
| GAP-0115 | 9a8c76d | pre-commit zig-fmt widened to `tests/`. |
| GAP-0116 | 93db923 | Two drifted conformance test files re-formatted; `zig fmt --check tests/` clean. |
| GAP-0118 | e9e8165 | 9 `std.debug.print` sites in `src/tls13/sig.zig` collapsed to comptime-gated helper. |
| GAP-0119 | 2a346ad, 394efe2 | Added `tests/rfc5280/section_4_2_*.zig`, `section_5_*.zig`, `section_6_*.zig`. |
| GAP-0120 | 7d505cd, 0f06326, 34cea5b, a3bb37b | Added `tests/rfc8446/section_{4_3,4_6,6,8}_*.zig`. |
| GAP-0121 | de226a2, 743de6f | Added `tests/rfc9001/section_{5_4,5_5,6,9}_*.zig`. |
| GAP-0122 | 9037778 | Dead public exports removed from `src/lib.zig`. |
| GAP-0123 | f8b5ecd | `zig build test --listen=-` wiring fixed; clean exit on green tree. |
| GAP-0124 | ed345b1 | `docs/API.md` now documents `request_client_cert` and `client_auth_ca_certs` with mTLS example. |
| GAP-0125 | 4bfccfa | `docs/ARCHITECTURE.md` module map refreshed; 0-RTT moved from Future to Shipped. |
| GAP-0126 | 8bf4ce5 | Scaffolded `docs/adr/` with template + 3 ADRs; added `docs/RUNBOOK.md`, `docs/RFC_COVERAGE.md`. |

### QUAL closures (21) — Phase 13

See `docs/QUALITY_GAP_ANALYSIS.md` → "Phase 13 Gap Closure Run" for the full closure table. Closed IDs: QUAL-302, 304, 307, 308, 309, 311, 314, 319, 320, 321, 322, 325, 326, 327, 330, 332, 334, 335, 336, 337, 343. Keystone: engine.zig deletion (commit 4ae8ac7) subsumed QUAL-302/304/319 directly and provided partial closure for QUAL-314/325/343.

### PERF closures (12) + ledger-only (2) — Phase 13

See `docs/PERF_GAP_ANALYSIS.md` → "Phase 13 Gap Closure Run" for the full closure table. Closed IDs: PERF-023, 040, 208, 213, 216, 217, 219, 220, 221, 222, 225 (partial), 226. Plus PERF-211 marked Won't-Do (NRVO false positive) and PERF-212 confirmed Already-Resolved (bench blocker fix landed 2026-04-18). Keystone: engine.zig deletion subsumed 6 PERF items (023/040/217/219/220/226).

### SEC closures (4) — Phase 13

See `docs/SECURITY_GAP_ANALYSIS.md` → "Phase 13 Gap Closure Run" for full detail.

| SEC-ID | Risk | Issue | Closing commit | Summary |
|--------|------|-------|----------------|---------|
| SEC-061 | Low (6) | #184 | b864812 | 8 CI catalog imports pinned to immutable commit SHAs. |
| SEC-062 | Low (8) | #219 | 8e894fe | QUIC TP fuzz corpus expanded from 1 seed to ~30 (RFC 9000 §18.2 / 9001 §8.2 coverage). |
| SEC-063 | Low (4) | #222 | 106a287 | `.semgrepignore` entry for `specs/**/*.txt` to silence RFC canonical PEM FPs. |
| SEC-064 | Low (12) | #226 | 4ae8ac7 | `src/tls13/engine.zig` deleted (-2283 LOC net); divergence vector eliminated. |

**Security posture post-Phase 13: 0 Critical / 0 High / 0 Medium / 0 Low open.**

### Phase 13 Deferred (tracked for next cycle)

- **QUAL-317** — context.zig decomposition (Phase 13 epic; too large for this run)
- **QUAL-315** — coverage instrumentation (tooling choice kcov vs llvm-cov pending)
- **QUAL-338, QUAL-339, QUAL-340, QUAL-341, QUAL-342** — long-function splits / dispatch tables (opportunistic Cluster O, scheduled next cycle)
- **PERF-209** — ThreadPool uses page_allocator (suspected; needs upstream reproducer)

### Phase 13 Housekeeping Follow-ups

Stale doc references to the deleted `src/tls13/engine.zig` remain at:

- `src/tls13.zig:26`
- `src/tls13/types.zig:18`
- `src/tls13/messages/client_hello.zig:556`

These are comment / doc-string references, not active imports. Flagged for next-cycle cleanup.

Pre-existing pre-commit hook failures on files not touched by this run are flagged as a next-cycle GAP.

---

## Phase 4 Closures (2026-04-18)

### GAP-0097: parallel module built but never imported at runtime [RESOLVED]

- **Issue:** N/A (no matching GitLab issue was ever filed for this gap)
- **Category:** Code Quality
- **Resolution:** The `parallel` module is now publicly exported from the root library API.
  Commit `b31f035` ("feat(tls): export parallel module from public root API") adds
  `pub const parallel = @import("parallel");` at `src/lib.zig:414` with documentation
  for `parallelCertificateValidate`, `parallelSignatureVerify`, `parallelAeadSeal`,
  `parallelKeyDerive`, and pool lifecycle helpers. A smoke test proves the re-export
  works end-to-end. Latent Zig 0.16 compat issues masked by the module's prior
  unreachability were fixed in the same commit.
- **Evidence:**
  - `src/lib.zig:414` -- `pub const parallel = @import("parallel");`
  - `git show b31f035 --stat` -- `build.zig | 1 +`, `src/lib.zig | 16 ++++++++++++++++`, `src/parallel.zig | 4 +---`
- **Resolved date:** 2026-04-18

---

## Phase 14 Closures (2026-04-20) -- Cycle 2

### GAP-0098: 7 unused public symbols [RESOLVED]

- **Issue:** N/A (ledger internal)
- **Category:** Code Quality
- **Resolution:** Subsumed by GAP-0122 (Phase 13 commit 9037778). Ledger alignment commit 46a3419 (Cycle 2) recorded the closure. 5 of the 6 originally listed symbols deleted; `parallel.deinitPool` now has a live caller at `src/lib.zig:556` (Phase 4); 3 varint re-exports in `quic_transport_params.zig` retained as intentional QUIC public API surface.
- **Evidence:** GitLab issue search returns no remaining open issue for GAP-0098.
- **Resolved date:** 2026-04-19

### GAP-0102: validateChain parses+discards leaf, caller re-parses [RESOLVED]

- **Issue:** [#138](https://gitlab.com/devnw/zig/tls/-/issues/138)
- **Category:** Performance
- **Resolution:** Delivered via PERF-207. Commits 090356c + 7c0c058 added `x509.validateChainReturnParsed` via a shared `runChainChecks` helper. Both client-side callers in `src/tls13/context.zig` (server cert verify, mTLS client cert verify) reuse the already-parsed leaf. Regression test: `tests/perf/test_validate_chain_parsed.zig`.
- **Evidence:** No re-parse of `chain[0]` after validation at `context.zig:2823` or `:3036`.
- **Resolved date:** 2026-04-19

### GAP-0103: sendClientHello2 body/msg dual-alloc+memcpy [RESOLVED]

- **Issue:** [#139](https://gitlab.com/devnw/zig/tls/-/issues/139)
- **Category:** Performance
- **Resolution:** Delivered via PERF-208. Commit 08045dd reserved 4 bytes of header space inside `buildClientHello`; the caller now writes the handshake-type/length header directly. Second alloc + body-to-outer memcpy eliminated.
- **Evidence:** `sendClientHello2` issues one allocation; no body-to-outer memcpy.
- **Resolved date:** 2026-04-19

### GAP-0105: xorNonce/deriveNonce micro-optimization candidates [RESOLVED]

- **Issue:** [#141](https://gitlab.com/devnw/zig/tls/-/issues/141)
- **Category:** Performance
- **Resolution:** Delivered via PERF-035 (LLVM auto-vectorization confirmed for `deriveNonce` in ReleaseFast) + PERF-211 Won't-Do (commit bca9b0a, NRVO elides the 12-byte return copy). PERF-210 (xorNonce per-byte loop) remains informational.
- **Evidence:** AEAD hot path inspected; deriveNonce + NRVO confirmed optimal.
- **Resolved date:** 2026-04-19

### GAP-0109: RSA-PSS verify triple copy-paste [RESOLVED -- fully canonicalized]

- **Issue:** [#145](https://gitlab.com/devnw/zig/tls/-/issues/145)
- **Category:** Code Quality / Maintainability (crypto)
- **Resolution:**
  - Phase 13 `src/tls13/engine.zig` deletion (commit 4ae8ac7) dropped "triple" to "double".
  - Cycle 2 commit 92f8f96 merged the `parallel.zig` SHA-256/SHA-384 arms into a single comptime-generic `verifyRsaPssWithHash`.
  - Cycle 4 (2026-04-20) completed cross-file canonicalization: commit 531c149 extracted `sig.rsaPssVerifyGeneric(comptime Hash, ...)` as the single shared core; commit 1eb1777 routed `parallel.verifyRsaPssWithHash` through it (preserving the `SignatureVerifyResult{valid, error_code}` contract); commit ff01e30 added `tests/fuzz/rsa_pss_verify.zig` + `tests/fuzz/corpus/rsa_pss/` as a differential oracle; commit dccc339 wired the harness into CI as a regression gate.
- **Evidence:** `grep -c 'PSSSignature.verify' src/**/*.zig` = 1 (single call site); full `zig build test` green (591/593); fuzz seed corpus reports zero `DifferentialDivergence` pre- and post-refactor; LOC delta parallel.zig -11 / sig.zig +30 (net +19).
- **Resolved date:** 2026-04-20 (Cycle 4 full closure on top of 2026-04-19 scoped closure)

### GAP-0127: Feature Request MR template MD031 fenced-code blanks [RESOLVED]

- **Issue:** N/A (ledger-only; no GitLab issue filed)
- **Category:** Docs
- **Resolution:** Commit 4bef6d4 inserted blank lines around fenced code blocks in `.gitlab/issue_templates/Feature Request.md` to satisfy markdownlint MD031.
- **Evidence:** `pre-commit run markdownlint --all-files` clean.
- **Resolved date:** 2026-04-19

### GAP-0128: Default MR template MD032 list blanks [RESOLVED]

- **Issue:** N/A (ledger-only)
- **Category:** Docs
- **Resolution:** Commit 118c3a1 added blank lines around bulleted lists in `.gitlab/merge_request_templates/Default.md` to satisfy MD032.
- **Evidence:** `pre-commit run markdownlint --all-files` clean.
- **Resolved date:** 2026-04-19

### GAP-0129: SUPPORT.md bare email autolink MD034 [RESOLVED]

- **Issue:** N/A (ledger-only)
- **Category:** Docs
- **Resolution:** Commit 54ebf35 converted bare email in `SUPPORT.md` to `<mailto:>` autolink.
- **Evidence:** `pre-commit run markdownlint --all-files` clean.
- **Resolved date:** 2026-04-19

### GAP-0130: ARCHITECTURE.md stale engine.zig prose reference [RESOLVED]

- **Issue:** N/A (ledger-only)
- **Category:** Docs
- **Resolution:** Commit 301729d removed residual `engine.zig` prose reference from `docs/ARCHITECTURE.md` after the Phase 13 engine deletion; module map refreshed.
- **Evidence:** `grep engine.zig docs/ARCHITECTURE.md` returns no stale references.
- **Resolved date:** 2026-04-19

### PERF-023: encodeHandshake always allocates new buffer (P2) [RESOLVED]

- **Issue:** [#105](https://gitlab.com/devnw/zig/tls/-/issues/105)
- **Category:** Performance
- **Resolution:** Subsumed by engine.zig deletion (Phase 13 commit 4ae8ac7). Cycle 2 header-marker alignment commit 5443971 aligned the detail entry header. All 8 production callers removed with the file; no alternative call sites exist.
- **Evidence:** `grep encodeHandshake src/tls13/` shows zero production callers remaining.
- **Resolved date:** 2026-04-19

## Phase 15 Closures (2026-04-19) -- Cycle 3

### QUAL-342: key_schedule.zig public-fn docstring coverage [RESOLVED]

- **Issue:** [#214](https://gitlab.com/devnw/zig/tls/-/work_items/214)
- **Category:** Docs / readability
- **Resolution:** Added `///` doc blocks to the 10 public functions that were missing them (`digestLength`, `zeroSecret`, `extractHash`, `expandLabelHash`, `deriveSecretHash`, `hmacHash`, `updateTrafficSecretHash`, `deriveKeyIvHpHash`, `hashBytes`, `deriveFinishedVerifyDataHash`). `hmacSha256` was already documented. Each new block cites the governing RFC section (RFC 8446 §4.4.1, §4.4.4, §7.1, §7.2; RFC 9001 §5.1 / §6; RFC 9369 §3.3.1; RFC 5869 §2.2; RFC 2104) and documents input-length invariants and the returned `Secret` / array shape.
- **Evidence:** All 11 public fns now precede with `///` block. `zig fmt --check src/key_schedule.zig` clean. `zig build test` 521 pass / 2 skip — unchanged from pre-edit baseline (doc-only change).
- **Resolved date:** 2026-04-19

### QUAL-341: Scheme-dispatch table for verify/signCertificateVerify [RESOLVED]

- **Issue:** [#211](https://gitlab.com/devnw/zig/tls/-/work_items/211)
- **Category:** Readability / maintainability
- **Resolution:** Replaced the 4-arm `switch` bodies in `verifyCertificateVerify` and `signCertificateVerify` (src/sig.zig) with table-driven dispatch. New `SchemeEntry { alg, verify, sign: ?SignFn }` table (`SCHEMES`) holds one entry per TLS 1.3 signature scheme; both public functions are now 7-LOC and 8-LOC orchestrators that call `schemeEntry(alg)` and forward to the matching helper. Per-scheme bodies (`verifyEd25519`, `verifyRsaPssSha256`, `verifyEcdsaP256Sha256`, `verifyEcdsaP384Sha384`, `signEd25519`, `signEcdsaP256Sha256`) are lifted verbatim from the pre-refactor switch arms, preserving bit-exact RFC 8446 §4.2.3 behaviour (including the `error.Unsupported` return for RSA-PSS/ECDSA-P384 sign paths). `schemeEntry` uses an explicit linear scan (N=4) rather than `@intFromEnum` indexing to avoid coupling to enum declaration order.
- **Evidence:** Orchestrator LOC: `verifyCertificateVerify` = 7 LOC, `signCertificateVerify` = 8 LOC (well under the 40 LOC bound). `zig fmt src/sig.zig` clean. `zig build test` 521 pass / 2 skip, identical to pre-refactor baseline. `tests/sig_unit_tests.zig` (76 pass) and `tests/rfc8446/mod.zig` RFC 8446 vector suite (106 pass) both green.
- **Resolved date:** 2026-04-19

### QUAL-338: parseCert + runChainChecks split into stepwise helpers [RESOLVED]

- **Issue:** [#208](https://gitlab.com/devnw/zig/tls/-/work_items/208)
- **Category:** Maintainability
- **Resolution:** Split `parseCert` (was 193 LOC) and `runChainChecks` (was 152 LOC) in `src/x509.zig` into step-wise helpers at natural RFC 5280 boundaries.
  - **parseCert**: orchestrator now 70 LOC. Private helpers at natural DER boundaries: `parseTbsHeader` (version + serial, 16 LOC), `parseIssuerValidity` (issuer + validity, 12 LOC), `parseSubjectAndCN` (subject + CN extraction, 40 LOC), `parseSpki` (SubjectPublicKeyInfo with full DER header, 12 LOC), `parseExtensionsBlock` (dispatch to existing `parseExt*` helpers, 57 LOC). Four internal record types (`TbsHeaderInfo`, `IssuerValidityInfo`, `SubjectInfo`, `ParsedExtensions`) carry the intermediate shape through the pipeline. The parseExtensionsBlock helper consolidates the errdefer ownership contract for SAN / nameConstraints / policyMappings allocations.
  - **runChainChecks**: orchestrator now 26 LOC. Private validators: `validateLeafValidity` (3 LOC), `validateEku` (6 LOC), `validateBasicConstraintsAndKu` (44 LOC), `validateNameConstraints` (58 LOC), `validateSignatureChain` (39 LOC). Per-intermediate validity check remains interleaved inside `validateBasicConstraintsAndKu` rather than being hoisted, preserving the pre-refactor error priority (e.g. BasicConstraints/KU failures on cert *i* still surface before a later cert's validity failure).
- **Evidence:** No function in `src/x509.zig` exceeds 100 LOC after the split (verified via awk pass over the file). `zig fmt src/x509.zig` clean. `zig build test` shows **586 pass / 2 skip** — identical to the Cycle 2 baseline. `tests/rfc5280/**`, `tests/x509_unit_tests.zig`, and `tests/x509_openssl_conformance.zig` all green.
- **Resolved date:** 2026-04-19

### QUAL-340: validateStapledResponse split into 4 validators [RESOLVED]

- **Issue:** [#210](https://gitlab.com/devnw/zig/tls/-/work_items/210)
- **Category:** Readability
- **Resolution:** Split the 199-LOC `validateStapledResponse` (src/ocsp.zig) into a 20-LOC orchestrator plus four validators: `decodeResponseBytes` (responseStatus + responseBytes + BasicOCSPResponse decode, 71 LOC), `parseResponseData` (tbsResponseData up through producedAt + responses SEQUENCE, 29 LOC), `matchSingleResponse` (SingleResponse iteration + CertID match, 66 LOC), and `verifySignerChain` (delegated responder cert validation + signature verification, 22 LOC). A secondary helper `parseSingleResponseTimes` (32 LOC) keeps the SingleResponse status + thisUpdate + nextUpdate tail out of `matchSingleResponse`. Two helper record types (`DecodedResponse`, `ParsedResponseData`) carry the intermediate shape through the pipeline. The CWE-328 SHA-1 skip (two `continue` sites) is preserved inside `matchSingleResponse` with prominent in-code comments noting its security-critical status.
- **Evidence:** Orchestrator `validateStapledResponse` = 20 LOC (< 60 target). All helpers under the 80-LOC bound (71/29/66/32/22 LOC). `zig fmt src/ocsp.zig` clean. `zig build test` 521 pass / 2 skip (unchanged from pre-refactor baseline). `tests/ocsp_unit_tests.zig` green, `tests/ocsp_openssl_conformance.zig` green.
- **Resolved date:** 2026-04-19

### PERF-209: ThreadPool uses page_allocator [RESOLVED]

- **Issue:** [#155](https://gitlab.com/devnw/zig/tls/-/issues/155)
- **Category:** Performance (allocator hygiene)
- **Resolution:** Commit 24a275c swapped `src/parallel.zig:78` from `std.heap.page_allocator` to `std.heap.smp_allocator`. Cycle 3 added a reproducer (`tests/perf/bench_threadpool_alloc.zig`, commit 88e4968) that quantified the prior allocator tax: under a 10,000-job parallel-verify-like workload the `page_allocator` configuration produced +136..+154 minor page faults per run while `smp_allocator` and `c_allocator` both produced zero. Post-swap runs confirm `smp_allocator` eliminates those faults. `smp_allocator` was chosen over `c_allocator` to preserve the pure-Zig/no-libc property of the library (relevant for embedded / freestanding downstream consumers). Ledger closed in commit e94fdbb. Also resolves GAP-0104.
- **Evidence:** Reproducer output recorded in `docs/PERF_GAP_ANALYSIS.md` § PERF-209 (three independent ReleaseFast runs). `zig build` PASS, `zig build test` 586 pass / 2 skip, `zig fmt --check` clean, bench harness green.
- **Resolved date:** 2026-04-20

### PERF-218: EE ALPN dupe -- Cycle 3 audit (not promoted)

- **Issue:** [#182](https://gitlab.com/devnw/zig/tls/-/issues/182) (kept **OPEN** with Cycle 3 audit findings; Cycle 2 deferral plan remains valid)
- **Category:** Performance (allocator hygiene)
- **Cycle 3 outcome:** Not promoted to implementation; audit committed (29a3ef1) strengthens the Cycle 2 deferral.
- **Audit findings:** Single-file concentration (`src/tls13/context.zig`, 10 references, 0 external consumers of `Context.negotiatedAlpn()`). Critical: the field has an **asymmetric ownership contract** — the server-path write at `context.zig:1314` (`selectServerAlpn`, sourced from long-lived `config.alpn_protocols`) is borrow-safe, but the client-path write at `context.zig:2933` (`handleEncryptedExtensions`, sourced from the transient EE parse buffer) **must stay owned** unless the parser is taught to hand Context a longer-lived view. A blanket "flip to borrow" would introduce UAF on the client path. The safe refactor remains the Cycle 2 tagged-ownership plan (`negotiated_alpn_owned: bool` sentinel or `.owned`/`.borrowed` tagged union) with audit of 6+ free/replace sites.
- **Evidence:** `rg '\bnegotiated_alpn\b' src/ tests/ examples/ docs/` output captured in `docs/PERF_GAP_ANALYSIS.md` § PERF-218; 10 `context.zig` references, 0 cross-file references.
- **Audit date:** 2026-04-20

### QUAL-339: parseClientHello ExtHandler table dispatch [CLOSED Cycle 4]

- **Issue:** [#209](https://gitlab.com/devnw/zig/tls/-/work_items/209) — closed on GitLab with Cycle 4 closure note.
- **Category:** Readability / Maintainability
- **Resolution (Cycle 4 / Phase 16, 2026-04-20):** Collapsed the 10-arm parse/build switch statements into a shared `HANDLERS: []const ExtHandler` table in `src/tls13/messages/client_hello_handlers.zig`. Adding an extension now touches one file. All three security-critical invariants were preserved at the OUTER (non-handler) scope:
  1. **SEC-054 errdefer block** — unchanged at `client_hello.zig:262-271`; owns cleanup of partially-populated `ch` allocations. Handlers never errdefer themselves; they only `try` into `ctx.ch`.
  2. **SEC-057 `std.enums.fromInt` guard** — preserved literally on the extension-tag decode (outer loop) and on the `SignatureScheme` decode inside `parseSignatureAlgorithms`.
  3. **CWE-345 `psk_seen` ordering sentinel** — `var psk_seen = false;` declared at outer parseClientHello scope, checked before each non-PSK handler dispatch, and assigned `true` by the outer loop immediately after a `pre_shared_key` handler returns successfully. The HANDLERS table places `.pre_shared_key` LAST so `buildClientHello`'s ordered iteration emits it last on the wire.
- **Equivalence proof:** `tests/fuzz/client_hello_trace_capture.zig` captures an error-trace oracle across 387 inputs (3 seeds × 1 original + 128 deterministic single-bit-flip mutations each, `tests/fuzz/corpus/client_hello_golden.bin`). Post-refactor `cmp` vs pre-refactor golden = byte-identical (exit 0). CI regression gate `client_hello_oracle` in `.gitlab-ci.yml` runs `cmp` every pipeline and fails on divergence.
- **LOC delta:** `src/tls13/messages/client_hello.zig` 905 → 594 LOC (−311); new `src/tls13/messages/client_hello_handlers.zig` 539 LOC housing the extracted handlers + table.
- **Upstream Zig 0.16 fuzz bug:** `std.testing.fuzz` still errors at `lib/compiler/test_runner.zig:566`; the oracle uses a plain `b.addExecutable` to dodge the bug. Mutation is deterministic bit-flip enumeration, not coverage-guided.
- **Closing commit:** 45cc212 (Task 5 dispatch flip); CI gate in 7f8c735; ledger close in <this commit>.

### GAP-0104: thread_pool uses page_allocator [RESOLVED]

- **Issue:** [#140](https://gitlab.com/devnw/zig/tls/-/issues/140)
- **Category:** Performance
- **Resolution:** Closed via PERF-209 (commit 24a275c). GAP-0104 was originally filed as a "needs reproducer" finding; Cycle 3 built the reproducer (`tests/perf/bench_threadpool_alloc.zig`) and promoted the finding to a measured closure. See PERF-209 above for allocator-swap evidence.
- **Resolved date:** 2026-04-20

## Phase 17 Closures (2026-04-20)

### QUAL-317 — `context.zig` decomposition

**Closing commit:** 7f3b48e
**LOC delta:** `src/tls13/context.zig` 3426 → 3055 (original plan
target ≤500; revised to ~3055 due to orchestrator constraint —
see below).
**New modules:** 8 pure-function files under `src/tls13/context/`
totaling ~2600 LOC + ~80 new unit tests.

**Architectural constraint discovered during implementation:** three
stateful orchestrators (`negotiateCipherAndKeys`, `emitServerFlight`,
`driveServerHandshakeFlight`) mutate ≥20 Context fields each. Wrapping
them behind pure APIs would require state slices that defeat the
purpose. These remain in the shell as documented adapters. Target
revised from "≤500 LOC" to "extract every pure-testable helper" —
achieved at 3055 LOC.

**Security invariants preserved verbatim** (oracle byte-identical
across all 12 landing commits):

- `secureZero` on secret replacement stays in shell
- `timing_safe.compare` on PSK binder colocated in `psk_selection.zig`
- SEC-054 errdefer unchanged
- SEC-057 `std.enums.fromInt` guards preserved
- RFC 8446 §4.4.1 transcript transformation (HRR)
- RFC 8446 §4.4.3 CertificateVerify context strings
- RFC 8446 §4.6.3 KeyUpdate semantics + reciprocal-loop break
- RFC 8446 §7.2 traffic-secret rotation

**Bonus security hardening** (discovered during extraction):

- **CWE-226 fix**: Task 9 added 4 new `secureZero` calls on OLD
  app-traffic secrets before KeyUpdate installs new ones. Pre-refactor
  KU paths had zero zeroization — secrets silently persisted in
  memory after rotation. Strictly additive (oracle byte-identical).

**Test count delta:** ~591 → 659 pass (across all 12 commits).

**CI regression gate:** `.gitlab-ci.yml:context_decomp_oracle` runs
every pipeline and cmps against the committed golden file.

Closes QUAL-317 (BLOCKED at Cycle 3, design brainstormed 2026-04-20,
delivered Phase 17).
