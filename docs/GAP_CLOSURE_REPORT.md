# Gap Closure Completion Report -- Phase 22

**Date:** 2026-04-27
**Branch:** main
**Run:** /codepros:gap-close (10-gap scope)

## GAP_ANALYSIS Status

| File                     | Closed (cycle) | Blocked | Won't Do (cycle) | Open (post-cycle) | Total tracked |
|--------------------------|----------------|---------|------------------|-------------------|---------------|
| GAP_ANALYSIS.md          | 3              | 0       | 0                | 5                 | 137           |
| SECURITY_GAP_ANALYSIS.md | 3 (+1 subsumed)| 0       | 0                | 5 open Phase 20 carry (none High) | 73 (legacy table) |
| QUALITY_GAP_ANALYSIS.md  | 2 (+1 subsumed)| 0       | 0                | 29                | 137           |
| PERF_GAP_ANALYSIS.md     | 4 (+ cascade)  | 0       | 0                | 18                | 97            |

**Phase 22 outcome:** 9 closed, 0 blocked, 0 Won't Do, 1 deferred (with refined scope-creep note) out of 10 scoped items. Subsumption: SEC-092 closes SEC-078; QUAL-374 closes QUAL-364 + SEC-084; PERF-237b/GAP-0131 deletion subsumes #180/#190/#195/#200/#248/#263/#278.

## Closed Items (9)

| Gap-ID | File | Title | Evidence |
|--------|------|-------|----------|
| SEC-088 | SECURITY_GAP_ANALYSIS.md | ClientHello legacy_compression_methods enforcement (RFC 8446 §4.1.2) | `src/tls13/messages/client_hello.zig:334`; `src/tls13/context.zig:2410-2413, 1093-1130`; `src/tls13/types.zig:269+` (`IllegalCompressionMethods` variant); `src/alert.zig:129`; tests `tests/security/sec088_clienthello_compression.zig:74-128` (4 cases); commits a941970 + 8a7f394 |
| SEC-092 (subsumes SEC-078) | SECURITY_GAP_ANALYSIS.md | EE/SH duplicate-extension rejection (RFC 8446 §4.2) | `src/tls13/messages/encrypted_extensions.zig:217-237`; `src/tls13/context/server_hello_parsers.zig:44-95`; `src/tls13/context.zig:2425-2433`; `src/tls13/types.zig:269` (`DuplicateExtension`); tests `tests/security/sec092_ee_dup_ext.zig:65-101`; commit ab1f781 |
| GAP-0138 | GAP_ANALYSIS.md | Handshake errors do not queue fatal alerts (RFC 8446 §6.2) | `src/tls13/context.zig:1086-1132` (`handleHandshakeMessage` catch + `dispatchHandshake`); `src/tls13/context.zig:2213-2218` (`failAlert`); `src/alert.zig:108-129` (`fromHandshakeError`); tests `tests/security/gap0138_handshake_alert_emit.zig`; commit aa9254b |
| GAP-0139 | GAP_ANALYSIS.md | CertificateRequest level + post_handshake_auth gate (RFC 8446 §4.3.2 / §4.6.2) | `src/tls13/context.zig:1188-1220`; `src/tls13/config.zig:382` (`post_handshake_auth: bool = false`); tests `tests/security/gap0139_certreq_level_gate.zig:38-93` (4 cases); commit aabbb74 |
| QUAL-374 (subsumes QUAL-364, SEC-084) | QUALITY_GAP_ANALYSIS.md | Replace SkipZigTest stubs with real coverage | `tests/sig_unit_tests.zig:146-189` (RSA SPKI wrong-OID rejection vs `id-ecPublicKey`); `tests/x509_unit_tests.zig:536-577` (`validateChain` against existing Ed25519 self-signed fixture); 0 unconditional skips remain in those files; commit 23df917 |
| PERF-249 | PERF_GAP_ANALYSIS.md | Outbound CryptoBuffer pre-size for alert + framed-message paths | `src/tls13/context.zig:1476, 1489, 2158, 2180, 2690` (5 outbound paths pre-sized); regression `tests/perf/test_outbound_allocs.zig:26` (≤2 reallocs assertion via `CountingAllocator`); commit 2502b80 |
| PERF-255 | PERF_GAP_ANALYSIS.md | Replace PSK binder rehash with `Transcript.clone()` | `src/tls13/transcript.zig:181-183` (`clone`); `src/tls13/transcript.zig:826` (regression test); `src/tls13/context.zig:2327-2354` (binder path uses `clone`); `src/tls13/context.zig:1471-1493` (`update_transcript=false` plumbing); commit 6298477 |
| PERF-229 | PERF_GAP_ANALYSIS.md | ECDSA-P256 stdlib bottleneck — close via ADR-0002 acceptance | `docs/adr/0002-ecdsa-p256-performance.md:3-5` (Status: Accepted 2026-04-27); `README.md:13-19` (Performance note); `tests/bench.zig` `benchEcdsaP256Verify` continues guarding 10% regressions; commit 25c3690 |
| PERF-237b / GAP-0131 (cascade #180/#190/#195/#200/#248/#263/#267/#278) | PERF_GAP_ANALYSIS.md + GAP_ANALYSIS.md | Delete `src/parallel.zig` (997 LOC, zero production callers) | `src/parallel.zig` deleted; `src/lib.zig:409-413, 550-551` (re-export + smoke test removed); `build.zig:242, 278` (`parallel_mod` stripped); `tests/fuzz/rsa_pss_verify.zig` migrated to `sig.rsaPssVerifyGeneric`; `build.zig.zon:12` bumped to 0.2.0 (semver MAJOR per breaking-change policy); `CHANGELOG.md:10-19` migration notes; commit 14b73a6 |

## Deferred / Refined (1)

| Gap-ID | File | Title | Reason | Unblock steps |
|--------|------|-------|--------|---------------|
| QUAL-351 | QUALITY_GAP_ANALYSIS.md | `handleServerHello` hardcodes X25519, contradicting `Config.supported_groups` | Scope creep — closure requires 5 coordinated changes across multiple files. Closing in this run risks regressing the QUIC-INTEROP-HRR cookie work (SEC-086, SEC-087, QUAL-369) that just landed earlier in the same cycle. | (1) Tagged-union `ClientPriv` to replace the `[32]u8` field; (2) widen `ClientHelloParams.client_pub` from `[32]u8` to a per-curve buffer + propagate through the `buildKeyShare` extension handler; (3) per-group dispatch in `handleServerHello`'s key_share parse and ECDHE compute (P256 ECDH is **not** in `std.crypto.dh` — caller must use `std.crypto.pcurves.p256.P256.mul(priv, .big)` directly); (4) matching dispatch in `sendClientHello2` (HRR rekey path) and on the server side (`server_priv` + `scalarmult`); (5) relax the `Config.init` guard at `context.zig:602-604`. Estimated as non-trivial M-effort; defer to a dedicated wave. Refinement landed in commit d482da4. |

## Tests Executed

| Command | Result |
|---------|--------|
| `zig build` | PASS |
| `zig build test` | PASS — 646 pass / 7 skip (all 7 skips are tls_insecure_testing-gated) |
| `zig fmt --check src/ tests/ build.zig` | PASS |
| `zig build fuzz-rsa-pss` | PASS |

## Security Notes

- **GAP-0138** wires every `HandshakeError` variant through `failAlert` so the spec-mandated alert is queued before the typed error propagates. RFC 8446 §6.2 alert-code mapping is centralized in `alert.fromHandshakeError`. Tests assert the outbound CryptoBuffer payload bytes (level=2 fatal + expected description) and `Context.phase == .terminated` for each error category.
- **SEC-088** enforces RFC 8446 §4.1.2 / §4.1.3 on `legacy_compression_methods` (ClientHello) and `legacy_compression_method` (ServerHello). Follow-up commit `8a7f394` adds the new `IllegalCompressionMethods` variant to the `dispatchHandshake` catch list so the runtime alert path emits `illegal_parameter` rather than `internal_error`.
- **SEC-092** closes the EE/SH duplicate-extension defense gap (subsumes SEC-078). All four walks (EE parser, SH `validateSupportedVersions`, SH `parsePskExtension`, inline SH walk in `handleServerHello`) now use `EnumSet(ExtensionType)` to reject duplicates per RFC 8446 §4.2 and emit `illegal_parameter` via the GAP-0138 alert path. Prior allocation leak path closed.
- **GAP-0139** gates `certificate_request` on encryption level + the new `Config.post_handshake_auth` bool. Initial: reject; Handshake: accept only pre-`application_ready`; Application: accept only when `post_handshake_auth == true` AND phase has reached `.application_ready` / `.post_handshake`.
- **PERF-237b / GAP-0131** is a breaking deletion (semver MAJOR) — `src/parallel.zig` re-export removed from public API. CHANGELOG documents the migration to `sig.rsaPssVerifyGeneric` for the only non-trivial consumer.

## Remaining Blockers

None. QUAL-351 is explicitly deferred (not blocked) with a documented unblock plan; the work is feature-scope, not blocked on external dependencies.

## Platform issues to close manually

The reporter intentionally did not invoke `glab` / `gh` this run (no `--skip-issues` was passed but the user requested doc-only edits to keep the run fast). The following GitLab issues should be closed manually with a comment referencing the closing commit:

| Gap-ID | Issue | Closing commit | Action |
|--------|-------|----------------|--------|
| SEC-088 | [#323](https://gitlab.com/devnw/zig/tls/-/issues/323) | a941970 + 8a7f394 | close |
| SEC-092 (subsumes SEC-078) | [#296](https://gitlab.com/devnw/zig/tls/-/issues/296) | ab1f781 | close |
| GAP-0138 | [#302](https://gitlab.com/devnw/zig/tls/-/issues/302) | aa9254b | close |
| GAP-0139 | [#303](https://gitlab.com/devnw/zig/tls/-/issues/303) | aabbb74 | close |
| QUAL-374 (subsumes #282 QUAL-364, #301 SEC-084) | [#307](https://gitlab.com/devnw/zig/tls/-/issues/307) | 23df917 | close |
| PERF-249 | [#315](https://gitlab.com/devnw/zig/tls/-/issues/315) | 2502b80 | close |
| PERF-255 | [#320](https://gitlab.com/devnw/zig/tls/-/issues/320) | 6298477 | close |
| PERF-237b / GAP-0131 (cascade #180/#190/#195/#200/#248/#263/#267/#278) | [#322](https://gitlab.com/devnw/zig/tls/-/issues/322) | 14b73a6 | close (and close cascaded issues) |
| PERF-229 | [#243](https://gitlab.com/devnw/zig/tls/-/issues/243) | 25c3690 (ADR-0002 acceptance) | close |
| QUAL-351 | [#245](https://gitlab.com/devnw/zig/tls/-/issues/245) | d482da4 (refinement only) | comment-only — remains Open / Deferred |

## Commits in this Phase 22 run (oldest first)

1. a941970 — SEC-088 (legacy_compression_methods enforcement)
2. ab1f781 — SEC-092 / SEC-078 (EE/SH duplicate-extension rejection)
3. aabbb74 — GAP-0139 (CertificateRequest level + post_handshake_auth gate)
4. aa9254b — GAP-0138 (handshake-error fatal alert queueing)
5. 23df917 — QUAL-374 (replace SkipZigTest with real coverage)
6. d482da4 — QUAL-351 (deferred — evidence refinement, scope-creep note)
7. 6298477 — PERF-255 (PSK binder Transcript.clone)
8. 2502b80 — PERF-249 (outbound CryptoBuffer pre-size)
9. 25c3690 — PERF-229 (ADR-0002 acceptance)
10. 14b73a6 — PERF-237b / GAP-0131 (parallel.zig deletion; semver MAJOR -> 0.2.0)
11. 8a7f394 — SEC-088 / GAP-0138 follow-up (`IllegalCompressionMethods` -> alert path)

## Definition of Done

- [x] Every scoped gap is Closed or explicitly Deferred with reason.
- [x] Every tracking file (`GAP_ANALYSIS.md`, `SECURITY_GAP_ANALYSIS.md`, `QUALITY_GAP_ANALYSIS.md`, `PERF_GAP_ANALYSIS.md`, `GAP_ANALYSIS_RESOLVED.md`) reflects final state.
- [x] All tests pass (646 pass / 7 skip; 0 new failures vs baseline).
- [x] Changes are secure, accurate, consistent across ledgers.
- [x] New tests cover SEC-088, SEC-092, GAP-0138, GAP-0139, PERF-249, PERF-255, QUAL-374.
- [ ] Platform issues — list provided for user to close manually.
- [x] Completion report produced (this file).
