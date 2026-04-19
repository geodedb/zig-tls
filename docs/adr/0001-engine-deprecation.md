# ADR-0001: Engine module deprecation in favor of Context

## Status

Accepted -- implemented (2026-04-19)

Engine deleted in commit landing on main after this ADR update. No
downstream caller or test referenced `Engine`, `TicketStore`,
`TicketEntry`, `encodeMinimalClientHello`, or `encodeMinimalServerHello`
outside of engine.zig itself and the re-export barrel files
(`src/tls13/mod.zig`, `src/tls13.zig`), so the deletion is a single
atomic change with no caller-facing migration. The Engine-only tests
(OOM propagation via `FailingAllocator`, X25519 `IdentityElement`
rejection, `parseRealServerHello` supported_versions checks) have
equivalent behavioural coverage through `handshake_state.zig`
FailingAllocator tests and the existing RFC 8446 §4.2.1 extension
tests in `tests/rfc8446/section_4_2_extensions.zig`; the
`parseMinimalHelloPub` canonical definition already lived in
`src/tls13/messages.zig` and is unaffected.

## Context

The TLS 1.3 implementation historically carried two parallel drivers:

- `src/tls13/engine.zig` -- the original minimal state machine (~2236
  LOC), designed as a lightweight experimentation vehicle before the
  full Context was ready.
- `src/tls13/context.zig` -- the production driver that absorbed all
  subsequent features (mTLS, 0-RTT, NewSessionTicket, HRR, client
  auth, parallel chain validation, transcript lock-hash, structured
  logging, QUIC integration hooks, etc.).

Engine remained useful as a reference implementation while Context
matured, but by mid-2026 every feature request, security fix, and
perf optimisation landed exclusively on Context. Engine kept compiling
but was effectively frozen at the mid-2025 feature level. Its
continued presence produced four ongoing costs:

1. Duplicate type definitions (KeyMaterial, HandshakeState,
   CipherSuite, BidirSecrets) with divergent field orderings and
   subtle semantic drift.
2. A fan of re-exports in `src/tls13.zig` and `src/tls13/mod.zig`
   that had to be kept in sync with two implementations.
3. Engine-only tests that exercised an API surface downstream
   consumers no longer touched.
4. Reader confusion: new contributors routinely grepped Engine by
   accident and copied obsolete patterns.

Several existing gap items (SEC-064, QUAL-319, QUAL-302, QUAL-304,
PERF-023, PERF-040, PERF-217, PERF-219, PERF-220, PERF-226,
GAP-0108, GAP-0110) all called for Engine-side fixes that Context
already had.

## Decision

Delete `src/tls13/engine.zig` outright rather than bring it up to
parity. Before deletion, port Engine-only coverage (OOM propagation,
X25519 identity-element rejection, supported_versions enforcement,
`parseMinimalHelloPub` / `encodeMinimal*` callers) to equivalent
tests against Context. After the tests pass, remove Engine, strip its
re-exports from `src/tls13.zig` and `src/tls13/mod.zig`, and update
`docs/ENGINE_TO_CONTEXT_MIGRATION.md` to the "complete" state.

This aligns with the project's documented preference for deleting
broken or frozen features rather than patching them when there is no
active maintainer for the parallel path.

## Consequences

- **Positive**: -2236 LOC. One driver to audit. Duplicate type
  families can be consolidated (QUAL-335/336/337, GAP-0107). A dozen
  open gap items close in bulk.
- **Negative**: Any downstream consumer of Engine breaks at compile
  time. We believe the project has no such external consumer; any
  that surface will be directed to Context with help from the
  migration guide.
- **Neutral**: Engine's minimal-hello encoder/parser was useful for a
  handful of fuzz harnesses; those are ported before deletion.

## Alternatives Considered

- **Keep Engine, backport fixes** -- rejected: ongoing maintenance
  cost with no downstream consumer and no maintainer volunteers.
- **Freeze Engine with a compile-time deprecation warning** -- rejected:
  the re-exports still poison the public surface, and warnings get
  cargo-culted past.
- **Extract Engine into its own repo** -- rejected: nobody has asked
  for it, and we would still need to maintain the re-export glue.
