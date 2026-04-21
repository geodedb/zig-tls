# Architecture Decision Records (ADR)

This directory holds the project's Architecture Decision Records.

An ADR captures a single architecturally-significant decision: the
context that led to it, the alternatives considered, the decision
itself, and the consequences accepted.

## Format

Each record is a numbered Markdown file:

```text
docs/adr/NNNN-short-slug.md
```

`NNNN` is a four-digit, zero-padded monotonically increasing index. Do
not reuse numbers; if a decision is superseded, write a new ADR that
links back to the one it replaces and mark the old one
`Status: Superseded by ADR-NNNN`.

## Template

```markdown
# ADR-NNNN: <Short Title>

## Status

Proposed | Accepted | Superseded by ADR-NNNN | Deprecated

## Context

What motivates this decision? What forces, constraints, or evidence
shape it? (Keep to one or two paragraphs.)

## Decision

The chosen course of action, stated as a single declarative sentence
followed by supporting detail as needed.

## Consequences

Positive, negative, and neutral outcomes accepted as part of this
choice. Include migration cost, operational implications, and any
gaps this opens.

## Alternatives Considered

Bullet list of options evaluated and one-line reason each was
rejected.
```

## Index

| ADR  | Title                                                               | Status                |
|------|---------------------------------------------------------------------|-----------------------|
| 0001 | Engine module deprecation                                           | Accepted              |
| 0002 | [ECDSA-P256 performance strategy](./0002-ecdsa-p256-performance.md) | Proposed (2026-04-21) |
