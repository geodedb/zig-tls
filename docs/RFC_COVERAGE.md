# RFC Coverage Matrix

This document tracks which RFC sections are implemented, which are
conformance-tested, and which remain gaps. It is the canonical source
for "are we RFC 8446 / 9001 / 5280 compliant?".

The matrix is maintained alongside `tests/rfc<NNNN>/` test files. A
section is considered "tested" only when a named test case asserts the
MUST/SHOULD clauses of that section against production code.

Legend:

- `[x]` -- implemented and covered by at least one `tests/rfc*/` case
- `[p]` -- partially implemented or partially tested (see notes)
- `[ ]` -- gap: either unimplemented or untested

## RFC 8446 -- TLS 1.3

| Section | Clause                                   | Impl | Test |
|---------|------------------------------------------|------|------|
| 4.1.2   | ClientHello                              | [x]  | [x]  |
| 4.1.3   | ServerHello                              | [x]  | [x]  |
| 4.1.4   | HelloRetryRequest                        | [x]  | [x]  |
| 4.2.3   | SignatureAlgorithms extension            | [x]  | [x]  |
| 4.2.4   | CertificateAuthorities extension         | [x]  | [p]  |
| 4.2.7   | SupportedGroups extension                | [x]  | [x]  |
| 4.2.8   | KeyShare extension                       | [x]  | [x]  |
| 4.2.9   | PreSharedKey extension                   | [x]  | [p]  |
| 4.2.10  | EarlyData extension                      | [x]  | [x]  |
| 4.2.11  | PSK exchange modes                       | [x]  | [p]  |
| 4.3.1   | EncryptedExtensions                      | [x]  | [x]  |
| 4.3.2   | CertificateRequest (mTLS)                | [x]  | [x]  |
| 4.4.2   | Certificate                              | [x]  | [x]  |
| 4.4.3   | CertificateVerify                        | [x]  | [x]  |
| 4.4.4   | Finished                                 | [x]  | [x]  |
| 4.6.1   | NewSessionTicket                         | [ ]  | [p]  |
| 4.6.3   | KeyUpdate                                | [x]  | [x]  |
| 5       | Record layer                             | [x]  | [x]  |
| 6       | Alert protocol                           | [x]  | [x]  |
| 7       | Key schedule                             | [x]  | [x]  |
| 8       | 0-RTT / anti-replay                      | [x]  | [x]  |
| B.4     | Cipher suite enum parity (QUAL-337)      | [x]  | [x]  |

## RFC 9001 -- TLS for QUIC

| Section | Clause                                   | Impl | Test |
|---------|------------------------------------------|------|------|
| 4       | Carrying TLS records in QUIC             | [x]  | [x]  |
| 5.1     | Packet protection keys                   | [x]  | [x]  |
| 5.2     | Initial secrets                          | [x]  | [x]  |
| 5.3     | AEAD usage                               | [x]  | [x]  |
| 5.4     | Header protection                        | [ ]  | [p]  |
| 5.5     | Retry integrity                          | [ ]  | [p]  |
| 6       | Key updates                              | [x]  | [x]  |
| 9       | Version negotiation                      | [x]  | [x]  |

## RFC 5280 -- X.509 PKIX

| Section | Clause                                   | Impl | Test |
|---------|------------------------------------------|------|------|
| 4.1     | Basic certificate fields                 | [x]  | [x]  |
| 4.2.1.3 | KeyUsage extension                       | [x]  | [x]  |
| 4.2.1.6 | SubjectAltName extension                 | [x]  | [x]  |
| 4.2.1.9 | BasicConstraints extension               | [x]  | [x]  |
| 4.2.1.10| NameConstraints extension                | [x]  | [x]  |
| 4.2.1.12| ExtKeyUsage extension                    | [x]  | [x]  |
| 5       | CRL processing                           | [ ]  | [p]  |
| 6       | Certification path validation            | [x]  | [x]  |

## Follow-up

Sections marked `[ ]` or `[p]` are planned for the RFC test coverage
epic (see GAP-0119 / GAP-0120 / GAP-0121). Each gap should add one
test file under `tests/rfc<NNNN>/section_<clause>_<topic>.zig` and be
registered in `build.zig`.
