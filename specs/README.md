# RFC Specification Reference Files

This directory contains **RFC specification documents** for reference during
TLS 1.3/QUIC implementation. These are publicly available IETF documents.

## Contents

| Directory | Description | Primary RFCs |
|-----------|-------------|--------------|
| `aead/` | Authenticated encryption specs | RFC 5116, RFC 8439 |
| `ecdhe/` | Elliptic curve Diffie-Hellman | RFC 7748 |
| `ecdsa/` | ECDSA signature algorithm | RFC 6979 |
| `pem/` | PEM encoding format | RFC 7468 |
| `quic/` | QUIC transport protocol | RFC 9000, RFC 9001 |
| `tls/` | TLS 1.3 protocol | RFC 8446 |
| `x509/` | X.509 certificates | RFC 5280, RFC 8410 |

## Security Notice

**These files may contain example cryptographic keys from RFCs.**

These are **publicly documented test vectors** used for interoperability testing
and are NOT real private keys. They are included in this repository to:

1. Verify our implementation against RFC test vectors
2. Document expected formats and encodings
3. Support automated interop testing

### Secret Scanner False Positives

Security scanners (gitleaks, trufflehog, etc.) may flag files like:

- `x509/rfc8410.txt` - Contains Ed25519/X25519 example keys from RFC 8410
- `pem/rfc7468.txt` - Contains PEM-encoded example certificates

**These are intentional and safe.** The `.gitleaks.toml` configuration excludes
this directory with appropriate comments explaining why.

## Source

All specifications are sourced from:
- IETF Datatracker: https://datatracker.ietf.org/
- RFC Editor: https://www.rfc-editor.org/

## License

RFC documents are subject to IETF Trust copyright. See:
https://trustee.ietf.org/license-info/
