# Test Certificates and Keys

> **SECURITY WARNING: DO NOT USE THESE IN PRODUCTION!**

## Purpose

This directory contains self-signed X.509 certificates and private keys used
**exclusively for automated testing** of the TLS 1.3 implementation.

## Contents

- `root_cert.pem` / `root_key.pem` - Self-signed root CA
- `intermediate_cert.pem` / `intermediate_key.pem` - Intermediate CA
- `leaf_cert.pem` / `leaf_key.pem` - End-entity certificate
- `*_cert.pem` / `*_key.pem` - Algorithm-specific test certificates (P-256, P-384, Ed25519, RSA-2048)
- `expired_cert.pem` - Intentionally expired certificate for testing
- `cert_with_extensions.pem` - Certificate with various X.509 extensions

## Security Warnings

1. **These private keys are PUBLIC** - they are committed to version control
   and must never be used to protect real data or communications.

2. **No trust anchor** - These certificates are not trusted by any real PKI.
   Do not add them to system trust stores.

3. **Weak parameters** - Some test keys may use parameters that are not
   recommended for production use.

4. **Test-only CN/SAN** - The certificates use test domains (localhost, etc.)
   that should never be trusted for real TLS connections.

## Production Usage

For production TLS deployments:

1. Obtain certificates from a trusted Certificate Authority (CA)
2. Generate private keys on secure, dedicated hardware (HSM) when possible
3. Never commit private keys to version control
4. Use proper key management practices (rotation, access control, etc.)

## Regenerating Test Certificates

Test certificates can be regenerated using OpenSSL. See the project's
development documentation for instructions.
