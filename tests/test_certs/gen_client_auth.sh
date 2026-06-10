#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Generate a self-signed clientAuth X.509 test fixture (DER) for the TLS
# library's client-authentication conformance tests.
#
#   client_cert.der - self-signed cert usable as its own trust anchor:
#                       basicConstraints = critical, CA:TRUE
#                       keyUsage         = critical, digitalSignature, keyCertSign
#                       extendedKeyUsage = clientAuth (1.3.6.1.5.5.7.3.2)
#                       CN / SAN DNS     = client.example.com
#
# Modeled on gen_name_constraints.sh's self-signed CA so x509.validateChain
# accepts it as a single-cert self-signed chain under the .client_auth purpose.
#
# DO NOT USE THIS IN PRODUCTION. The key is public.
set -euo pipefail

cd "$(dirname "$0")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- Key ----------------------------------------------------------------------
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/client.key"

# --- Config (self-signed clientAuth CA / trust anchor) ------------------------
cat > "$WORK/client.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
x509_extensions = v3_client

[dn]
CN = client.example.com

[v3_client]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign
extendedKeyUsage = clientAuth
subjectAltName = DNS:client.example.com
EOF

# Self-signed, serial 1. The fixed validity window (2025-01-01 .. 2035-01-01)
# brackets the conformance suite's NOW_VALID instant (2026-01-01) so the cert is
# valid at test time regardless of when the script is run. -not_after overrides
# any -days default.
openssl req -x509 -new -key "$WORK/client.key" -sha256 \
    -not_before 20250101000000Z -not_after 20350101000000Z \
    -config "$WORK/client.cnf" -set_serial 1 -out "$WORK/client.pem"

# --- Emit DER -----------------------------------------------------------------
openssl x509 -in "$WORK/client.pem" -outform DER -out client_cert.der

echo "Wrote client_cert.der"
