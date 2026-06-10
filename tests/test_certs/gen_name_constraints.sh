#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Generate name-constrained X.509 test fixtures (DER) for the TLS library's
# X.509 nameConstraints conformance tests.
#
#   nc_constrained_ca.der  - self-signed CA, nameConstraints permitted DNS:.example.com
#   nc_permitted_leaf.der   - leaf CN=host.example.com (inside the constraint)
#   nc_excluded_leaf.der     - leaf CN=evil.test (outside the constraint)
#
# DO NOT USE THESE IN PRODUCTION. Keys are public.
set -euo pipefail

cd "$(dirname "$0")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- Keys ---------------------------------------------------------------------
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/ca.key"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/permitted.key"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/excluded.key"

# --- CA config (with nameConstraints) -----------------------------------------
cat > "$WORK/ca.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
x509_extensions = v3_ca

[dn]
CN = Name Constraints Test CA

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
nameConstraints = critical, permitted;DNS:.example.com
EOF

# Self-signed CA, serial 1.
openssl req -x509 -new -key "$WORK/ca.key" -sha256 -days 3650 \
    -config "$WORK/ca.cnf" -set_serial 1 -out "$WORK/ca.pem"

# --- Leaf ext configs ---------------------------------------------------------
cat > "$WORK/permitted.cnf" <<'EOF'
[v3_leaf]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:host.example.com
EOF

cat > "$WORK/excluded.cnf" <<'EOF'
[v3_leaf]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:evil.test
EOF

# --- Permitted leaf (serial 10) -----------------------------------------------
openssl req -new -key "$WORK/permitted.key" -subj "/CN=host.example.com" \
    -out "$WORK/permitted.csr"
openssl x509 -req -in "$WORK/permitted.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
    -set_serial 10 -days 3650 -sha256 \
    -extfile "$WORK/permitted.cnf" -extensions v3_leaf -out "$WORK/permitted.pem"

# --- Excluded leaf (serial 11) ------------------------------------------------
openssl req -new -key "$WORK/excluded.key" -subj "/CN=evil.test" \
    -out "$WORK/excluded.csr"
openssl x509 -req -in "$WORK/excluded.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
    -set_serial 11 -days 3650 -sha256 \
    -extfile "$WORK/excluded.cnf" -extensions v3_leaf -out "$WORK/excluded.pem"

# --- Emit DER -----------------------------------------------------------------
openssl x509 -in "$WORK/ca.pem"        -outform DER -out nc_constrained_ca.der
openssl x509 -in "$WORK/permitted.pem" -outform DER -out nc_permitted_leaf.der
openssl x509 -in "$WORK/excluded.pem"  -outform DER -out nc_excluded_leaf.der

echo "Wrote nc_constrained_ca.der nc_permitted_leaf.der nc_excluded_leaf.der"
