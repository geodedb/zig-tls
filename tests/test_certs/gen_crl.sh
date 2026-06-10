#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Generate CRL test fixtures (DER) for the TLS library's CRL conformance tests
# using the `openssl ca` demoCA workflow (index.txt + serial + crlnumber).
#
#   crl_ca.der           - issuing CA cert (DER)
#   crl_leaf.der          - leaf cert that gets revoked (DER)
#   crl_empty.der          - CRL with no revoked entries
#   crl_with_revoked.der    - CRL revoking the leaf's serial
#
# nextUpdate is far future (default_crl_days = 3650).
#
# DO NOT USE THESE IN PRODUCTION. Keys are public.
set -euo pipefail

cd "$(dirname "$0")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- demoCA layout ------------------------------------------------------------
mkdir -p "$WORK/demoCA/newcerts"
: > "$WORK/demoCA/index.txt"
echo 1000 > "$WORK/demoCA/serial"
echo 1000 > "$WORK/demoCA/crlnumber"

cat > "$WORK/ca.cnf" <<EOF
[ca]
default_ca = CA_default

[CA_default]
dir              = $WORK/demoCA
database         = \$dir/index.txt
new_certs_dir    = \$dir/newcerts
serial           = \$dir/serial
crlnumber        = \$dir/crlnumber
certificate      = $WORK/ca.pem
private_key      = $WORK/ca.key
default_md       = sha256
default_days     = 3650
default_crl_days = 3650
policy           = policy_anything
x509_extensions  = v3_leaf
crl_extensions   = crl_ext

[policy_anything]
commonName = supplied

[v3_leaf]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:crl-leaf.example.com

[crl_ext]
authorityKeyIdentifier = keyid:always

[req]
distinguished_name = dn
prompt = no
x509_extensions = v3_ca

[dn]
CN = CRL Test CA

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
EOF

# --- Issuing CA (RSA, self-signed) -------------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/ca.key" \
    -config "$WORK/ca.cnf" -set_serial 1 -days 3650 -sha256 -out "$WORK/ca.pem"

# --- Leaf, issued via `openssl ca` so it lands in the index ------------------
openssl req -newkey rsa:2048 -nodes -keyout "$WORK/leaf.key" \
    -subj "/CN=crl-leaf.example.com" -out "$WORK/leaf.csr"
openssl ca -batch -config "$WORK/ca.cnf" -in "$WORK/leaf.csr" -out "$WORK/leaf.pem" \
    -notext

# --- Empty CRL (before revoking anything) ------------------------------------
openssl ca -batch -config "$WORK/ca.cnf" -gencrl -out "$WORK/crl_empty.pem"

# --- Revoke the leaf, then regenerate the CRL --------------------------------
openssl ca -batch -config "$WORK/ca.cnf" -revoke "$WORK/leaf.pem"
openssl ca -batch -config "$WORK/ca.cnf" -gencrl -out "$WORK/crl_revoked.pem"

# --- Emit DER -----------------------------------------------------------------
openssl crl  -in "$WORK/crl_empty.pem"   -outform DER -out crl_empty.der
openssl crl  -in "$WORK/crl_revoked.pem" -outform DER -out crl_with_revoked.der
openssl x509 -in "$WORK/ca.pem"          -outform DER -out crl_ca.der
openssl x509 -in "$WORK/leaf.pem"        -outform DER -out crl_leaf.der

echo "Wrote crl_ca.der crl_leaf.der crl_empty.der crl_with_revoked.der"
