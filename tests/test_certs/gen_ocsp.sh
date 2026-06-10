#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Generate OCSP BasicOCSPResponse test fixtures (DER) for the TLS library's
# ocsp.validateStapledResponse conformance tests.
#
# The library performs FULL validation: decode + CertID match against
# (leaf, issuer) + signature verification + validity-time check. Therefore the
# response is signed by the same CA whose cert we save (rsigner = CA), and the
# leaf CertID must match the saved leaf + issuer.
#
#   ocsp_ca.der             - issuing CA cert (DER)
#   ocsp_leaf.der            - leaf cert the responses are about (serial 0x1010 = 4112)
#   ocsp_response_good.der    - BasicOCSPResponse, Cert Status: good
#   ocsp_response_revoked.der - BasicOCSPResponse, Cert Status: revoked
#
# DO NOT USE THESE IN PRODUCTION. Keys are public.
set -euo pipefail

cd "$(dirname "$0")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

LEAF_SERIAL_HEX=1010   # 4112 decimal

# --- Issuing CA (RSA, self-signed) -------------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/ca.key" \
    -subj "/CN=OCSP Test CA" -set_serial 1 -days 3650 -sha256 \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
    -out "$WORK/ca.pem"

# --- Leaf signed by CA, serial 0x1010 ----------------------------------------
openssl req -newkey rsa:2048 -nodes -keyout "$WORK/leaf.key" \
    -subj "/CN=ocsp-leaf.example.com" -out "$WORK/leaf.csr"

cat > "$WORK/leaf.cnf" <<'EOF'
[v3_leaf]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:ocsp-leaf.example.com
EOF

openssl x509 -req -in "$WORK/leaf.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
    -set_serial "0x${LEAF_SERIAL_HEX}" -days 3650 -sha256 \
    -extfile "$WORK/leaf.cnf" -extensions v3_leaf -out "$WORK/leaf.pem"

# --- CA index database --------------------------------------------------------
# index.txt line format (tab-separated):
#   <status>\t<expiry YYMMDDHHMMSSZ>\t[<revoke-time>]\t<serial hex>\tunknown\t<DN>
# status: V (valid), R (revoked). Serial must be uppercase hex w/o 0x.
EXPIRY="360607000000Z"   # far future
REVOKED_TIME="260101000000Z"
SUBJECT_DN="/CN=ocsp-leaf.example.com"

printf 'V\t%s\t\t%s\tunknown\t%s\n' "$EXPIRY" "1010" "$SUBJECT_DN" > "$WORK/index_good.txt"
printf 'R\t%s\t%s\t%s\tunknown\t%s\n' "$EXPIRY" "$REVOKED_TIME" "1010" "$SUBJECT_DN" > "$WORK/index_revoked.txt"

# --- Build a single OCSP request for the leaf --------------------------------
# Note: the digest flag (-sha256) must precede -cert. SHA-256 CertID is REQUIRED:
# the library deliberately rejects SHA-1 CertIDs (CWE-328), so OpenSSL's default
# SHA-1 would cause every SingleResponse to be skipped (MissingSingleResponse).
openssl ocsp -issuer "$WORK/ca.pem" -sha256 -cert "$WORK/leaf.pem" \
    -reqout "$WORK/req.der" -no_nonce

# --- Produce GOOD response (rsigner = CA) ------------------------------------
# -ndays sets nextUpdate far in the future. thisUpdate is stamped at gen time.
openssl ocsp -index "$WORK/index_good.txt" -CA "$WORK/ca.pem" \
    -rsigner "$WORK/ca.pem" -rkey "$WORK/ca.key" \
    -reqin "$WORK/req.der" -respout ocsp_response_good.der \
    -ndays 3650 -no_nonce -resp_no_certs

# --- Produce REVOKED response (rsigner = CA) ---------------------------------
openssl ocsp -index "$WORK/index_revoked.txt" -CA "$WORK/ca.pem" \
    -rsigner "$WORK/ca.pem" -rkey "$WORK/ca.key" \
    -reqin "$WORK/req.der" -respout ocsp_response_revoked.der \
    -ndays 3650 -no_nonce -resp_no_certs

# --- Emit CA + leaf DER -------------------------------------------------------
openssl x509 -in "$WORK/ca.pem"   -outform DER -out ocsp_ca.der
openssl x509 -in "$WORK/leaf.pem" -outform DER -out ocsp_leaf.der

echo "Wrote ocsp_ca.der ocsp_leaf.der ocsp_response_good.der ocsp_response_revoked.der"
