#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Generate an X.509 test fixture (DER) carrying a certificatePolicies
# extension for the TLS library's policy conformance tests.
#
#   policy_leaf.der - self-signed ECDSA prime256v1, CN=policy.example.com,
#                     asserting policy OID 1.3.6.1.4.1.99999.1.
#
# The policyIdentifier OID 1.3.6.1.4.1.99999.1 encodes to the 9 value bytes
# 2B 06 01 04 01 86 8D 1F 01. The library's parseExtCertificatePolicies
# extracts these policy OID value bytes; full RFC 5280 §6.1 policy-tree
# processing (mapping, anyPolicy inhibition across a path) is out of scope.
#
# DO NOT USE THIS IN PRODUCTION. The key is public.
set -euo pipefail

cd "$(dirname "$0")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- Key ----------------------------------------------------------------------
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/policy.key"

# --- Self-signed leaf with certificatePolicies extension ----------------------
openssl req -x509 -new -key "$WORK/policy.key" -sha256 -days 3650 \
    -subj "/CN=policy.example.com" -set_serial 1 \
    -addext "certificatePolicies=1.3.6.1.4.1.99999.1" \
    -out "$WORK/policy.pem"

# --- Emit DER -----------------------------------------------------------------
openssl x509 -in "$WORK/policy.pem" -outform DER -out policy_leaf.der

echo "Wrote policy_leaf.der"
openssl asn1parse -in policy_leaf.der -inform DER | grep -A1 -i "Certificate Policies"
