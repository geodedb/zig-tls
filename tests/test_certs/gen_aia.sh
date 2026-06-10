#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Generate an X.509 test fixture (DER) carrying an AuthorityInfoAccess
# extension for the TLS library's AIA conformance tests.
#
#   aia_leaf.der - self-signed ECDSA prime256v1, CN=aia.example.com, with
#                  authorityInfoAccess containing BOTH an OCSP URI and a
#                  caIssuers URI:
#                    OCSP      - URI:http://ocsp.example/
#                    CA Issuers - URI:http://ca.example/ca.der
#
# The library's parseExtAuthorityInfoAccess buckets these by accessMethod
# (id-ad-ocsp / id-ad-caIssuers) and exposes the URIs; performing the actual
# HTTP fetches is the application layer's responsibility (out of scope here).
#
# DO NOT USE THIS IN PRODUCTION. The key is public.
set -euo pipefail

cd "$(dirname "$0")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- Key ----------------------------------------------------------------------
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/aia.key"

# --- Self-signed leaf with AIA extension --------------------------------------
openssl req -x509 -new -key "$WORK/aia.key" -sha256 -days 3650 \
    -subj "/CN=aia.example.com" -set_serial 1 \
    -addext "authorityInfoAccess=OCSP;URI:http://ocsp.example/,caIssuers;URI:http://ca.example/ca.der" \
    -out "$WORK/aia.pem"

# --- Emit DER -----------------------------------------------------------------
openssl x509 -in "$WORK/aia.pem" -outform DER -out aia_leaf.der

echo "Wrote aia_leaf.der"
openssl x509 -in aia_leaf.der -inform DER -noout -text | grep -A4 "Authority Information Access"
