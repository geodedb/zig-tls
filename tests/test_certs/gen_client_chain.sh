#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Generate the CA-issued client certificate fixtures (DER) for the
# client-chain-completion tests (tests/client_chain_tests.zig, SONNY-6457).
#
#   client_chain_ca.der        - self-signed Ed25519 CA (CA:TRUE, keyCertSign)
#   client_chain_other_ca.der  - a second, unrelated self-signed Ed25519 CA
#   client_chain_leaf.der      - Ed25519 clientAuth leaf (CA:FALSE) issued by
#                                client_chain_ca
#   client_chain_leaf_key.der  - the leaf's PKCS#8 private key
#
# Valid for 100 years from generation so the handshake tests, which use the
# real clock, keep passing.
#
# DO NOT USE THIS IN PRODUCTION. The key is public.
set -euo pipefail

cd "$(dirname "$0")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ca() {
    local name="$1" cn="$2"
    openssl genpkey -algorithm ed25519 -out "$WORK/$name.key"
    openssl req -x509 -new -key "$WORK/$name.key" -days 36500 -set_serial 1 \
        -subj "/CN=$cn" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,digitalSignature,keyCertSign" \
        -out "$WORK/$name.pem"
    openssl x509 -in "$WORK/$name.pem" -outform DER -out "$name.der"
}

ca client_chain_ca "client-chain-test-ca"
ca client_chain_other_ca "client-chain-test-other-ca"

openssl genpkey -algorithm ed25519 -out "$WORK/leaf.key"
openssl req -new -key "$WORK/leaf.key" -subj "/CN=client.example.com" -out "$WORK/leaf.csr"
cat > "$WORK/leaf.ext" <<'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = DNS:client.example.com
EOF
openssl x509 -req -in "$WORK/leaf.csr" -CA "$WORK/client_chain_ca.pem" \
    -CAkey "$WORK/client_chain_ca.key" -set_serial 2 -days 36500 \
    -extfile "$WORK/leaf.ext" -out "$WORK/leaf.pem"
openssl x509 -in "$WORK/leaf.pem" -outform DER -out client_chain_leaf.der
openssl pkey -in "$WORK/leaf.key" -outform DER -out client_chain_leaf_key.der

echo "Wrote client_chain_ca.der client_chain_other_ca.der client_chain_leaf.der client_chain_leaf_key.der"
