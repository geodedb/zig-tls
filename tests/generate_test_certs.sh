#!/bin/bash
# Generate test certificates and keys for unit tests

set -e

CERT_DIR="tests/test_certs"
mkdir -p "$CERT_DIR"

echo "Generating test certificates..."

# ============================================================================
# Ed25519 certificates
# ============================================================================

# Generate Ed25519 private key and self-signed certificate
openssl genpkey -algorithm ED25519 -out "$CERT_DIR/ed25519_key.pem"
openssl req -x509 -new -key "$CERT_DIR/ed25519_key.pem" -days 3650 \
    -out "$CERT_DIR/ed25519_cert.pem" \
    -subj "/CN=ed25519.example.com/O=Test/C=US"

# Convert to DER format
openssl x509 -in "$CERT_DIR/ed25519_cert.pem" -outform DER -out "$CERT_DIR/ed25519_cert.der"
openssl pkey -in "$CERT_DIR/ed25519_key.pem" -outform DER -out "$CERT_DIR/ed25519_key.der"

# Extract public key SPKI
openssl x509 -in "$CERT_DIR/ed25519_cert.pem" -pubkey -noout > "$CERT_DIR/ed25519_pubkey.pem"
openssl pkey -pubin -in "$CERT_DIR/ed25519_pubkey.pem" -outform DER -out "$CERT_DIR/ed25519_spki.der"

# ============================================================================
# ECDSA P-256 certificates
# ============================================================================

# Generate ECDSA P-256 private key and certificate
openssl ecparam -name prime256v1 -genkey -noout -out "$CERT_DIR/p256_key.pem"
openssl req -x509 -new -key "$CERT_DIR/p256_key.pem" -days 3650 \
    -out "$CERT_DIR/p256_cert.pem" \
    -subj "/CN=p256.example.com/O=Test/C=US"

# Convert to DER
openssl x509 -in "$CERT_DIR/p256_cert.pem" -outform DER -out "$CERT_DIR/p256_cert.der"
openssl pkey -in "$CERT_DIR/p256_key.pem" -outform DER -out "$CERT_DIR/p256_key.der"

# Extract SPKI
openssl x509 -in "$CERT_DIR/p256_cert.pem" -pubkey -noout > "$CERT_DIR/p256_pubkey.pem"
openssl pkey -pubin -in "$CERT_DIR/p256_pubkey.pem" -outform DER -out "$CERT_DIR/p256_spki.der"

# ============================================================================
# ECDSA P-384 certificates
# ============================================================================

# Generate ECDSA P-384 private key and certificate
openssl ecparam -name secp384r1 -genkey -noout -out "$CERT_DIR/p384_key.pem"
openssl req -x509 -new -key "$CERT_DIR/p384_key.pem" -days 3650 \
    -out "$CERT_DIR/p384_cert.pem" \
    -subj "/CN=p384.example.com/O=Test/C=US"

# Convert to DER
openssl x509 -in "$CERT_DIR/p384_cert.pem" -outform DER -out "$CERT_DIR/p384_cert.der"
openssl pkey -in "$CERT_DIR/p384_key.pem" -outform DER -out "$CERT_DIR/p384_key.der"

# Extract SPKI
openssl x509 -in "$CERT_DIR/p384_cert.pem" -pubkey -noout > "$CERT_DIR/p384_pubkey.pem"
openssl pkey -pubin -in "$CERT_DIR/p384_pubkey.pem" -outform DER -out "$CERT_DIR/p384_spki.der"

# ============================================================================
# RSA 2048-bit certificates
# ============================================================================

# Generate RSA 2048-bit private key and certificate
openssl genrsa -out "$CERT_DIR/rsa2048_key.pem" 2048
openssl req -x509 -new -key "$CERT_DIR/rsa2048_key.pem" -days 3650 \
    -out "$CERT_DIR/rsa2048_cert.pem" \
    -subj "/CN=rsa2048.example.com/O=Test/C=US"

# Convert to DER
openssl x509 -in "$CERT_DIR/rsa2048_cert.pem" -outform DER -out "$CERT_DIR/rsa2048_cert.der"
openssl pkey -in "$CERT_DIR/rsa2048_key.pem" -outform DER -out "$CERT_DIR/rsa2048_key.der"

# Extract SPKI
openssl x509 -in "$CERT_DIR/rsa2048_cert.pem" -pubkey -noout > "$CERT_DIR/rsa2048_pubkey.pem"
openssl pkey -pubin -in "$CERT_DIR/rsa2048_pubkey.pem" -outform DER -out "$CERT_DIR/rsa2048_spki.der"

# ============================================================================
# Certificate with extensions (SAN, KeyUsage, BasicConstraints, EKU)
# ============================================================================

cat > "$CERT_DIR/extensions.cnf" << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca

[req_distinguished_name]

[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:2
keyUsage = critical,digitalSignature,keyCertSign
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = DNS:test.example.com,DNS:*.example.com,DNS:localhost,IP:127.0.0.1
EOF

openssl req -x509 -new -key "$CERT_DIR/p256_key.pem" -days 3650 \
    -out "$CERT_DIR/cert_with_extensions.pem" \
    -config "$CERT_DIR/extensions.cnf" \
    -subj "/CN=test.example.com/O=Test Organization/OU=Test Unit/C=US"

openssl x509 -in "$CERT_DIR/cert_with_extensions.pem" -outform DER -out "$CERT_DIR/cert_with_extensions.der"

# ============================================================================
# Certificate chain (Root -> Intermediate -> Leaf)
# ============================================================================

# Generate Root CA
openssl genrsa -out "$CERT_DIR/root_key.pem" 2048
openssl req -x509 -new -key "$CERT_DIR/root_key.pem" -days 7300 \
    -out "$CERT_DIR/root_cert.pem" \
    -subj "/CN=Test Root CA/O=Test/C=US" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

# Generate Intermediate CA
openssl genrsa -out "$CERT_DIR/intermediate_key.pem" 2048
openssl req -new -key "$CERT_DIR/intermediate_key.pem" \
    -out "$CERT_DIR/intermediate.csr" \
    -subj "/CN=Test Intermediate CA/O=Test/C=US"

# Sign intermediate with root
openssl x509 -req -in "$CERT_DIR/intermediate.csr" \
    -CA "$CERT_DIR/root_cert.pem" -CAkey "$CERT_DIR/root_key.pem" \
    -CAcreateserial -days 3650 \
    -out "$CERT_DIR/intermediate_cert.pem" \
    -extfile <(echo "basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign")

# Generate leaf certificate
openssl genrsa -out "$CERT_DIR/leaf_key.pem" 2048
openssl req -new -key "$CERT_DIR/leaf_key.pem" \
    -out "$CERT_DIR/leaf.csr" \
    -subj "/CN=leaf.example.com/O=Test/C=US"

# Sign leaf with intermediate
openssl x509 -req -in "$CERT_DIR/leaf.csr" \
    -CA "$CERT_DIR/intermediate_cert.pem" -CAkey "$CERT_DIR/intermediate_key.pem" \
    -CAcreateserial -days 365 \
    -out "$CERT_DIR/leaf_cert.pem" \
    -extfile <(echo "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:leaf.example.com,DNS:www.example.com")

# Convert chain to DER
openssl x509 -in "$CERT_DIR/root_cert.pem" -outform DER -out "$CERT_DIR/root_cert.der"
openssl x509 -in "$CERT_DIR/intermediate_cert.pem" -outform DER -out "$CERT_DIR/intermediate_cert.der"
openssl x509 -in "$CERT_DIR/leaf_cert.pem" -outform DER -out "$CERT_DIR/leaf_cert.der"

# ============================================================================
# Expired and not-yet-valid certificates
# ============================================================================

# Expired certificate - create a cert and manually set dates
openssl req -x509 -new -key "$CERT_DIR/p256_key.pem" -days 365 \
    -out "$CERT_DIR/expired_cert.pem" \
    -subj "/CN=expired.example.com/O=Test/C=US" \
    -set_serial 1

# Modify the cert to be expired (if faketime is available, use it)
if command -v faketime &> /dev/null; then
    faketime '2020-01-01' openssl req -x509 -new -key "$CERT_DIR/p256_key.pem" -days 365 \
        -out "$CERT_DIR/expired_cert.pem" \
        -subj "/CN=expired.example.com/O=Test/C=US"
fi

openssl x509 -in "$CERT_DIR/expired_cert.pem" -outform DER -out "$CERT_DIR/expired_cert.der"

# ============================================================================
# Generate hex dumps for embedding in tests
# ============================================================================

echo "Generating hex dumps..."

for cert in "$CERT_DIR"/*.der; do
    base=$(basename "$cert" .der)
    echo "// $base" > "$CERT_DIR/${base}.hex"
    xxd -p "$cert" | tr -d '\n' >> "$CERT_DIR/${base}.hex"
    echo "" >> "$CERT_DIR/${base}.hex"
done

echo "Test certificates generated successfully in $CERT_DIR"
echo ""
echo "Summary of generated files:"
ls -la "$CERT_DIR"/*.der | wc -l
echo "DER certificates generated"
