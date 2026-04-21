#!/usr/bin/env bash
# SEC-075 test fixture generator.
#
# Writes the two DER outputs into ../security/fixtures/ because Zig 0.16
# constrains @embedFile to the test module's package path
# (tests/security/), so the embedded fixtures must live beneath that dir.
# Intermediate/temp material is written and cleaned up next to this script.
set -euo pipefail
cd "$(dirname "$0")"

OUT_DIR="../security/fixtures"
mkdir -p "$OUT_DIR"

# Shared CA
openssl genrsa -out ca.key 2048 2>/dev/null
openssl req -new -x509 -key ca.key -subj "/CN=sec075-ca" -days 3650 -out ca.crt 2>/dev/null

# Leaf key (shared across both certs)
openssl genrsa -out leaf.key 2048 2>/dev/null

# Critical=TRUE unknown ext (OID 1.3.9999.42)
cat > ext_critical.cnf <<'EOF'
[ extensions ]
1.3.9999.42=critical,ASN1:UTF8String:attacker-controlled-policy
EOF
openssl req -new -key leaf.key -subj "/CN=sec075-critical" -out leaf_crit.csr 2>/dev/null
openssl x509 -req -in leaf_crit.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out leaf_crit.crt -days 365 -extfile ext_critical.cnf -extensions extensions 2>/dev/null
openssl x509 -outform DER -in leaf_crit.crt -out "$OUT_DIR/sec075_unknown_critical_ext.der"

# Critical=FALSE (default) unknown ext
cat > ext_noncritical.cnf <<'EOF'
[ extensions ]
1.3.9999.42=ASN1:UTF8String:benign-policy
EOF
openssl req -new -key leaf.key -subj "/CN=sec075-noncrit" -out leaf_noncrit.csr 2>/dev/null
openssl x509 -req -in leaf_noncrit.csr -CA ca.crt -CAkey ca.key -CAserial ca.srl \
    -out leaf_noncrit.crt -days 365 -extfile ext_noncritical.cnf -extensions extensions 2>/dev/null
openssl x509 -outform DER -in leaf_noncrit.crt -out "$OUT_DIR/sec075_unknown_noncritical_ext.der"

rm -f ca.srl ca.crt ca.key leaf.key leaf_crit.csr leaf_noncrit.csr \
    leaf_crit.crt leaf_noncrit.crt ext_critical.cnf ext_noncritical.cnf
echo "Generated: $OUT_DIR/sec075_unknown_critical_ext.der $OUT_DIR/sec075_unknown_noncritical_ext.der"
