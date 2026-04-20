#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Regenerate the RSA-PSS differential fuzz seed corpus.
#
# Produces 5 seed files covering SHA-256/SHA-384 valid triples at 2048-/3072-bit
# moduli plus one corrupted-signature negative case. Writes the binary layout
# expected by `tests/fuzz/rsa_pss_verify.zig`:
#
#   offset  0: u8   hash_id        (0 = sha256, 1 = sha384)
#   offset  1: u16  spki_len       (big-endian)
#   offset  3: [spki_len]  pubkey_spki_der
#   offset  3+spki_len: u16 msg_len (big-endian)
#   ...:  [msg_len]   msg
#   ...:  u16 sig_len (big-endian)
#   ...:  [sig_len]   signature
#
# NOTE: RSA-PSS signatures incorporate a random salt; output is NOT byte-
# identical across runs. Regenerating refreshes the corpus and invalidates
# the previous committed binaries. Commit the updated .bin files after
# running this script.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../../.." && pwd)"
certs="$repo/tests/test_certs"

# The 2048-bit key ships in-repo (test_certs/rsa2048_key.pem). The 3072-bit
# key does NOT ship in-repo because upstream GitLab's pre-receive hook
# rejects *.pem/*.key additions. Generate it locally into a transient file
# under /tmp for seed generation, then discard -- the committed artifacts
# are the SPKI (test_certs/rsa3072_spki.der) + the RSA-PSS signatures
# embedded inside the .bin seeds. Regenerating the key produces byte-
# different signatures but functionally-equivalent seeds (the SPKI stays
# identical, so the verification oracle still works).
rsa3072_key="$(mktemp --suffix=.pem)"
trap 'rm -f "$rsa3072_key"' EXIT
if [ ! -s "$certs/rsa3072_spki.der" ]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
        -out "$rsa3072_key" >/dev/null 2>&1
    openssl pkey -in "$rsa3072_key" -pubout -outform DER \
        -out "$certs/rsa3072_spki.der" >/dev/null 2>&1
else
    # Recover the private key material from the committed SPKI? Impossible.
    # The signatures embedded in the committed .bin seeds are bound to the
    # private key that produced the committed rsa3072_spki.der. To refresh
    # signatures we must regenerate both the key AND the SPKI together.
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
        -out "$rsa3072_key" >/dev/null 2>&1
    openssl pkey -in "$rsa3072_key" -pubout -outform DER \
        -out "$certs/rsa3072_spki.der" >/dev/null 2>&1
fi

python3 - "$here" "$certs" "$rsa3072_key" <<'PY'
import pathlib, struct, subprocess, sys, tempfile

here = pathlib.Path(sys.argv[1])
certs = pathlib.Path(sys.argv[2])
rsa3072_key = pathlib.Path(sys.argv[3])

RSA2048_KEY = certs / "rsa2048_key.pem"
RSA2048_SPKI = certs / "rsa2048_spki.der"
RSA3072_KEY = rsa3072_key
RSA3072_SPKI = certs / "rsa3072_spki.der"

MESSAGE = b"GAP-0109 RSA-PSS differential fuzz seed"


def sign_pss(key_pem: pathlib.Path, digest: str, message: bytes) -> bytes:
    """Generate an RSA-PSS signature via openssl CLI."""
    with tempfile.NamedTemporaryFile(delete=False) as msgf, \
         tempfile.NamedTemporaryFile(delete=False) as sigf:
        msgf.write(message)
        msgf.flush()
        subprocess.check_call([
            "openssl", "dgst",
            f"-{digest}",
            "-sign", str(key_pem),
            "-sigopt", "rsa_padding_mode:pss",
            "-sigopt", "rsa_pss_saltlen:digest",
            "-out", sigf.name,
            msgf.name,
        ])
        return pathlib.Path(sigf.name).read_bytes()


def seed(hash_id: int, spki: bytes, msg: bytes, sig: bytes) -> bytes:
    out = bytearray()
    out += bytes([hash_id])
    out += struct.pack(">H", len(spki)) + spki
    out += struct.pack(">H", len(msg)) + msg
    out += struct.pack(">H", len(sig)) + sig
    return bytes(out)


def write(name: str, data: bytes) -> None:
    (here / name).write_bytes(data)


# Valid SHA-256 + 2048-bit modulus
sig = sign_pss(RSA2048_KEY, "sha256", MESSAGE)
write("sha256_valid_2048.bin",
      seed(0, RSA2048_SPKI.read_bytes(), MESSAGE, sig))

# Valid SHA-256 + 3072-bit modulus
sig = sign_pss(RSA3072_KEY, "sha256", MESSAGE)
write("sha256_valid_3072.bin",
      seed(0, RSA3072_SPKI.read_bytes(), MESSAGE, sig))

# Valid SHA-384 + 2048-bit modulus
sig = sign_pss(RSA2048_KEY, "sha384", MESSAGE)
write("sha384_valid_2048.bin",
      seed(1, RSA2048_SPKI.read_bytes(), MESSAGE, sig))

# Valid SHA-384 + 3072-bit modulus
sig = sign_pss(RSA3072_KEY, "sha384", MESSAGE)
write("sha384_valid_3072.bin",
      seed(1, RSA3072_SPKI.read_bytes(), MESSAGE, sig))

# Corrupted: valid SHA-256 + 2048-bit sig with one flipped byte mid-sig.
sig = bytearray(sign_pss(RSA2048_KEY, "sha256", MESSAGE))
sig[len(sig) // 2] ^= 0x01
write("sha256_corrupt.bin",
      seed(0, RSA2048_SPKI.read_bytes(), MESSAGE, bytes(sig)))

print(f"wrote seeds under {here}")
PY
