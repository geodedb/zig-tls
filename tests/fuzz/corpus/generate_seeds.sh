#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Regenerate fuzz seed corpus files from a Python specification.
# Deterministic: running twice produces byte-identical output.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"

python3 - "$here" <<'PY'
import pathlib, struct, sys

here = pathlib.Path(sys.argv[1])

def build_ch(bad_alg: int) -> bytes:
    body = bytearray()
    body += b'\x03\x03'                               # legacy_version
    body += b'\xAA' * 32                              # random
    body += b'\x00'                                   # session_id (len 0)
    body += b'\x00\x02\x13\x01'                       # cipher_suites (TLS_AES_128_GCM_SHA256)
    body += b'\x01\x00'                               # compression_methods

    ext = bytearray()
    # signature_algorithms ext (0x000d): list of [bad_alg, ed25519]
    ext += b'\x00\x0d\x00\x06\x00\x04'
    ext += struct.pack('>H', bad_alg)
    ext += b'\x08\x07'                                # ed25519
    # supported_versions
    ext += b'\x00\x2b\x00\x03\x02\x03\x04'
    # supported_groups
    ext += b'\x00\x0a\x00\x04\x00\x02\x00\x1d'
    # key_share x25519 + 32 bytes
    ext += b'\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20' + b'\x01' * 32

    body += struct.pack('>H', len(ext)) + bytes(ext)
    return bytes(body)

ch = here / 'client_hello'
ch.mkdir(parents=True, exist_ok=True)
(ch / 'sec057_0x0402.bin').write_bytes(build_ch(0x0402))
(ch / 'sec057_0x0500.bin').write_bytes(build_ch(0x0500))
(ch / 'sec057_0x0701.bin').write_bytes(build_ch(0x0701))

tp = here / 'quic_tp'
tp.mkdir(parents=True, exist_ok=True)
# TP: id=1 (1-byte varint), length = 2^32 (8-byte varint), no value bytes.
(tp / 'sec058_length_overflow.bin').write_bytes(
    bytes([0x01, 0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
)

print(f'wrote seeds under {ch} and {tp}')
PY
