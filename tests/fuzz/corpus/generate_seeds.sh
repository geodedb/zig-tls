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

# ----------------------------------------------------------------------
# SEC-058: existing length-overflow seed (kept, byte-identical).
# TP: id=1 (1-byte varint), length = 2^32 (8-byte varint), no value bytes.
# ----------------------------------------------------------------------
(tp / 'sec058_length_overflow.bin').write_bytes(
    bytes([0x01, 0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
)

# ----------------------------------------------------------------------
# SEC-062: QUIC transport-parameter fuzz corpus expansion.
#
# Each seed is <= 256 bytes and covers one of:
#   - happy-path encoding for each known param ID (RFC 9000 §18.2)
#   - varint boundary values (max 2^62-1, zero-length, duplicates)
#   - GREASE IDs (31N+27 per RFC 9000 §18.1)
#   - malformed preferred_address layouts
#   - extra length-overflow variants on different IDs
# ----------------------------------------------------------------------

def vi(n: int) -> bytes:
    """Encode QUIC varint (RFC 9000 §16)."""
    if n < 1 << 6:
        return bytes([n])
    if n < 1 << 14:
        return bytes([0x40 | ((n >> 8) & 0x3F), n & 0xFF])
    if n < 1 << 30:
        return bytes([0x80 | ((n >> 24) & 0x3F),
                      (n >> 16) & 0xFF,
                      (n >> 8) & 0xFF,
                      n & 0xFF])
    if n < 1 << 62:
        return bytes([0xC0 | ((n >> 56) & 0x3F),
                      (n >> 48) & 0xFF,
                      (n >> 40) & 0xFF,
                      (n >> 32) & 0xFF,
                      (n >> 24) & 0xFF,
                      (n >> 16) & 0xFF,
                      (n >> 8) & 0xFF,
                      n & 0xFF])
    raise OverflowError('varint out of range')

def tp_entry(pid: int, value: bytes) -> bytes:
    return vi(pid) + vi(len(value)) + value

# Happy-path seeds, one per known param ID (RFC 9000 §18.2).
happy = {
    0x00: b'\x01' * 8,                    # original_destination_connection_id
    0x01: vi(30_000),                     # max_idle_timeout (30s)
    0x02: b'\xAA' * 16,                   # stateless_reset_token (16B)
    0x03: vi(1200),                       # max_udp_payload_size
    0x04: vi(1 << 20),                    # initial_max_data
    0x05: vi(1 << 18),                    # initial_max_stream_data_bidi_local
    0x06: vi(1 << 18),                    # initial_max_stream_data_bidi_remote
    0x07: vi(1 << 18),                    # initial_max_stream_data_uni
    0x08: vi(100),                        # initial_max_streams_bidi
    0x09: vi(100),                        # initial_max_streams_uni
    0x0A: vi(3),                          # ack_delay_exponent
    0x0B: vi(25),                         # max_ack_delay
    0x0C: b'',                            # disable_active_migration (flag)
    0x0E: vi(8),                          # active_connection_id_limit
    0x0F: b'\x02' * 8,                    # initial_source_connection_id
    0x10: b'\x03' * 8,                    # retry_source_connection_id
}
for pid, value in happy.items():
    (tp / f'sec062_happy_{pid:#04x}.bin').write_bytes(tp_entry(pid, value))

# Max-varint value on initial_max_data (RFC 9000 varint ceiling).
max_varint = (1 << 62) - 1
(tp / 'sec062_max_varint_initial_max_data.bin').write_bytes(
    tp_entry(0x04, vi(max_varint))
)

# Zero-length value on a variable-length ID that must reject empty.
(tp / 'sec062_zero_length_reset_token.bin').write_bytes(
    tp_entry(0x02, b'')
)

# Duplicate IDs (RFC 9000 §18 forbids duplicates).
(tp / 'sec062_duplicate_initial_max_data.bin').write_bytes(
    tp_entry(0x04, vi(1024)) + tp_entry(0x04, vi(2048))
)

# GREASE IDs (31N+27): 27, 58, 89, and 27 + 31*1000.
for k in (0, 1, 2, 1000):
    grease_id = 31 * k + 27
    (tp / f'sec062_grease_{grease_id:x}.bin').write_bytes(
        tp_entry(grease_id, b'\xDE\xAD\xBE\xEF')
    )

# Extra length-overflow variant — initial_max_streams_bidi claims 2^32 bytes.
(tp / 'sec062_length_overflow_max_streams_bidi.bin').write_bytes(
    vi(0x08) + bytes([0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
)

# Malformed preferred_address (id=0x0D).
# Legal layout: 4B ipv4 + 2B port + 16B ipv6 + 2B port + 1B cid_len + cid + 16B reset_token
# Variant 1: cid_len claims 255 but only 4 bytes follow.
truncated_pa = (
    b'\x01\x02\x03\x04'                    # ipv4
    + b'\x01\xBB'                          # port
    + b'\x20\x01' + b'\x00' * 14           # ipv6
    + b'\x01\xBB'                          # port
    + b'\xFF'                              # cid_len (claims 255)
    + b'\x11' * 4                          # only 4B follow
    + b'\xCC' * 16                         # reset_token
)
(tp / 'sec062_preferred_address_truncated.bin').write_bytes(
    tp_entry(0x0D, truncated_pa)
)

# Variant 2: Total body shorter than fixed fields require.
short_pa = b'\x01\x02\x03\x04' + b'\x01\xBB'  # only ipv4+port
(tp / 'sec062_preferred_address_short.bin').write_bytes(
    tp_entry(0x0D, short_pa)
)

print(f'wrote seeds under {ch} and {tp}')
PY
