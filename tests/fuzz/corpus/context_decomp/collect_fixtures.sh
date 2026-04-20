#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024-2026 CodePros
#
# QUAL-317 Task 1: Collect handshake fixture inputs from the existing fuzz
# corpora (client_hello/, quic_tp/, rsa_pss/) into tests/fuzz/corpus/
# context_decomp/ so the context_decomp_trace_capture executable can drive
# Context.processCrypto across all of them in a single sorted pass.
#
# Idempotent: re-running overwrites existing copies with `cp -f` and only
# processes .bin files (skipping README.md / generate_seeds.sh).
#
# Usage: bash tests/fuzz/corpus/context_decomp/collect_fixtures.sh
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
mkdir -p "$HERE"
for src in client_hello quic_tp rsa_pss; do
    if [ -d "$HERE/../$src" ]; then
        for f in "$HERE/../$src"/*.bin; do
            [ -f "$f" ] || continue
            cp -f "$f" "$HERE/${src}_$(basename "$f")"
        done
    fi
done
