# Fuzz corpus — seed inputs

This directory contains seed inputs for `zig build test --fuzz`. Each file
is a raw wire-format payload for one parser entrypoint.

## Layout

- `client_hello/` — seeds for `parseClientHello`
- `quic_tp/` — seeds for `TransportParameters.decode`

## Naming

`<sec_id>_<short_description>.bin` — one seed per historical regression,
so the fuzzer immediately re-checks every previously-fixed input class.

## Regenerating

Run `bash tests/fuzz/corpus/generate_seeds.sh` to rebuild all seed files
from the Python generator.

## Adding new seeds

When you fix a parser bug, add the trigger input here. Commit the
binary. CI picks it up on the next `fuzz` job (see `.gitlab-ci.yml`).
