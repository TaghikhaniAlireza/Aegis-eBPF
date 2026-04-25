#!/usr/bin/env bash
# eBPF integration tests need root (`sudo`). Miri test binaries live under `target/miri/` and must
# be executed via `cargo-miri runner` (not sudo).
set -euo pipefail
if [[ -n "${MIRI_SYSROOT:-}" || "${1:-}" == *"/target/miri/"* || "${1:-}" == *"/target\\miri\\"* ]]; then
  exec cargo-miri runner "$@"
fi
exec sudo -E "$@"
