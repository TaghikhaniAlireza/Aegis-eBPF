#!/usr/bin/env bash
# =============================================================================
# Minimal guest packages for eBPF loader smoke tests
# =============================================================================
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y --no-install-recommends ca-certificates curl kmod
fi

echo "[provision-common] VM=${AEGIS_VM_NAME:-unknown}"
echo "[provision-common] ${AEGIS_KERNEL_NOTE:-}"
uname -a
