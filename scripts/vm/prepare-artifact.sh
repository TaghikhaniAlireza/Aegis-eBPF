#!/usr/bin/env bash
# =============================================================================
# Host: copy pre-built BPF ELF + release loader into scripts/vm/artifacts/
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

DEST="$ROOT/scripts/vm/artifacts"
mkdir -p "$DEST"

echo "[prepare-artifact] workspace: $ROOT"

cargo build --release -p aegis-ebpf-loader
cp -v "$ROOT/target/release/aegis-ebpf-loader" "$DEST/"

cargo build -p aegis-ebpf

# Collect candidate BPF ELFs (exclude host binaries named aegis-ebpf under target/release).
mapfile -t CANDS < <(
  {
    find "$ROOT/target" -path '*/bpfel-unknown-none/release/aegis-ebpf' -type f 2>/dev/null || true
    find "$ROOT/target" -path '*/bpfel-unknown-none/debug/aegis-ebpf' -type f 2>/dev/null || true
    find "$ROOT/target" -path '*/build/aegis-ebpf-*/out/aegis-ebpf' -type f 2>/dev/null || true
  } | sort -u
)

if [[ ${#CANDS[@]} -eq 0 ]]; then
  echo "[prepare-artifact] ERROR: no aegis-ebpf BPF ELF found. Run: cargo build -p aegis-ebpf" >&2
  exit 1
fi

BEST=""
BEST_M=0
for f in "${CANDS[@]}"; do
  [[ -f "$f" ]] || continue
  if file "$f" 2>/dev/null | grep -q ELF; then
    :
  else
    continue
  fi
  m=$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null || echo 0)
  if (( m >= BEST_M )); then
    BEST_M=$m
    BEST=$f
  fi
done

if [[ -z "$BEST" ]]; then
  echo "[prepare-artifact] ERROR: no ELF aegis-ebpf candidates among: ${CANDS[*]}" >&2
  exit 1
fi

cp -v "$BEST" "$DEST/aegis-ebpf"
echo "[prepare-artifact] OK: $DEST/aegis-ebpf (from $BEST)"
ls -la "$DEST"
