#!/usr/bin/env bash
# Phase 1.2: Miri + AddressSanitizer for `aegis-ebpf` (userspace / FFI).
# Requires nightly with `miri` and `llvm-tools-preview` components.
set -euo pipefail
cd "$(dirname "$0")"

echo "==> Ensure nightly components (idempotent)"
rustup component add miri llvm-tools-preview --toolchain nightly-x86_64-unknown-linux-gnu 2>/dev/null || \
  rustup component add miri llvm-tools-preview --toolchain nightly

echo "==> One normal build of aegis-ebpf (produces target/*/build/aegis-ebpf-*/out/aegis-ebpf for Miri/ASAN build.rs)"
cargo build -p aegis-ebpf

echo "==> cargo +nightly miri setup"
cargo +nightly miri setup

echo "==> Miri: FFI tests"
cargo +nightly miri test -p aegis-ebpf ffi

echo "==> Miri: arena / ring buffer tests"
cargo +nightly miri test -p aegis-ebpf arena

echo "==> ASAN: full aegis-ebpf lib test suite"
RUSTFLAGS="-Zsanitizer=address" cargo +nightly test -p aegis-ebpf --lib --target x86_64-unknown-linux-gnu

echo "==> Memory checks finished successfully."
