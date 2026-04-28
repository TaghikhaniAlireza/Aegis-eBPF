# Convenience targets from the repository root (see also aegis-ebpf/Makefile).

.PHONY: rust-build rust-build-release go-test go-test-release clients-go-test build-agent fmt clippy

rust-build:
	cargo build -p aegis-ebpf

rust-build-release:
	cargo build --release -p aegis-ebpf

# Go SDK in-tree (static debug lib); requires CGO + same libc as Rust build.
go-test: rust-build
	cd aegis-ebpf/pkg/aegis && CGO_ENABLED=1 go test -race -v ./...

go-test-release: rust-build-release
	cd aegis-ebpf/pkg/aegis && CGO_ENABLED=1 go test -race -v -tags aegis_static_release ./...

clients-go-test: rust-build
	cd clients/go/aegis && CGO_ENABLED=1 go test -race -v ./...

# Standalone agent (CGO + static Rust lib from debug build).
build-agent: rust-build
	mkdir -p build
	cd clients/go && CGO_ENABLED=1 go build -o ../../build/aegis-agent ./cmd/aegis-agent

fmt:
	cargo +nightly fmt --all --check

clippy:
	cargo clippy --all-targets --all-features -- -D warnings
