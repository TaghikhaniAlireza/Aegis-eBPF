# Convenience targets from the repository root (see also aegis-ebpf/Makefile).

.PHONY: rust-build rust-build-release go-test go-test-release clients-go-test build-agent build-agent-release pack-deb fmt clippy

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

build-agent-release: rust-build-release
	mkdir -p build
	cd clients/go && CGO_ENABLED=1 go build -tags aegis_static_release -o ../../build/aegis-agent ./cmd/aegis-agent

# Requires nfpm on PATH and VERSION_TAG (e.g. 0.1.0). Example: VERSION_TAG=0.1.0 make pack-deb
pack-deb: build-agent-release
	test -n "$(VERSION_TAG)" || (echo "set VERSION_TAG, e.g. VERSION_TAG=0.1.0" && false)
	VERSION_TAG=$(VERSION_TAG) nfpm package --config packaging/nfpm.yaml --packager deb --target .

fmt:
	cargo +nightly fmt --all --check

clippy:
	cargo clippy --all-targets --all-features -- -D warnings
