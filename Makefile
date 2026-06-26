.PHONY: setup setup-go setup-rust control-dev bench bench-clean

# One-shot dev environment setup. Installs OS deps and pre-fetches each side's
# dependencies. Most contributors only touch one side — run `make setup-go` or
# `make setup-rust` for just that half (see CONTRIBUTING.md). `make setup` does
# both.
setup: setup-go setup-rust
	@echo "✓ setup complete — see CONTRIBUTING.md for build/test commands"

setup-go:
	@command -v go >/dev/null 2>&1 || { \
		echo "✗ Go not found. Install the version in go.mod (https://go.dev/dl/)"; exit 1; }
	@echo "→ Go $$(go version | awk '{print $$3}') detected; fetching modules"
	@GOWORK=off go mod download
	@echo "✓ Go side ready: GOWORK=off go build ./... && go test ./..."

setup-rust:
	@command -v cargo >/dev/null 2>&1 || { \
		echo "✗ Rust not found. Install via https://rustup.rs"; exit 1; }
	@echo "→ $$(cargo --version) detected"
	@if [ "$$(uname -s)" = "Linux" ]; then \
		if ! pkg-config --exists fuse3 2>/dev/null; then \
			echo "→ installing libfuse3-dev + pkg-config (Linux mount client links libfuse3)"; \
			if command -v apt-get >/dev/null 2>&1; then \
				sudo apt-get update || echo "  (apt-get update had errors — continuing; unrelated repos may be broken)"; \
				sudo apt-get install -y libfuse3-dev pkg-config; \
			else \
				echo "✗ install libfuse3 dev headers + pkg-config with your package manager, then re-run"; exit 1; \
			fi; \
		else echo "→ libfuse3 already present"; fi; \
	else echo "→ non-Linux host: mount client uses the in-process NFS path, no FUSE headers needed"; fi
	@cargo fetch --locked
	@echo "✓ Rust side ready: cargo build --locked && cargo test --locked"

control-dev:
	@set -a; \
	if [ -f .env ]; then . ./.env; fi; \
	set +a; \
	go run ./cmd/orlop-control

# Run the data-plane benchmark harness.
# Defaults to driving workloads against a tmp directory — that measures the
# host filesystem, used as a smoke-test for the harness pipeline. Point
# ORLOP_BENCH_MOUNT at a real orlop mount to measure orlop. BENCH_LABEL/
# BENCH_DATA_PLANE/BENCH_WORKLOADS are passed through as run metadata.
bench:
	@cargo build --release -p orlop-bench
	@mkdir -p bench-results
	@MOUNT="$${ORLOP_BENCH_MOUNT:-/tmp/orlop-bench-mnt}"; \
	mkdir -p "$$MOUNT"; \
	SHA="$$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"; \
	OUT="bench-results/$$SHA$${BENCH_SUFFIX:+-$$BENCH_SUFFIX}.json"; \
	ARGS="--mount $$MOUNT --out $$OUT"; \
	if [ -n "$$BENCH_LABEL" ]; then ARGS="$$ARGS --label $$BENCH_LABEL"; fi; \
	if [ -n "$$BENCH_DATA_PLANE" ]; then ARGS="$$ARGS --data-plane $$BENCH_DATA_PLANE"; fi; \
	if [ -n "$$BENCH_WORKLOADS" ]; then ARGS="$$ARGS --workloads $$BENCH_WORKLOADS"; fi; \
	echo "Running orlop-bench against $$MOUNT → $$OUT"; \
	./target/release/orlop-bench $$ARGS

bench-clean:
	find bench-results -maxdepth 1 -name '*.json' -delete 2>/dev/null || true
	rm -rf /tmp/orlop-bench-mnt
