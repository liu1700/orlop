.PHONY: control-dev bench bench-clean

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
