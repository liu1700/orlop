#!/usr/bin/env bash
#
# Host-side runner: build the pjdfstest rig image and execute
# scripts/pjdfstest-rig.sh inside a FUSE-capable privileged container.
# Works on macOS (Docker Desktop) and Linux.
#
#   scripts/pjdfstest-docker.sh                # full suite
#   PJDFS_TESTS=rename scripts/pjdfstest-docker.sh   # one category
#
# Results land in pjdfstest-results/ on the host.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT_DIR/../.." && pwd)"
IMAGE="${PJDFS_IMAGE:-orlop-pjdfstest-rig:latest}"
RESULTS_HOST_DIR="${RESULTS_HOST_DIR:-$ROOT_DIR/pjdfstest-results}"

mkdir -p "$RESULTS_HOST_DIR"

echo "==> Building runner image $IMAGE"
docker build -f "$ROOT_DIR/scripts/pjdfstest.Dockerfile" -t "$IMAGE" "$ROOT_DIR/scripts"

echo "==> Running rig (results -> $RESULTS_HOST_DIR)"
docker run --rm \
  --device /dev/fuse \
  --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined \
  -v "$REPO_ROOT:/src" \
  -v orlop-pjdfs-cargo-registry:/usr/local/cargo/registry \
  -v orlop-pjdfs-cargo-target:/build/target \
  -v orlop-pjdfs-gocache:/root/.cache/go-build \
  -v orlop-pjdfs-gomod:/root/go/pkg/mod \
  -v "$RESULTS_HOST_DIR:/results" \
  -e CARGO_TARGET_DIR=/build/target \
  -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" \
  -e ORLOP_BIN=/build/target/release/orlop \
  -e RESULTS_DIR=/results \
  -e PJDFS_TESTS="${PJDFS_TESTS:-}" \
  -e PJDFS_FS="${PJDFS_FS:-ext4}" \
  "$IMAGE" \
  bash scripts/pjdfstest-rig.sh
