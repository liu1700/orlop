# orlop (mount client): the disk-mount binary with FUSE available at runtime.
#
# This is the image that saves consumers the Rust toolchain build the mount
# client otherwise needs. It carries the static, release-versioned
# `orlop` binary on a slim Debian base with the fusermount3 helper. The binary
# uses fuser's pure-Linux backend and does not link libfuse3.so, so consumers
# may also COPY it into a different Linux base. Build context is docker/; the
# per-arch binary is staged at bin/<arch>/ by release.yml.
#
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f docker/mount.Dockerfile -t ghcr.io/liu1700/orlop-mount:vX.Y.Z docker/
#
# Runtime contract (see docs/container-images.md):
#   Mount : needs /dev/fuse and CAP_SYS_ADMIN (FUSE mounts). On Kubernetes:
#           securityContext.capabilities.add: ["SYS_ADMIN"] + a /dev/fuse device.
#   Env   : ORLOP_TOKEN (or a mounted credentials/secrets dir), ORLOP_CONTROL_URL,
#           ORLOP_MOUNT_POINT — see `orlop --help` / docs/agent-memory.md.
#   Entry : the bare binary; pass a subcommand, e.g. `orlop mount …` or
#           `orlop --from-env`.

FROM debian:trixie-slim

# fuse3 provides fusermount3 for unprivileged mounts; ca-certificates is for
# control-plane HTTPS. libfuse is not a binary dependency.
RUN apt-get update && \
    apt-get install -y --no-install-recommends fuse3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
COPY bin/${TARGETARCH}/orlop /usr/local/bin/orlop

RUN orlop --version

ENTRYPOINT ["orlop"]
