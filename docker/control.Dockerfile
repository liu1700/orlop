# orlop-control: the control-plane HTTP API + operator CLI.
#
# Packages the pre-built, release-versioned binary (built natively per-arch in
# release.yml) onto a distroless static base — the Go binaries are pure-Go
# (CGO_ENABLED=0), so no libc or shell is needed at runtime. Build context is
# docker/, and the per-arch binary is staged at bin/<arch>/ by the release job:
#
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f docker/control.Dockerfile -t ghcr.io/liu1700/orlop-control:vX.Y.Z docker/
#
# Runtime contract (see docs/container-images.md):
#   Port  : 8080 (HTTP control API; override with PORT)
#   Env   : DATABASE_URL (postgres://… or sqlite:/data/orlop.db),
#           ORLOP_CONTROL_PLANE_TOKEN, ORLOP_DATAGW_SERVER_FQDN, ORLOP_SECRETS_DIR
#           (filesystem CA backend) or ORLOP_SECRETS_BACKEND=postgres, ORLOP_*
#   State : with Postgres + ORLOP_SECRETS_BACKEND=postgres the container is
#           stateless; with SQLite or the filesystem CA backend, mount a writable
#           volume (owned by uid 65532) for the DB file and ORLOP_SECRETS_DIR.
#   Migrate: `migrate` is a subcommand of this same binary — run
#            `orlop-control migrate up` (e.g. an initContainer) before serving.

FROM gcr.io/distroless/static:nonroot

ARG TARGETARCH
COPY bin/${TARGETARCH}/orlop-control /usr/local/bin/orlop-control

EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["orlop-control"]
