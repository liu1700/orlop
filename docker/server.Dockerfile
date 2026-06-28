# orlop-server: the data-plane server (ops + data planes, mTLS).
#
# Same shape as control.Dockerfile: a pre-built, release-versioned pure-Go
# binary on distroless static. Build context is docker/; the per-arch binary is
# staged at bin/<arch>/ by release.yml.
#
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f docker/server.Dockerfile -t ghcr.io/liu1700/orlop-server:vX.Y.Z docker/
#
# Runtime contract (see docs/container-images.md):
#   Ports : 7878 (ops/HTTPS, server.ops_bind), 8443 (data/mTLS, server.data_bind)
#   Config: requires a YAML config via `-config`; the default CMD reads
#           /etc/orlop/server.yaml, so mount your config there (ConfigMap).
#   Env   : ORLOP_DATAGW_SERVICE_TOKEN (must equal the control plane's
#           ORLOP_CONTROL_PLANE_TOKEN), ORLOP_JFS_META_URL (juicefs quota), ORLOP_*
#   State : object store + routes DB live under the paths named in the config
#           (store.root, routes.path, tenants_root) — back them with a volume.
#   TLS   : with tls.self_provision the server fetches its leaf cert and the
#           client CA from the control plane; tls.fqdn must match the cert SAN /
#           Service name or the server exits with fqdn_not_allowed.

FROM gcr.io/distroless/static:nonroot

ARG TARGETARCH
COPY bin/${TARGETARCH}/orlop-server /usr/local/bin/orlop-server

EXPOSE 7878 8443
USER nonroot:nonroot
ENTRYPOINT ["orlop-server"]
CMD ["-config", "/etc/orlop/server.yaml"]
