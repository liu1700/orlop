package main

import "net/http"

// apiVersion is the major version of the control-plane HTTP API — the contract
// the Go SDK (and any other client) is written against. It is independent of the
// orlop release version: the API was byte-identical across v0.1.0 and v0.2.0, so
// it stays "1" until a breaking API change. The `/v1/...` path prefix carries
// the same number.
//
// It is advertised on every response as the Orlop-API-Version header so a client
// can DETECT version skew explicitly, instead of inferring it from an opaque 4xx.
// See docs/control-plane.md and docs/openapi/orlop-control.yaml.
const apiVersion = "1"

// apiVersionHeader sets Orlop-API-Version on every response.
func apiVersionHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Orlop-API-Version", apiVersion)
		next.ServeHTTP(w, r)
	})
}
