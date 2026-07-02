package main

import "net/http"

// apiVersion is the control-plane HTTP API's major version (the /v1 path
// prefix). Independent of the orlop release version; bumps only on breaking API
// changes. Sent as the Orlop-API-Version header on every response so clients
// can detect version skew explicitly rather than inferring it from opaque 4xxs.
const apiVersion = "1"

// apiVersionHeader sets Orlop-API-Version on every response.
func apiVersionHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Orlop-API-Version", apiVersion)
		next.ServeHTTP(w, r)
	})
}
