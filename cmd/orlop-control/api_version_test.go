package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIVersionHeaderSet(t *testing.T) {
	h := apiVersionHeader(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/entities/agent/x", nil))

	if got := rec.Header().Get("Orlop-API-Version"); got != apiVersion {
		t.Fatalf("Orlop-API-Version = %q, want %q", got, apiVersion)
	}
}
