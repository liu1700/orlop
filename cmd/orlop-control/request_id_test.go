package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
)

func TestRequestLoggerReturnsRequestIDHeader(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := middleware.RequestID(requestLogger(logger)(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		},
	)))
	req := httptest.NewRequest(http.MethodGet, "/v1/entities/agent/a", nil)
	req.Header.Set("X-Request-ID", "req-from-caller")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-ID"); got != "req-from-caller" {
		t.Fatalf("X-Request-ID = %q; want req-from-caller", got)
	}
}
