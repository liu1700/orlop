package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func TestControlMetricsUsesRoutePatternsAndClassifiesOutcomes(t *testing.T) {
	m := newControlMetrics()
	r := chi.NewRouter()
	r.Use(m.middleware)
	r.Get("/v1/entities/{type}/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	r.Post("/agent/enroll", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/entities/agent/secret-agent-id", nil))
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agent/enroll", nil))

	body := scrapeControlMetrics(t, m)
	for _, want := range []string{
		`orlop_control_requests_total{method="GET",route="/v1/entities/{type}/{id}",status="404"} 1`,
		`orlop_enroll_total{outcome="retryable_error"} 1`,
		`orlop_control_build_info{version="`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in metrics:\n%s", want, body)
		}
	}
	if strings.Contains(body, "secret-agent-id") {
		t.Fatalf("metrics leaked a concrete path into a label:\n%s", body)
	}
}

func TestControlMetricsCAExpiry(t *testing.T) {
	m := newControlMetrics()
	m.setCAExpiry("root", time.Unix(2_000_000_000, 0))
	body := scrapeControlMetrics(t, m)
	if !strings.Contains(body, `orlop_ca_cert_expiry_timestamp_seconds{kind="root"} 2e+09`) {
		t.Fatalf("missing CA expiry gauge:\n%s", body)
	}
}

func TestNewRouterExposesRequestMetricsOnlyOnPrivateRegistry(t *testing.T) {
	m := newControlMetrics()
	h := newRouter(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		runtimeDeps{metrics: m},
		config{},
	)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if body := scrapeControlMetrics(t, m); !strings.Contains(body, `route="/healthz"`) {
		t.Fatalf("health request was not observed:\n%s", body)
	}
}

func scrapeControlMetrics(t *testing.T, m *controlMetrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics status = %d", rec.Code)
	}
	return rec.Body.String()
}
