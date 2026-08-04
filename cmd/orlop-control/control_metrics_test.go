package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

func TestControlMetricsUsesRoutePatternsAndClassifiesOutcomes(t *testing.T) {
	m := newControlMetrics()
	r := chi.NewRouter()
	r.Use(m.middleware)
	r.Get("/v1/entities/{type}/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	r.Post("/agent/enroll", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Outcome") != "" {
			setControlOutcome(r, r.Header.Get("X-Test-Outcome"))
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/entities/agent/secret-agent-id", nil))
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agent/enroll", nil))
	overridden := httptest.NewRequest(http.MethodPost, "/agent/enroll", nil)
	overridden.Header.Set("X-Test-Outcome", "no_capacity")
	r.ServeHTTP(httptest.NewRecorder(), overridden)

	body := scrapeControlMetrics(t, m)
	for _, want := range []string{
		`orlop_control_requests_total{method="GET",route="/v1/entities/{type}/{id}",status="404"} 1`,
		`orlop_enroll_total{outcome="retryable_error"} 1`,
		`orlop_enroll_total{outcome="no_capacity"} 1`,
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

type fakeCapacityMetricsStore struct {
	pools   []storage.ServerPoolCapacity
	pending int64
}

func (f *fakeCapacityMetricsStore) ListServerPoolCapacity(context.Context) ([]storage.ServerPoolCapacity, error) {
	return append([]storage.ServerPoolCapacity(nil), f.pools...), nil
}

func (f *fakeCapacityMetricsStore) CountPurgePendingAllocations(context.Context) (int64, error) {
	return f.pending, nil
}

func TestControlMetricsCapacityGaugesReadCurrentStoreState(t *testing.T) {
	serverID := uuid.MustParse("4aee1e96-9348-465c-82d7-3d950a09d0a9")
	store := &fakeCapacityMetricsStore{
		pools: []storage.ServerPoolCapacity{{
			ServerID: serverID, TotalBytes: 8192, FreeBytes: 4096,
		}},
		pending: 3,
	}
	m := newControlMetrics()
	m.setCapacityStore(store)

	body := scrapeControlMetrics(t, m)
	for _, want := range []string{
		`orlop_server_pool_free_bytes{server_id="4aee1e96-9348-465c-82d7-3d950a09d0a9"} 4096`,
		`orlop_server_pool_total_bytes{server_id="4aee1e96-9348-465c-82d7-3d950a09d0a9"} 8192`,
		`orlop_allocations_purge_pending 3`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in metrics:\n%s", want, body)
		}
	}

	// A later scrape must query storage again rather than retain process-local
	// values that drift after an out-of-band purge or allocator update.
	store.pools[0].FreeBytes = 6144
	store.pending = 0
	body = scrapeControlMetrics(t, m)
	if !strings.Contains(body, `orlop_server_pool_free_bytes{server_id="4aee1e96-9348-465c-82d7-3d950a09d0a9"} 6144`) ||
		!strings.Contains(body, `orlop_allocations_purge_pending 0`) {
		t.Fatalf("capacity gauges did not refresh from storage:\n%s", body)
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
