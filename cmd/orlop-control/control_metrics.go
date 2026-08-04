package main

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
	"github.com/liu1700/orlop/internal/buildinfo"
)

const capacityMetricsCollectTimeout = 3 * time.Second

// capacityMetricsCollector reads allocator state at scrape time. Gauges must
// reflect the database after restarts and out-of-band repairs; incrementing
// process-local values on request paths would silently drift.
type capacityMetricsCollector struct {
	mu      sync.RWMutex
	store   storage.CapacityMetricsStore
	free    *prometheus.Desc
	total   *prometheus.Desc
	pending *prometheus.Desc
}

func newCapacityMetricsCollector() *capacityMetricsCollector {
	return &capacityMetricsCollector{
		free: prometheus.NewDesc(
			"orlop_server_pool_free_bytes",
			"Unreserved bytes remaining in a server allocation pool.",
			[]string{"server_id"}, nil),
		total: prometheus.NewDesc(
			"orlop_server_pool_total_bytes",
			"Total bytes managed by a server allocation pool.",
			[]string{"server_id"}, nil),
		pending: prometheus.NewDesc(
			"orlop_allocations_purge_pending",
			"Revoked allocations whose durable purge has not completed.",
			nil, nil),
	}
}

func (c *capacityMetricsCollector) setStore(store storage.CapacityMetricsStore) {
	c.mu.Lock()
	c.store = store
	c.mu.Unlock()
}

func (c *capacityMetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.free
	ch <- c.total
	ch <- c.pending
}

func (c *capacityMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	store := c.store
	c.mu.RUnlock()
	if store == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), capacityMetricsCollectTimeout)
	defer cancel()
	pools, err := store.ListServerPoolCapacity(ctx)
	if err != nil {
		ch <- prometheus.NewInvalidMetric(c.free, err)
		return
	}
	for _, pool := range pools {
		serverID := pool.ServerID.String()
		ch <- prometheus.MustNewConstMetric(c.free, prometheus.GaugeValue, float64(pool.FreeBytes), serverID)
		ch <- prometheus.MustNewConstMetric(c.total, prometheus.GaugeValue, float64(pool.TotalBytes), serverID)
	}
	pending, err := store.CountPurgePendingAllocations(ctx)
	if err != nil {
		ch <- prometheus.NewInvalidMetric(c.pending, err)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.pending, prometheus.GaugeValue, float64(pending))
}

// controlMetrics owns a private registry so tests and multiple in-process
// control planes never collide through prometheus.DefaultRegisterer.
type controlMetrics struct {
	registry        *prometheus.Registry
	requestDuration *prometheus.HistogramVec
	requests        *prometheus.CounterVec
	enroll          *prometheus.CounterVec
	certMint        *prometheus.CounterVec
	alloc           *prometheus.CounterVec
	caExpiry        *prometheus.GaugeVec
	capacity        *capacityMetricsCollector
}

func newControlMetrics() *controlMetrics {
	capacity := newCapacityMetricsCollector()
	m := &controlMetrics{
		registry: prometheus.NewRegistry(),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "orlop_control_request_duration_seconds",
			Help:    "Control-plane HTTP request latency by stable route pattern.",
			Buckets: prometheus.DefBuckets,
		}, []string{"route", "method", "status"}),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "orlop_control_requests_total",
			Help: "Control-plane HTTP requests by stable route pattern.",
		}, []string{"route", "method", "status"}),
		enroll: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "orlop_enroll_total",
			Help: "Agent enrollment requests by outcome.",
		}, []string{"outcome"}),
		certMint: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "orlop_cert_mint_total",
			Help: "Server certificate mint requests by outcome.",
		}, []string{"outcome"}),
		alloc: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "orlop_alloc_total",
			Help: "Agent allocation requests by outcome.",
		}, []string{"outcome"}),
		caExpiry: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "orlop_ca_cert_expiry_timestamp_seconds",
			Help: "CA certificate expiry as a Unix timestamp.",
		}, []string{"kind"}),
		capacity: capacity,
	}
	m.registry.MustRegister(
		m.requestDuration,
		m.requests,
		m.enroll,
		m.certMint,
		m.alloc,
		m.caExpiry,
		m.capacity,
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "orlop_control_build_info",
			Help: "Build information for orlop-control. Always 1.",
			ConstLabels: prometheus.Labels{
				"version": buildinfo.Version(),
			},
		}, func() float64 { return 1 }),
	)
	return m
}

func (m *controlMetrics) setCapacityStore(store storage.CapacityMetricsStore) {
	if m == nil || m.capacity == nil || store == nil {
		return
	}
	m.capacity.setStore(store)
}

func (m *controlMetrics) handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{Registry: m.registry})
}

func (m *controlMetrics) setCAExpiry(kind string, expiresAt time.Time) {
	if m == nil || expiresAt.IsZero() {
		return
	}
	m.caExpiry.WithLabelValues(kind).Set(float64(expiresAt.Unix()))
}

func (m *controlMetrics) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		state := &controlOutcomeState{}
		r = r.WithContext(context.WithValue(r.Context(), controlOutcomeContextKey{}, state))
		next.ServeHTTP(ww, r)

		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "unmatched"
		}
		statusCode := ww.Status()
		if statusCode == 0 {
			statusCode = http.StatusOK
		}
		status := strconv.Itoa(statusCode)
		m.requestDuration.WithLabelValues(route, r.Method, status).Observe(time.Since(started).Seconds())
		m.requests.WithLabelValues(route, r.Method, status).Inc()

		outcome := state.value
		if outcome == "" {
			outcome = controlOutcome(statusCode)
		}
		switch {
		case route == "/agent/enroll":
			m.enroll.WithLabelValues(outcome).Inc()
		case route == "/control/sign-server-cert":
			m.certMint.WithLabelValues(outcome).Inc()
		case r.Method == http.MethodPost &&
			(strings.HasSuffix(route, "/v1/entities") || strings.HasSuffix(route, "/api/v1/entities")):
			m.alloc.WithLabelValues(outcome).Inc()
		}
	})
}

type controlOutcomeContextKey struct{}

type controlOutcomeState struct {
	value string
}

// setControlOutcome gives handlers a bounded, diagnostic outcome for errors
// that share an HTTP status (for example pool exhaustion versus an unavailable
// server VM). It is a no-op outside the metrics middleware.
func setControlOutcome(r *http.Request, outcome string) {
	if state, ok := r.Context().Value(controlOutcomeContextKey{}).(*controlOutcomeState); ok {
		state.value = outcome
	}
}

func controlOutcome(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "issued"
	case status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable:
		return "retryable_error"
	case status >= 400 && status < 500:
		return "rejected"
	default:
		return "server_error"
	}
}
