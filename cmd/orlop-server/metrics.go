package main

import (
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// serverMetrics holds the Prometheus collectors for the data plane and the
// chunk + lease lifecycle. Exposed at /metrics by newRouter.
//
// Cardinality note: orlop_lease_held{path} is keyed by mount-relative path.
// We delete the series when the lease is released so idle paths don't carry
// stale time series. If the install ever holds many short-lived leases this
// will need to switch to a sampled histogram, but the spec calls for a per-
// path gauge so we honour it here.
type serverMetrics struct {
	registry    *prometheus.Registry
	opDuration  *prometheus.HistogramVec
	bytesTotal  *prometheus.CounterVec
	chunksTotal *prometheus.CounterVec
	leaseHeld   *prometheus.GaugeVec

	// Journal metrics.
	journalWrites      *prometheus.CounterVec
	journalQueryDur    prometheus.Histogram
	journalRows        *prometheus.GaugeVec
	journalRevertTotal *prometheus.CounterVec

	// Session-forgery rejections by reason (bad_format, bad_hex,
	// unknown_or_wrong_conn, fenced). See checkSessionFence.
	sessionForgeryRejected *prometheus.CounterVec

	// Per-agent path-authorization rejections, by op. A connection whose cert
	// carries an /agent/<id> SAN that touches a path outside /agents/<id>.
	// See checkAgentPath.
	agentPathDenied *prometheus.CounterVec

	mu    sync.Mutex
	paths map[string]int // path → ref count (a path may be re-granted before its release lands)
}

func newServerMetrics() *serverMetrics {
	reg := prometheus.NewRegistry()
	sm := &serverMetrics{
		registry: reg,
		opDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "orlop_dataplane_op_duration_seconds",
			Help:    "Latency of data-plane ops, server-side.",
			Buckets: prometheus.ExponentialBuckets(0.0005, 2, 14),
		}, []string{"op"}),
		bytesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "orlop_dataplane_bytes_total",
			Help: "Bytes transferred over the data plane. direction=in for client→server payloads, out for server→client.",
		}, []string{"direction", "op"}),
		chunksTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "orlop_chunks_total",
			Help: "Chunk lifecycle counter. state=cached on chunk_put store, deduped on chunk_put hit, fetched on chunk_get success, evicted on GC sweep.",
		}, []string{"state"}),
		leaseHeld: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "orlop_lease_held",
			Help: "1 while a lease is held on the labelled path, otherwise the time series is removed.",
		}, []string{"path"}),
		journalWrites: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "orlop_journal_writes_total",
			Help: "Journal rows written, by op and allocation.",
		}, []string{"op", "allocation_id"}),
		journalQueryDur: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "orlop_journal_query_duration_seconds",
			Help:    "Time spent in JournalQuery RPC.",
			Buckets: prometheus.DefBuckets,
		}),
		journalRows: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "orlop_journal_rows_total",
			Help: "Current journal row count per allocation.",
		}, []string{"allocation_id"}),
		journalRevertTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "orlop_journal_revert_total",
			Help: "JournalRevertPath outcomes.",
		}, []string{"allocation_id", "result"}),
		sessionForgeryRejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "orlop_session_forgery_rejected_total",
			Help: "Writes rejected by the mount-session authenticity check, by reason.",
		}, []string{"reason"}),
		agentPathDenied: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "orlop_agent_path_denied_total",
			Help: "Requests rejected because the cert's agent SAN scope did not cover the requested path, by op.",
		}, []string{"op"}),
		paths: make(map[string]int),
	}
	reg.MustRegister(
		sm.opDuration, sm.bytesTotal, sm.chunksTotal, sm.leaseHeld,
		sm.journalWrites, sm.journalQueryDur, sm.journalRows, sm.journalRevertTotal,
		sm.sessionForgeryRejected, sm.agentPathDenied,
	)
	return sm
}

// sessionForgery bumps orlop_session_forgery_rejected_total{reason} by 1.
// reason values: bad_format, bad_hex, unknown_or_wrong_conn, fenced.
func (m *serverMetrics) sessionForgery(reason string) {
	if m == nil {
		return
	}
	m.sessionForgeryRejected.WithLabelValues(reason).Inc()
}

// agentPathDeniedInc bumps orlop_agent_path_denied_total{op} by 1.
func (m *serverMetrics) agentPathDeniedInc(op string) {
	if m == nil {
		return
	}
	m.agentPathDenied.WithLabelValues(op).Inc()
}

func (m *serverMetrics) handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{Registry: m.registry})
}

// observeDuration records elapsed time for a single op invocation.
// Pass `defer m.observeDuration(op, time.Now())()` ... actually we use an
// explicit started value so callers can record on the success path only.
func (m *serverMetrics) observeDuration(op string, started time.Time) {
	if m == nil {
		return
	}
	m.opDuration.WithLabelValues(op).Observe(time.Since(started).Seconds())
}

// observeOp records bytes for a data-plane payload. direction is "in" for
// client→server bytes (chunk_put, manifest_put) or "out" for server→client
// (chunk_get, manifest_get, chunk_has bitmap).
func (m *serverMetrics) observeOp(op, direction string, bytes uint64) {
	if m == nil {
		return
	}
	m.bytesTotal.WithLabelValues(direction, op).Add(float64(bytes))
}

// chunkState bumps orlop_chunks_total{state=...}. Valid states: cached,
// deduped, fetched, evicted.
func (m *serverMetrics) chunkState(state string) {
	if m == nil {
		return
	}
	m.chunksTotal.WithLabelValues(state).Inc()
}

// leaseAcquired raises orlop_lease_held{path}=1 and refcounts overlapping
// grants — a fresh grant racing a not-yet-audited release won't drop the
// series before the new holder shows up.
func (m *serverMetrics) leaseAcquired(path string) {
	if m == nil || path == "" {
		return
	}
	m.mu.Lock()
	m.paths[path]++
	m.mu.Unlock()
	m.leaseHeld.WithLabelValues(path).Set(1)
}

// leaseReleased decrements the refcount for path and deletes the gauge time
// series when the count reaches zero, so dashboards don't see stale 1s.
func (m *serverMetrics) leaseReleased(path string) {
	if m == nil || path == "" {
		return
	}
	m.mu.Lock()
	n := m.paths[path] - 1
	if n <= 0 {
		delete(m.paths, path)
		m.mu.Unlock()
		m.leaseHeld.DeleteLabelValues(path)
		return
	}
	m.paths[path] = n
	m.mu.Unlock()
}

// journalWrite increments orlop_journal_writes_total{op, allocation_id}.
func (m *serverMetrics) journalWrite(op, allocationID string) {
	if m == nil {
		return
	}
	m.journalWrites.WithLabelValues(op, allocationID).Inc()
}

// newJournalQueryTimer returns a prometheus.Timer that records elapsed time
// into orlop_journal_query_duration_seconds when ObserveDuration is called.
func (m *serverMetrics) newJournalQueryTimer() *prometheus.Timer {
	if m == nil {
		return prometheus.NewTimer(prometheus.ObserverFunc(func(float64) {}))
	}
	return prometheus.NewTimer(m.journalQueryDur)
}

// journalRevert bumps orlop_journal_revert_total{allocation_id, result} by n.
func (m *serverMetrics) journalRevert(allocationID, result string, n int) {
	if m == nil || n == 0 {
		return
	}
	m.journalRevertTotal.WithLabelValues(allocationID, result).Add(float64(n))
}

func (m *serverMetrics) journalRowCount(allocationID string, count int64) {
	if m == nil {
		return
	}
	m.journalRows.WithLabelValues(allocationID).Set(float64(count))
}

// journalRowCountDelete drops the gauge series when an allocation is
// cascade-deleted so dashboards don't carry a stale count.
func (m *serverMetrics) journalRowCountDelete(allocationID string) {
	if m == nil {
		return
	}
	m.journalRows.DeleteLabelValues(allocationID)
}
