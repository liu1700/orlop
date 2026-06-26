package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsExposesAllSeries(t *testing.T) {
	m := newServerMetrics()

	m.observeDuration("manifest_get", time.Now().Add(-25*time.Millisecond))
	m.observeOp("chunk_get", "out", 4096)
	m.observeOp("chunk_put", "in", 4096)
	m.chunkState("cached")
	m.chunkState("deduped")
	m.chunkState("fetched")
	m.leaseAcquired("/file")

	srv := httptest.NewServer(m.handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("scrape failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	body := readAll(t, resp)
	for _, want := range []string{
		`orlop_dataplane_op_duration_seconds_bucket{op="manifest_get"`,
		`orlop_dataplane_bytes_total{direction="out",op="chunk_get"} 4096`,
		`orlop_dataplane_bytes_total{direction="in",op="chunk_put"} 4096`,
		`orlop_chunks_total{state="cached"} 1`,
		`orlop_chunks_total{state="deduped"} 1`,
		`orlop_chunks_total{state="fetched"} 1`,
		`orlop_lease_held{path="/file"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected exposition to contain %q\n--- body ---\n%s", want, body)
		}
	}

	// Releasing the lease should remove the time series so dashboards don't
	// see stale 1s.
	m.leaseReleased("/file")
	resp2, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	body2 := readAll(t, resp2)
	if strings.Contains(body2, `orlop_lease_held{path="/file"}`) {
		t.Errorf("expected lease_held{/file} to be deleted after release; body:\n%s", body2)
	}
}

func TestLeaseGaugeRefcounts(t *testing.T) {
	m := newServerMetrics()
	m.leaseAcquired("/p")
	m.leaseAcquired("/p")
	m.leaseReleased("/p")

	srv := httptest.NewServer(m.handler())
	defer srv.Close()
	resp, _ := http.Get(srv.URL)
	body := readAll(t, resp)
	resp.Body.Close()
	if !strings.Contains(body, `orlop_lease_held{path="/p"} 1`) {
		t.Fatalf("expected /p still held after one release while refcount=1; body:\n%s", body)
	}

	m.leaseReleased("/p")
	resp2, _ := http.Get(srv.URL)
	body2 := readAll(t, resp2)
	resp2.Body.Close()
	if strings.Contains(body2, `orlop_lease_held{path="/p"}`) {
		t.Fatalf("expected /p deleted after balanced release; body:\n%s", body2)
	}
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	return string(buf)
}
