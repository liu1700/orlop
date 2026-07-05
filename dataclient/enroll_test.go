package dataclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEnrollHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agent/enroll" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok-123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"client_cert_pem":"CERT","client_key_pem":"KEY","ca_chain_pem":"CA","server_addr":"data.example.com:8443","expires_at":"2030-01-01T00:00:00Z","allocation_id":"alloc-9","size_bytes":1024}`))
	}))
	defer srv.Close()

	creds, err := Enroll(context.Background(), nil, srv.URL, "tok-123")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if string(creds.ClientCertPEM) != "CERT" || creds.ServerAddr != "data.example.com:8443" || creds.AllocationID != "alloc-9" {
		t.Fatalf("creds = %+v", creds)
	}
	if creds.ExpiresAt.IsZero() {
		t.Fatalf("expires_at not parsed")
	}
	if creds.Expired(0) {
		t.Fatalf("a 2030 cert should not be reported expired")
	}
}

func TestEnrollRetryable503(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, err := Enroll(context.Background(), nil, srv.URL, "tok")
	var ee *EnrollError
	if !errors.As(err, &ee) {
		t.Fatalf("err = %v, want *EnrollError", err)
	}
	if !ee.Retryable || ee.StatusCode != http.StatusServiceUnavailable || ee.RetryAfter != "2" {
		t.Fatalf("EnrollError = %+v", ee)
	}
}

func TestEnrollUnauthorizedNotRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := Enroll(context.Background(), nil, srv.URL, "bad")
	var ee *EnrollError
	if !errors.As(err, &ee) {
		t.Fatalf("err = %v, want *EnrollError", err)
	}
	if ee.Retryable {
		t.Fatalf("401 must not be retryable: %+v", ee)
	}
}

func TestEnrollIncompleteCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"client_cert_pem":"CERT"}`)) // missing key + server_addr
	}))
	defer srv.Close()

	if _, err := Enroll(context.Background(), nil, srv.URL, "tok"); err == nil {
		t.Fatalf("expected error for incomplete credentials")
	}
}

func TestControlURLGate(t *testing.T) {
	cases := []struct {
		url      string
		insecure bool
		ok       bool
	}{
		{"https://control.example.com:8080", false, true},
		{"http://127.0.0.1:8080", false, true},            // loopback allowed
		{"http://localhost:8080", false, true},            // loopback allowed
		{"http://[::1]:8080", false, true},                // loopback allowed
		{"http://control.example.com:8080", false, false}, // non-loopback http rejected
		{"http://control.example.com:8080", true, true},   // explicit opt-in
		{"ftp://control.example.com", false, false},       // wrong scheme
	}
	for _, tc := range cases {
		err := checkControlURL(tc.url, tc.insecure)
		if (err == nil) != tc.ok {
			t.Errorf("checkControlURL(%q, insecure=%v) err=%v, want ok=%v", tc.url, tc.insecure, err, tc.ok)
		}
	}
}

func TestEnrollRejectsPlaintextNonLoopback(t *testing.T) {
	_, err := Enroll(context.Background(), nil, "http://control.example.com:8080", "tok")
	if err == nil || !strings.Contains(err.Error(), "plaintext") {
		t.Fatalf("Enroll over plaintext non-loopback err = %v, want rejection", err)
	}
}
