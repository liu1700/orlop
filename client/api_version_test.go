package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/liu1700/orlop/client"
)

// newVersionServer returns a control-plane stub that advertises the given
// Orlop-API-Version (empty = don't set the header) and answers ResolveDisk.
func newVersionServer(t *testing.T, advertise string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Orlop-API-Version"); got != client.APIVersion {
			t.Errorf("request Orlop-API-Version = %q, want %q", got, client.APIVersion)
		}
		if advertise != "" {
			w.Header().Set("Orlop-API-Version", advertise)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"handle": "h"})
	}))
}

func TestAPIVersionMatchSucceeds(t *testing.T) {
	ts := newVersionServer(t, client.APIVersion)
	defer ts.Close()
	if _, err := client.New(ts.URL, "tok").ResolveDisk(context.Background(), agentID); err != nil {
		t.Fatalf("matching version should succeed; got %v", err)
	}
}

func TestAPIVersionMissingHeaderTolerated(t *testing.T) {
	// A server that predates the header must still work (back-compat).
	ts := newVersionServer(t, "")
	defer ts.Close()
	if _, err := client.New(ts.URL, "tok").ResolveDisk(context.Background(), agentID); err != nil {
		t.Fatalf("missing version header should be tolerated; got %v", err)
	}
}

func TestAPIVersionMajorMismatchErrors(t *testing.T) {
	ts := newVersionServer(t, "2")
	defer ts.Close()
	_, err := client.New(ts.URL, "tok").ResolveDisk(context.Background(), agentID)
	var ve *client.APIVersionError
	if !errors.As(err, &ve) {
		t.Fatalf("want *APIVersionError, got %v", err)
	}
	if ve.Server != "2" || ve.Client != client.APIVersion {
		t.Fatalf("APIVersionError = %+v", ve)
	}
}
