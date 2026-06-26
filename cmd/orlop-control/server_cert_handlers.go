package main

import (
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/ca"
)

// defaultServerCertFQDN is the in-cluster Service name agents and
// orlop-control dial orlop-server at (see the helm
// orlop-server Service + pool-seed data_addr). It is the only name a
// self-provisioned server cert is allowed to carry.
const defaultServerCertFQDN = "orlop-server"

// defaultServerCertTTL is how long a self-provisioned server cert is valid.
// orlop-server re-signs well before this expires (rotation in place).
const defaultServerCertTTL = 90 * 24 * time.Hour

// serverCertHandlers backs POST /control/sign-server-cert: it takes a CSR from
// orlop-server (whose private key never leaves its pod) and returns a
// server-auth leaf signed by the org root, plus the org root itself (the client
// CA the server uses to verify agent client certs). This replaces the manual
// `ca mint-server-cert` + pre-created k8s Secret bootstrap.
//
// Authn is the shared service token (RequireServiceToken / ORLOP_CONTROL_PLANE_TOKEN)
// — the same gate as /v1/entities. The fqdn is constrained to allowedFQDN so a
// token holder can only ever obtain THE server's cert, not an arbitrary one.
type serverCertHandlers struct {
	logger      *slog.Logger
	ca          *ca.CA
	allowedFQDN string
	ttl         time.Duration
}

func newServerCertHandlers(logger *slog.Logger, agentCA *ca.CA, allowedFQDN string, ttl time.Duration) *serverCertHandlers {
	if allowedFQDN == "" {
		allowedFQDN = defaultServerCertFQDN
	}
	if ttl <= 0 {
		ttl = defaultServerCertTTL
	}
	return &serverCertHandlers{logger: logger, ca: agentCA, allowedFQDN: allowedFQDN, ttl: ttl}
}

func mountServerCert(r chi.Router, svc func(http.Handler) http.Handler, h *serverCertHandlers) {
	r.With(svc).Post("/control/sign-server-cert", h.handleSign)
}

type signServerCertRequest struct {
	CSRPEM string `json:"csr_pem"`
	// FQDN is optional. When set it must equal the server's configured name;
	// the signed cert always carries allowedFQDN regardless.
	FQDN string `json:"fqdn,omitempty"`
}

type signServerCertResponse struct {
	CertPEM     string `json:"cert_pem"`
	ClientCAPEM string `json:"client_ca_pem"`
	Serial      string `json:"serial"`
	ExpiresAt   string `json:"expires_at"`
}

func (h *serverCertHandlers) handleSign(w http.ResponseWriter, r *http.Request) {
	var req signServerCertRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed_body")
		return
	}
	if req.FQDN != "" && req.FQDN != h.allowedFQDN {
		h.logger.Warn("sign_server_cert_fqdn_denied", "requested", req.FQDN, "allowed", h.allowedFQDN)
		writeOAuthError(w, http.StatusForbidden, "access_denied", "fqdn_not_allowed")
		return
	}

	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "expected_pem_certificate_request")
		return
	}

	if !h.ca.HasRootKey() {
		// The signing host (e.g. a server-only VM that holds the root cert but
		// not the key) cannot sign. In orlop orlop-control always holds
		// the key, so this is a misconfiguration, not a normal state.
		h.logger.Error("sign_server_cert_no_root_key")
		writeOAuthError(w, http.StatusServiceUnavailable, "server_error", "ca_signing_unavailable")
		return
	}

	certPEM, serial, err := h.ca.SignServerCSR(block.Bytes, h.allowedFQDN, h.ttl)
	if err != nil {
		// A bad/forged CSR (parse or signature failure) is a client error; the
		// CA already rejected it without signing.
		h.logger.Warn("sign_server_cert_failed", "error", err)
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid_csr")
		return
	}
	leaf, err := ca.DecodeCertPEM(certPEM)
	if err != nil {
		h.logger.Error("sign_server_cert_parse_failed", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	h.logger.Info("sign_server_cert_issued", "fqdn", h.allowedFQDN, "serial", serial, "not_after", leaf.NotAfter.UTC())
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, signServerCertResponse{
		CertPEM:     string(certPEM),
		ClientCAPEM: string(h.ca.RootPEM()),
		Serial:      serial,
		ExpiresAt:   leaf.NotAfter.UTC().Format(time.RFC3339),
	})
}
