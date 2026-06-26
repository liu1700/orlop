// Package serverapi is a typed mTLS client for orlop-server's /control/tenants
// endpoint. It is used by the placement scheduler to register tenants on newly
// selected servers.
package serverapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

const defaultTimeout = 10 * time.Second

// Server-side codes from cmd/orlop-server/control_tenants.go. Keep in sync.
const (
	codeSizeMismatch       = "size_mismatch"
	codeFSQuotaUnavailable = "fs_quota_unavailable"
)

// Config wires the mTLS credentials and logging for a Client.
type Config struct {
	ClientCertPEM []byte         // control-plane cert from MintControlPlaneCert
	ClientKeyPEM  []byte         // corresponding private key
	ServerCAPool  *x509.CertPool // root that signs orlop-server's server cert
	Timeout       time.Duration  // per-request; default 10s if zero
	Logger        *slog.Logger
}

// Client is a typed mTLS client for orlop-server's admin API. Safe for
// concurrent use.
type Client struct {
	httpClient *http.Client
	logger     *slog.Logger
}

// New constructs a Client from cfg. Returns an error if the TLS credentials
// cannot be parsed or ServerCAPool is nil.
func New(cfg Config) (*Client, error) {
	if cfg.ServerCAPool == nil {
		return nil, fmt.Errorf("serverapi: ServerCAPool must not be nil")
	}
	cert, err := tls.X509KeyPair(cfg.ClientCertPEM, cfg.ClientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("serverapi: parse client cert/key: %w", err)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      cfg.ServerCAPool,
		MinVersion:   tls.VersionTLS13,
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg}
	return &Client{
		httpClient: &http.Client{Transport: transport, Timeout: timeout},
		logger:     logger,
	}, nil
}

// registerTenantRequest is the body sent to POST /control/tenants.
type registerTenantRequest struct {
	TenantID      string `json:"tenant_id"`
	OwnerTenantID string `json:"owner_tenant_id"`
	Name          string `json:"name"`
	SizeBytes     int64  `json:"size_bytes"`
}

// registerTenantResponse is the success body from POST /control/tenants.
type registerTenantResponse struct {
	TenantID  string `json:"tenant_id"`
	ProjectID uint32 `json:"project_id"`
	SizeBytes int64  `json:"size_bytes"`
}

// adminErrorEnvelope is the error body shape from POST /control/tenants.
type adminErrorEnvelope struct {
	Error adminErrorBody `json:"error"`
}

type adminErrorBody struct {
	Code              string `json:"code"`
	Message           string `json:"message"`
	Detail            string `json:"detail"`
	ExistingSizeBytes int64  `json:"existing_size_bytes"`
}

// ErrSizeMismatch is returned when orlop-server reports a 409 with code=size_mismatch.
type ErrSizeMismatch struct {
	Existing int64
}

func (e ErrSizeMismatch) Error() string {
	return fmt.Sprintf("serverapi: tenant already registered with different size %d", e.Existing)
}

// ErrQuotaUnavailable is returned when orlop-server reports a 500 with code=fs_quota_unavailable.
type ErrQuotaUnavailable struct {
	Detail string
}

func (e ErrQuotaUnavailable) Error() string {
	return fmt.Sprintf("serverapi: quota unavailable: %s", e.Detail)
}

// ErrAdmin is returned for any other non-2xx response.
type ErrAdmin struct {
	Status  int
	Code    string
	Message string
}

func (e ErrAdmin) Error() string {
	return fmt.Sprintf("serverapi: admin request failed status=%d code=%s: %s", e.Status, e.Code, e.Message)
}

// RegisterTenant calls POST https://<opsAddr>/control/tenants on orlop-server.
// opsAddr is the orlop-server ops listener address (HTTPS) — see server_pool.ops_addr.
// Returns projectID on success.
//
// Errors:
//   - ErrSizeMismatch if 409.
//   - ErrQuotaUnavailable if 500 with code=fs_quota_unavailable.
//   - ErrAdmin for any other non-2xx.
//   - Wrapped error for transport / TLS / decode failures.
func (c *Client) RegisterTenant(ctx context.Context, opsAddr, tenantID, ownerTenantID, name string, sizeBytes int64) (projectID uint32, err error) {
	body, err := json.Marshal(registerTenantRequest{
		TenantID:      tenantID,
		OwnerTenantID: ownerTenantID,
		Name:          name,
		SizeBytes:     sizeBytes,
	})
	if err != nil {
		return 0, fmt.Errorf("serverapi: marshal request: %w", err)
	}

	url := "https://" + opsAddr + "/control/tenants"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("serverapi: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("serverapi: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var ok registerTenantResponse
		if err := json.NewDecoder(resp.Body).Decode(&ok); err != nil {
			return 0, fmt.Errorf("serverapi: decode response: %w", err)
		}
		c.logger.Info("tenant_admin_register_ok",
			"ops_addr", opsAddr,
			"tenant_id", tenantID,
			"project_id", ok.ProjectID,
		)
		return ok.ProjectID, nil
	}

	// Non-2xx: try to decode error envelope; fall through gracefully if malformed.
	var env adminErrorEnvelope
	_ = json.NewDecoder(resp.Body).Decode(&env)
	e := env.Error

	c.logger.Error("tenant_admin_register_failed",
		"ops_addr", opsAddr,
		"tenant_id", tenantID,
		"status", resp.StatusCode,
		"code", e.Code,
	)

	switch {
	case resp.StatusCode == http.StatusConflict && e.Code == codeSizeMismatch:
		return 0, ErrSizeMismatch{Existing: e.ExistingSizeBytes}
	case resp.StatusCode == http.StatusInternalServerError && e.Code == codeFSQuotaUnavailable:
		return 0, ErrQuotaUnavailable{Detail: e.Detail}
	default:
		return 0, ErrAdmin{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
	}
}

// resizeTenantRequest is the body sent to PATCH /control/tenants/{id}.
type resizeTenantRequest struct {
	SizeBytes int64 `json:"size_bytes"`
}

// ResizeTenant calls PATCH https://<opsAddr>/control/tenants/{id} to change a
// tenant's hard size cap in place, preserving its project ID. It is the
// data-plane half of elastic storage — the storage autoscaler grows a tenant
// toward its promised ceiling, and the email-OTP upgrade raises an anon trial's
// cap the same way. Idempotent: re-applying the current size returns the
// unchanged projectID.
//
// Errors:
//   - ErrQuotaUnavailable if 500 with code=fs_quota_unavailable.
//   - ErrAdmin for any other non-2xx (including 404 when the tenant is unknown).
//   - Wrapped error for transport / TLS / decode failures.
func (c *Client) ResizeTenant(ctx context.Context, opsAddr, tenantID string, sizeBytes int64) (projectID uint32, err error) {
	body, err := json.Marshal(resizeTenantRequest{SizeBytes: sizeBytes})
	if err != nil {
		return 0, fmt.Errorf("serverapi: marshal request: %w", err)
	}

	url := "https://" + opsAddr + "/control/tenants/" + tenantID
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("serverapi: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("serverapi: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var ok registerTenantResponse
		if err := json.NewDecoder(resp.Body).Decode(&ok); err != nil {
			return 0, fmt.Errorf("serverapi: decode response: %w", err)
		}
		c.logger.Info("tenant_admin_resize_ok",
			"ops_addr", opsAddr,
			"tenant_id", tenantID,
			"project_id", ok.ProjectID,
			"size_bytes", ok.SizeBytes,
		)
		return ok.ProjectID, nil
	}

	var env adminErrorEnvelope
	_ = json.NewDecoder(resp.Body).Decode(&env)
	e := env.Error

	c.logger.Error("tenant_admin_resize_failed",
		"ops_addr", opsAddr,
		"tenant_id", tenantID,
		"status", resp.StatusCode,
		"code", e.Code,
	)

	if resp.StatusCode == http.StatusInternalServerError && e.Code == codeFSQuotaUnavailable {
		return 0, ErrQuotaUnavailable{Detail: e.Detail}
	}
	return 0, ErrAdmin{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
}

// SetAccountQuota calls PATCH https://<opsAddr>/control/accounts/{owner}/quota to set
// (or resize) the JuiceFS hard cap on an account's owner tenant dir — the shared disk
// budget all the account's agents draw from. Used on the buy/upgrade path. Idempotent.
//
// Errors mirror ResizeTenant: ErrQuotaUnavailable, ErrAdmin, or a wrapped transport error.
func (c *Client) SetAccountQuota(ctx context.Context, opsAddr, ownerTenantID string, sizeBytes int64) (projectID uint32, err error) {
	body, err := json.Marshal(resizeTenantRequest{SizeBytes: sizeBytes})
	if err != nil {
		return 0, fmt.Errorf("serverapi: marshal request: %w", err)
	}

	url := "https://" + opsAddr + "/control/accounts/" + ownerTenantID + "/quota"
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("serverapi: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("serverapi: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var ok registerTenantResponse
		if err := json.NewDecoder(resp.Body).Decode(&ok); err != nil {
			return 0, fmt.Errorf("serverapi: decode response: %w", err)
		}
		c.logger.Info("account_quota_set_ok", "ops_addr", opsAddr, "owner_tenant", ownerTenantID, "size_bytes", ok.SizeBytes)
		return ok.ProjectID, nil
	}

	var env adminErrorEnvelope
	_ = json.NewDecoder(resp.Body).Decode(&env)
	e := env.Error
	c.logger.Error("account_quota_set_failed", "ops_addr", opsAddr, "owner_tenant", ownerTenantID, "status", resp.StatusCode, "code", e.Code)
	if resp.StatusCode == http.StatusInternalServerError && e.Code == codeFSQuotaUnavailable {
		return 0, ErrQuotaUnavailable{Detail: e.Detail}
	}
	return 0, ErrAdmin{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
}

// UnregisterTenant calls DELETE https://<opsAddr>/control/tenants/{id} on
// orlop-server. Used by the anonymous-session sweeper to tear down a
// per-session tenant after its 5-min sandbox + 5h adoption window has
// elapsed.
//
// Idempotent: returns nil if the server already considers the tenant
// gone (404 with code=not_found). Any other non-2xx returns ErrAdmin.
func (c *Client) UnregisterTenant(ctx context.Context, opsAddr, tenantID string) error {
	url := "https://" + opsAddr + "/control/tenants/" + tenantID
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("serverapi: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("serverapi: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		c.logger.Info("tenant_admin_unregister_ok", "ops_addr", opsAddr, "tenant_id", tenantID)
		return nil
	}

	var env adminErrorEnvelope
	_ = json.NewDecoder(resp.Body).Decode(&env)
	e := env.Error

	if resp.StatusCode == http.StatusNotFound && e.Code == "not_found" {
		c.logger.Info("tenant_admin_unregister_already_gone", "ops_addr", opsAddr, "tenant_id", tenantID)
		return nil
	}

	c.logger.Error("tenant_admin_unregister_failed",
		"ops_addr", opsAddr,
		"tenant_id", tenantID,
		"status", resp.StatusCode,
		"code", e.Code,
	)
	return ErrAdmin{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
}

// TenantUsage is the decoded response from GetTenantUsage.
type TenantUsage struct {
	TenantID  string
	UsedBytes int64
	SizeBytes int64
}

type tenantUsageResponse struct {
	TenantID  string `json:"tenant_id"`
	UsedBytes int64  `json:"used_bytes"`
	SizeBytes int64  `json:"size_bytes"`
}

// GetTenantUsage calls GET https://<opsAddr>/control/tenants/{id}/usage on
// orlop-server. Returns ErrAdmin on non-2xx (including 404 for unknown tenants).
func (c *Client) GetTenantUsage(ctx context.Context, opsAddr, tenantID string) (TenantUsage, error) {
	url := "https://" + opsAddr + "/control/tenants/" + tenantID + "/usage"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return TenantUsage{}, fmt.Errorf("serverapi: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return TenantUsage{}, fmt.Errorf("serverapi: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var ok tenantUsageResponse
		if err := json.NewDecoder(resp.Body).Decode(&ok); err != nil {
			return TenantUsage{}, fmt.Errorf("serverapi: decode response: %w", err)
		}
		return TenantUsage{
			TenantID:  ok.TenantID,
			UsedBytes: ok.UsedBytes,
			SizeBytes: ok.SizeBytes,
		}, nil
	}

	var env adminErrorEnvelope
	_ = json.NewDecoder(resp.Body).Decode(&env)
	e := env.Error
	c.logger.Error("tenant_admin_usage_failed",
		"ops_addr", opsAddr,
		"tenant_id", tenantID,
		"status", resp.StatusCode,
		"code", e.Code,
	)
	return TenantUsage{}, ErrAdmin{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
}

// JournalEntry is one row decoded from GET /control/tenants/{id}/journal.
// The JSON tags double as the wire shape — the response decodes directly
// into this type.
type JournalEntry struct {
	SessionID     string  `json:"session_id"`
	AllocationID  string  `json:"allocation_id"`
	Seq           uint64  `json:"seq"`
	TsUnixMs      int64   `json:"ts_unix_ms"`
	Path          string  `json:"path"`
	Op            string  `json:"op"`
	AgentID       string  `json:"agent_id"`
	BeforeVersion *uint64 `json:"before_version,omitempty"`
	AfterVersion  *uint64 `json:"after_version,omitempty"`
	RenameFrom    string  `json:"rename_from,omitempty"`
	SizeBefore    *uint64 `json:"size_before,omitempty"`
	SizeAfter     *uint64 `json:"size_after,omitempty"`
}

// JournalQueryResult is the decoded response from QueryJournal.
type JournalQueryResult struct {
	Entries    []JournalEntry `json:"entries"`
	NextCursor string         `json:"next_cursor,omitempty"`
}

// QueryJournal calls GET https://<opsAddr>/control/tenants/{id}/journal on
// orlop-server. cursor is the opaque keyset pagination token ("" for the
// first page; pass a prior reply's NextCursor for the next).
// Returns ErrAdmin on non-2xx (including 404 for unknown tenants).
func (c *Client) QueryJournal(
	ctx context.Context,
	opsAddr, tenantID, allocationID string,
	limit uint32,
	cursor string,
) (JournalQueryResult, error) {
	url := "https://" + opsAddr + "/control/tenants/" + tenantID + "/journal"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return JournalQueryResult{}, fmt.Errorf("serverapi: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	q := req.URL.Query()
	if allocationID != "" {
		q.Set("allocation_id", allocationID)
	}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return JournalQueryResult{}, fmt.Errorf("serverapi: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var result JournalQueryResult
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return JournalQueryResult{}, fmt.Errorf("serverapi: decode response: %w", err)
		}
		return result, nil
	}

	var env adminErrorEnvelope
	_ = json.NewDecoder(resp.Body).Decode(&env)
	e := env.Error
	c.logger.Error("tenant_admin_journal_failed",
		"ops_addr", opsAddr,
		"tenant_id", tenantID,
		"status", resp.StatusCode,
		"code", e.Code,
	)
	return JournalQueryResult{}, ErrAdmin{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
}

// QueryJournalAfterSeq calls GET <opsAddr>/control/tenants/{id}/journal with
// the after_seq cursor (ascending order). Used by orlop-control's GET
// /api/v1/journal?after_seq=N backfill path (spec §4.4).
func (c *Client) QueryJournalAfterSeq(
	ctx context.Context,
	opsAddr, tenantID, allocationID string,
	limit uint32,
	afterSeq uint64,
) (JournalQueryResult, error) {
	url := "https://" + opsAddr + "/control/tenants/" + tenantID + "/journal"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return JournalQueryResult{}, fmt.Errorf("serverapi: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	q := req.URL.Query()
	if allocationID != "" {
		q.Set("allocation_id", allocationID)
	}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	q.Set("after_seq", fmt.Sprintf("%d", afterSeq))
	req.URL.RawQuery = q.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return JournalQueryResult{}, fmt.Errorf("serverapi: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var result JournalQueryResult
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return JournalQueryResult{}, fmt.Errorf("serverapi: decode response: %w", err)
		}
		return result, nil
	}

	var env adminErrorEnvelope
	_ = json.NewDecoder(resp.Body).Decode(&env)
	e := env.Error
	return JournalQueryResult{}, ErrAdmin{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
}

// StreamJournal opens GET <opsAddr>/control/tenants/{id}/journal/stream and
// returns a buffered channel that receives every SSE-decoded JournalEntry.
//
// The channel closes when (a) ctx is cancelled, (b) the response body
// returns an error, or (c) the body EOFs. Callers must drain or cancel
// promptly: a slow consumer can pin the goroutine but the channel buffer
// (cap 64) absorbs short bursts.
//
// The scanner buffer is enlarged from the stdlib default (64 KiB) to
// 1 MiB so a journal entry with a large rename_from or path doesn't trip
// bufio.ErrTooLong.
//
// The HTTP request does NOT use a per-call deadline — SSE streams are
// long-lived and must rely on the supplied ctx for cancellation. The
// Client's configured Timeout is therefore not applied here.
func (c *Client) StreamJournal(
	ctx context.Context,
	opsAddr, tenantID, allocationID string,
	afterSeq uint64,
) (<-chan JournalEntry, error) {
	url := "https://" + opsAddr + "/control/tenants/" + tenantID + "/journal/stream"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("serverapi: build request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	q := req.URL.Query()
	q.Set("allocation_id", allocationID)
	if afterSeq > 0 {
		q.Set("after_seq", fmt.Sprintf("%d", afterSeq))
	}
	req.URL.RawQuery = q.Encode()

	// SSE is long-lived; use a transport that bypasses the Client.Timeout.
	// The default httpClient has a Timeout that would force-cancel after
	// ~10s. Instead, send via a wrapped transport that respects only ctx.
	resp, err := c.streamTransport().RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("serverapi: do stream request: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := readAtMost(resp.Body, 1024)
		resp.Body.Close()
		return nil, fmt.Errorf("serverapi: stream status %d: %s", resp.StatusCode, body)
	}

	out := make(chan JournalEntry, 64)
	go func() {
		defer close(out)
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 || line[0] == ':' {
				// Blank separator line or SSE comment (keepalive). Skip.
				continue
			}
			if !bytes.HasPrefix(line, []byte("data: ")) {
				continue
			}
			var e JournalEntry
			if err := json.Unmarshal(line[len("data: "):], &e); err != nil {
				c.logger.Warn("stream_decode_failed",
					"ops_addr", opsAddr,
					"tenant_id", tenantID,
					"error", err)
				continue
			}
			select {
			case out <- e:
			case <-ctx.Done():
				return
			}
		}
		// scanner.Err() == nil on EOF; both paths close the channel via the
		// deferred close(out). A pathological transport error is logged but
		// not surfaced — the caller will treat channel close as end-of-stream.
		if err := scanner.Err(); err != nil {
			c.logger.Warn("stream_scan_error",
				"ops_addr", opsAddr,
				"tenant_id", tenantID,
				"error", err)
		}
	}()
	return out, nil
}

// streamTransport returns a Transport sharing the same TLS config as the
// configured Client but without a per-request timeout — SSE streams must
// not be killed by Client.Timeout. ctx is the only cancellation signal.
func (c *Client) streamTransport() http.RoundTripper {
	if c.httpClient.Transport != nil {
		return c.httpClient.Transport
	}
	return http.DefaultTransport
}

func readAtMost(r interface{ Read(p []byte) (int, error) }, max int) ([]byte, error) {
	buf := make([]byte, max)
	n, err := r.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	return nil, err
}

// JournalRevertResult mirrors orlop-server's controlJournalRevertResponse:
// Ok=true means the revert landed; Ok=false carries a conflict reason
// (no_journal_row, concurrent_writer, revert_blocked, ...).
type JournalRevertResult struct {
	Ok       bool                   `json:"ok"`
	Conflict *JournalRevertConflict `json:"conflict,omitempty"`
}

// JournalRevertConflict is the conflict-reason envelope returned alongside
// Ok=false. Reason is a machine-readable token; the UI maps it to text per
// spec §3.4.
type JournalRevertConflict struct {
	Reason string `json:"reason"`
}

// RevertJournalPath calls POST <opsAddr>/control/tenants/{id}/journal/revert.
// AgentID is recorded on the inverse journal row; callers should pass a
// stable, attributable string (e.g. the user's UUID or an anonymous-session
// short id). An empty agentID defaults server-side to "revert@control".
//
// On 200 the server returns either {ok:true} or {ok:false, conflict:{...}}.
// Non-2xx responses are surfaced as ErrAdmin.
func (c *Client) RevertJournalPath(
	ctx context.Context,
	opsAddr, tenantID, allocationID, sessionID, path string,
	seq uint64,
	force bool,
	agentID string,
) (JournalRevertResult, error) {
	body, err := json.Marshal(map[string]any{
		"allocation_id": allocationID,
		"session_id":    sessionID,
		"path":          path,
		"seq":           seq,
		"force":         force,
		"agent_id":      agentID,
	})
	if err != nil {
		return JournalRevertResult{}, fmt.Errorf("serverapi: marshal revert: %w", err)
	}

	url := "https://" + opsAddr + "/control/tenants/" + tenantID + "/journal/revert"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return JournalRevertResult{}, fmt.Errorf("serverapi: build revert request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return JournalRevertResult{}, fmt.Errorf("serverapi: do revert request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var result JournalRevertResult
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return JournalRevertResult{}, fmt.Errorf("serverapi: decode revert: %w", err)
		}
		return result, nil
	}

	var env adminErrorEnvelope
	_ = json.NewDecoder(resp.Body).Decode(&env)
	e := env.Error
	c.logger.Error("tenant_admin_revert_failed",
		"ops_addr", opsAddr,
		"tenant_id", tenantID,
		"allocation_id", allocationID,
		"status", resp.StatusCode,
		"code", e.Code,
	)
	return JournalRevertResult{}, ErrAdmin{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
}

// ClearActiveMountLease calls
// DELETE https://<opsAddr>/control/tenants/{tenant}/allocations/{alloc}/mount-lease
// to fence the currently-active session_id for an allocation so the displaced
// client cannot keep writing. Idempotent. Called by orlop-control on Revoke
// or owner-driven Force-Unmount (the Take-over path also routes through
// Force-Unmount). orlop-server installs the next session lazily on the first
// write that arrives after a clear — see issue #175.
func (c *Client) ClearActiveMountLease(ctx context.Context, opsAddr, tenantID, allocationID string) error {
	url := "https://" + opsAddr + "/control/tenants/" + tenantID + "/allocations/" + allocationID + "/mount-lease"
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("serverapi: build request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("serverapi: do request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	var env adminErrorEnvelope
	_ = json.NewDecoder(resp.Body).Decode(&env)
	e := env.Error
	c.logger.Error("clear_active_mount_lease_failed",
		"ops_addr", opsAddr,
		"tenant_id", tenantID,
		"allocation_id", allocationID,
		"status", resp.StatusCode,
		"code", e.Code,
	)
	return ErrAdmin{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
}

// AgentPurgeResult is the decoded response from PurgeAgentData.
type AgentPurgeResult struct {
	ManifestsDeleted int64  `json:"manifests_deleted"`
	ChunkRowsDeleted int64  `json:"chunk_rows_deleted"`
	BytesFreed       uint64 `json:"bytes_freed"`
}

// PurgeAgentData calls
// DELETE https://<opsAddr>/control/tenants/{tenant}/agents/{agent}
// to erase one agent's subtree (manifests + now-unreferenced chunks) from its
// per-user tenant on orlop-server. Used by the allocation purge path
// when the user still has other live agents sharing the tenant directory.
//
// Idempotent: a tenant the server no longer knows (404 code=not_found) means
// the whole tenant dir is already gone, which is at least as erased as a
// per-agent purge — returns a zero result and nil.
func (c *Client) PurgeAgentData(ctx context.Context, opsAddr, tenantID, agentID string) (AgentPurgeResult, error) {
	url := "https://" + opsAddr + "/control/tenants/" + tenantID + "/agents/" + agentID
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return AgentPurgeResult{}, fmt.Errorf("serverapi: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return AgentPurgeResult{}, fmt.Errorf("serverapi: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var out AgentPurgeResult
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return AgentPurgeResult{}, fmt.Errorf("serverapi: decode response: %w", err)
		}
		c.logger.Info("tenant_admin_agent_purge_ok",
			"ops_addr", opsAddr,
			"tenant_id", tenantID,
			"agent_id", agentID,
			"manifests_deleted", out.ManifestsDeleted,
			"chunk_rows_deleted", out.ChunkRowsDeleted,
			"bytes_freed", out.BytesFreed,
		)
		return out, nil
	}

	var env adminErrorEnvelope
	_ = json.NewDecoder(resp.Body).Decode(&env)
	e := env.Error

	if resp.StatusCode == http.StatusNotFound && e.Code == "not_found" {
		c.logger.Info("tenant_admin_agent_purge_tenant_gone",
			"ops_addr", opsAddr, "tenant_id", tenantID, "agent_id", agentID)
		return AgentPurgeResult{}, nil
	}

	c.logger.Error("tenant_admin_agent_purge_failed",
		"ops_addr", opsAddr,
		"tenant_id", tenantID,
		"agent_id", agentID,
		"status", resp.StatusCode,
		"code", e.Code,
	)
	return AgentPurgeResult{}, ErrAdmin{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
}
