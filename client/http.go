package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// APIVersion is the control-plane API major version this SDK is written against.
// It is sent on every request as the Orlop-API-Version header and compared
// against the server's advertised version so skew surfaces as an explicit
// APIVersionError rather than an opaque 4xx. See the compatibility policy in
// docs/control-plane.md.
const APIVersion = "1"

const apiVersionHeader = "Orlop-API-Version"

// APIVersionError reports that the control plane advertised a control API major
// version this SDK was not built against. When you see it, the SDK and server
// are incompatible — upgrade one to a matching major (see the compatibility
// policy). It is returned in preference to the underlying HTTP status so the
// skew is unambiguous.
type APIVersionError struct {
	Client string // the SDK's APIVersion
	Server string // the server's advertised Orlop-API-Version
}

func (e *APIVersionError) Error() string {
	return fmt.Sprintf("orlop: control API version skew: SDK speaks v%s, server speaks v%s", e.Client, e.Server)
}

// HTTPClient talks to a running orlop control plane (orlop-control) over its
// REST API. Construct it with New. The zero value is not usable; set HTTP to
// override the default http.Client (e.g. for timeouts or a custom transport).
type HTTPClient struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

var _ Client = (*HTTPClient)(nil)

// New returns a client for the given orlop-control base URL and service bearer
// token. The token authorizes control-plane operations and is never exposed to
// agents.
func New(baseURL, token string) *HTTPClient {
	return &HTTPClient{BaseURL: baseURL, Token: token, HTTP: http.DefaultClient}
}

func (c *HTTPClient) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *HTTPClient) do(ctx context.Context, method, path string, body, out any) error {
	buf := &bytes.Buffer{}
	if body != nil {
		if err := json.NewEncoder(buf).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, buf)
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(apiVersionHeader, APIVersion)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Detect SDK<->server skew explicitly. A server that predates the header
	// (empty) is left alone for back-compat; a differing MAJOR is incompatible.
	if sv := resp.Header.Get(apiVersionHeader); sv != "" && apiMajor(sv) != apiMajor(APIVersion) {
		return &APIVersionError{Client: APIVersion, Server: sv}
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("orlop %s %s: status %d", method, path, resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

type entityResp struct {
	Handle      string `json:"handle"`
	VirtualPath string `json:"virtual_path"`
	QuotaBytes  int64  `json:"quota_bytes"`
}

func (e entityResp) toDisk(agentID string) Disk {
	return Disk{
		AgentID:     agentID,
		Handle:      e.Handle,
		VirtualPath: orDefault(e.VirtualPath, MountPath(agentID)),
		QuotaBytes:  e.QuotaBytes,
	}
}

// entityBody builds the POST /v1/entities request body. owner_id is included
// only when ownerID is non-empty so the server derives the user's per-user
// tenant. grant_bytes is the initial size grant, omitted when 0 so the server
// applies its own default grant.
func entityBody(agentID, ownerID string, grantBytes int64) map[string]any {
	b := map[string]any{"entity_type": EntityType, "entity_id": agentID}
	if ownerID != "" {
		b["owner_id"] = ownerID
	}
	if grantBytes > 0 {
		b["grant_bytes"] = grantBytes
	}
	return b
}

func entityPath(agentID string) string {
	return fmt.Sprintf("/v1/entities/%s/%s", EntityType, agentID)
}

// AllocateDisk implements Client.
func (c *HTTPClient) AllocateDisk(ctx context.Context, agentID, ownerID string, grantBytes int64) (Disk, error) {
	var ent entityResp
	if err := c.do(ctx, http.MethodPost, "/v1/entities", entityBody(agentID, ownerID, grantBytes), &ent); err != nil {
		return Disk{}, err
	}
	return ent.toDisk(agentID), nil
}

// ResolveDisk implements Client.
func (c *HTTPClient) ResolveDisk(ctx context.Context, agentID string) (Disk, error) {
	var ent entityResp
	if err := c.do(ctx, http.MethodGet, entityPath(agentID), nil, &ent); err != nil {
		return Disk{}, err
	}
	return ent.toDisk(agentID), nil
}

// SetDiskQuota implements Client.
func (c *HTTPClient) SetDiskQuota(ctx context.Context, agentID string, grantBytes int64) error {
	body := map[string]any{"grant_bytes": grantBytes}
	return c.do(ctx, http.MethodPatch, entityPath(agentID), body, nil)
}

// RevokeDisk implements Client.
func (c *HTTPClient) RevokeDisk(ctx context.Context, agentID string) error {
	return c.do(ctx, http.MethodDelete, entityPath(agentID), nil, nil)
}

// SetAccountBudget implements Client.
// POST /v1/entities/account/{ownerID}/budget {"disk_bytes": N}.
func (c *HTTPClient) SetAccountBudget(ctx context.Context, ownerID string, diskBytes int64) error {
	body := map[string]any{"disk_bytes": diskBytes}
	return c.do(ctx, http.MethodPost, fmt.Sprintf("/v1/entities/account/%s/budget", ownerID), body, nil)
}

// ReassignDisk implements Client.
// POST /v1/entities/agent/{id}/reassign {"owner_id": "<new owner>"}.
func (c *HTTPClient) ReassignDisk(ctx context.Context, agentID, newOwnerID string) error {
	body := map[string]any{"owner_id": newOwnerID}
	return c.do(ctx, http.MethodPost, entityPath(agentID)+"/reassign", body, nil)
}

type enrollTokenResp struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

type tenantUsageResp struct {
	UsedBytes int64 `json:"used_bytes"`
}

// UserDiskUsage implements Client.
func (c *HTTPClient) UserDiskUsage(ctx context.Context, ownerID string) (int64, error) {
	var r tenantUsageResp
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/v1/tenants/%s/usage", ownerID), nil, &r); err != nil {
		return 0, err
	}
	return r.UsedBytes, nil
}

// MintEnrollToken implements Client.
func (c *HTTPClient) MintEnrollToken(ctx context.Context, agentID string) (string, error) {
	var r enrollTokenResp
	path := fmt.Sprintf("/v1/agents/%s/enroll-token", agentID)
	if err := c.do(ctx, http.MethodPost, path, nil, &r); err != nil {
		return "", err
	}
	if r.Token == "" {
		return "", fmt.Errorf("orlop: empty enroll token for agent %q", agentID)
	}
	return r.Token, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// apiMajor returns the major component of a version string ("1" from "1",
// "1.2" from "1.2"). Compatibility is decided on the major alone.
func apiMajor(v string) string {
	if i := strings.IndexByte(v, '.'); i >= 0 {
		return v[:i]
	}
	return v
}
