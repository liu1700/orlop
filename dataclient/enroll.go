package dataclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AgentCredentials is the result of Enroll: a short-lived (~1h), agent-scoped
// mTLS client certificate plus the data-plane address to Dial. The certificate
// carries the SPIFFE /agent/<id> SAN that confines every op to that agent's
// subtree, so credentials must be treated as agent-scoped secrets.
type AgentCredentials struct {
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	CACertPEM     []byte    // ca_chain_pem: the tenant CA chain that verifies the server
	ServerAddr    string    // data-plane mTLS address, host:port
	AllocationID  string    // the allocation the enroll token was bound to
	ExpiresAt     time.Time // certificate NotAfter; zero if the server omitted it
}

// Expired reports whether the certificate has passed its NotAfter (with an
// optional early-refresh skew). A caller caching credentials should re-Enroll
// before this returns true; the enroll endpoint is rate-limited, so cache and
// reuse credentials rather than enrolling per operation.
func (c *AgentCredentials) Expired(skew time.Duration) bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().Add(skew).After(c.ExpiresAt)
}

type enrollResp struct {
	ClientCertPEM string `json:"client_cert_pem"`
	ClientKeyPEM  string `json:"client_key_pem"`
	CAChainPEM    string `json:"ca_chain_pem"`
	ServerAddr    string `json:"server_addr"`
	ExpiresAt     string `json:"expires_at"`
	AllocationID  string `json:"allocation_id"`
}

// EnrollOption configures Enroll.
type EnrollOption func(*enrollConfig)

type enrollConfig struct {
	allowInsecureURL bool
}

// WithInsecureControlURL permits a plaintext http:// controlBaseURL to a
// non-loopback host. The enroll channel carries the enroll token AND the minted
// private key + CA trust root, so cleartext lets an on-path attacker capture the
// key and substitute the data-plane trust anchor. Use this ONLY when the network
// path is otherwise trusted (e.g. an in-cluster service reached over a private
// network), matching how the in-pod mounter enrolls. Loopback hosts are allowed
// without this option.
func WithInsecureControlURL() EnrollOption {
	return func(c *enrollConfig) { c.allowInsecureURL = true }
}

// EnrollError reports a non-200 response from /agent/enroll. Retryable is true
// for a 503 (transient placement/CA outage carrying Retry-After): the enroll
// token is left live for a retry. A 401/403/429 is not retryable.
type EnrollError struct {
	StatusCode int
	Retryable  bool
	RetryAfter string
	Body       string
}

func (e *EnrollError) Error() string {
	suffix := ""
	if e.Retryable {
		suffix = " (retryable)"
	}
	return fmt.Sprintf("orlop enroll: status %d%s", e.StatusCode, suffix)
}

// Enroll trades a per-agent enroll token at orlop-control's POST /agent/enroll
// for a ~1h agent-scoped mTLS client certificate plus the data-plane address to
// Dial. controlBaseURL is the orlop-control base URL. hc may be nil to use
// http.DefaultClient. The enroll endpoint is rate-limited per Authorization
// key, so callers should cache the returned credentials for their lifetime
// (see AgentCredentials.Expired) rather than enrolling per operation.
func Enroll(ctx context.Context, hc *http.Client, controlBaseURL, enrollToken string, opts ...EnrollOption) (*AgentCredentials, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	var cfg enrollConfig
	for _, o := range opts {
		o(&cfg)
	}
	if err := checkControlURL(controlBaseURL, cfg.allowInsecureURL); err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(controlBaseURL, "/") + "/agent/enroll"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+enrollToken)

	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, &EnrollError{
			StatusCode: resp.StatusCode,
			Retryable:  resp.StatusCode == http.StatusServiceUnavailable,
			RetryAfter: resp.Header.Get("Retry-After"),
			Body:       string(body),
		}
	}

	var er enrollResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&er); err != nil {
		return nil, fmt.Errorf("orlop enroll: decode response: %w", err)
	}
	if er.ClientCertPEM == "" || er.ClientKeyPEM == "" || er.ServerAddr == "" {
		return nil, fmt.Errorf("orlop enroll: incomplete credentials in response")
	}

	creds := &AgentCredentials{
		ClientCertPEM: []byte(er.ClientCertPEM),
		ClientKeyPEM:  []byte(er.ClientKeyPEM),
		CACertPEM:     []byte(er.CAChainPEM),
		ServerAddr:    er.ServerAddr,
		AllocationID:  er.AllocationID,
	}
	if er.ExpiresAt != "" {
		if t, perr := time.Parse(time.RFC3339, er.ExpiresAt); perr == nil {
			creds.ExpiresAt = t
		}
	}
	return creds, nil
}

// checkControlURL enforces HTTPS for the enroll endpoint, which carries the
// enroll token, the minted private key, and the data-plane trust anchor.
// Plaintext http is allowed only to a loopback host, or when the caller
// explicitly opts in via WithInsecureControlURL for a trusted private path.
func checkControlURL(raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("orlop enroll: invalid control url: %w", err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowInsecure || isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("orlop enroll: refusing plaintext http control url %q (carries the minted key + data-plane trust anchor); use https, or pass WithInsecureControlURL for a trusted network", raw)
	default:
		return fmt.Errorf("orlop enroll: control url must be http or https, got %q", u.Scheme)
	}
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
