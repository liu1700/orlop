package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/devauth"
)

type fakeMailer struct {
	mu    sync.Mutex
	codes map[string]string
	sends map[string]int
}

func newFakeMailer() *fakeMailer {
	return &fakeMailer{codes: make(map[string]string), sends: make(map[string]int)}
}

func (m *fakeMailer) SendOTP(_ context.Context, email, code string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[email] = code
	m.sends[email]++
	return nil
}

func (m *fakeMailer) code(email string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.codes[email]
}

func (m *fakeMailer) sendCount(email string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sends[email]
}

func httpTestDatabaseURL() string { return os.Getenv("TEST_DATABASE_URL") }

var (
	httpMigrateOnce sync.Once
	httpMigrateErr  error
)

func httpOpenTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	u := httpTestDatabaseURL()
	if u == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping HTTP integration test")
	}
	httpMigrateOnce.Do(func() {
		httpMigrateErr = db.MigrateUp(context.Background(), u)
	})
	if httpMigrateErr != nil {
		t.Fatalf("migrate up: %v", httpMigrateErr)
	}
	pool, err := pgxpool.New(context.Background(), u)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// CASCADE handles FK cleanup; sessions_anonymous and disk_allocations
		// are listed explicitly so tests that only touch them (Phase 2
		// anonymous sandbox flow) still get a clean slate, since the older
		// tables they descend from may not be referenced.
		_, _ = pool.Exec(context.Background(),
			"TRUNCATE TABLE sessions_anonymous, disk_allocations, server_pool, refresh_tokens, access_tokens, email_otps, device_authorizations, agent_enrollments, server_vms, users, tenants RESTART IDENTITY CASCADE")
		pool.Close()
	})
	return pool
}

func httpStartServer(t *testing.T, pool *pgxpool.Pool) (*httptest.Server, *devauth.Service, *fakeMailer) {
	t.Helper()
	return httpStartServerWithFencer(t, pool, nil)
}

func httpStartServerWithFencer(t *testing.T, pool *pgxpool.Pool, fencer mountLeaseFencer) (*httptest.Server, *devauth.Service, *fakeMailer) {
	t.Helper()
	svc := devauth.NewService(pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	mailer := newFakeMailer()
	router := newRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), runtimeDeps{
		devAuth:          svc,
		queries:          sqlcdb.New(pool),
		allocations:      allocations.NewService(pool, nil),
		mailer:           mailer,
		mountLeaseFencer: fencer,
	}, config{})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv, svc, mailer
}

// httpSeedAdminCounter ensures repeated calls within the same test create
// distinct users (different email) under the shared "acme" tenant. Without
// this the cross-user tests double-call this helper and trip the unique
// users.email / tenants.id constraints.
var httpSeedAdminCounter atomic.Int32

func httpSeedAdmin(t *testing.T, pool *pgxpool.Pool, svc *devauth.Service) (cookie *http.Cookie, tenantID string) {
	t.Helper()
	ctx := context.Background()
	q := sqlcdb.New(pool)
	// Idempotent tenant create: only the first call inserts; subsequent
	// calls inside the same test pick up the existing row.
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`,
		"acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	seq := httpSeedAdminCounter.Add(1)
	email := fmt.Sprintf("alice-%d@acme.example", seq)
	user, err := q.CreateUser(ctx, sqlcdb.CreateUserParams{Email: email, TenantID: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := svc.IssueAdminSession(ctx, user.ID, "acme")
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: devauth.AdminSessionCookie, Value: tok}, "acme"
}

func TestHTTPHappyPath(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc, _ := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)

	// 1. CLI creates a device code.
	resp, err := http.Post(srv.URL+"/auth/device/code", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("device/code status = %d", resp.StatusCode)
	}
	var code struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&code); err != nil {
		t.Fatal(err)
	}
	if code.DeviceCode == "" || !strings.HasPrefix(code.UserCode, "ORL-") {
		t.Fatalf("bad code response: %#v", code)
	}
	if code.Interval != int(devauth.PollInterval.Seconds()) {
		t.Fatalf("interval = %d, want %d", code.Interval, int(devauth.PollInterval.Seconds()))
	}
	if !strings.HasSuffix(code.VerificationURI, "/device") {
		t.Fatalf("verification_uri = %q", code.VerificationURI)
	}

	// 2. First poll → authorization_pending.
	pollResp := postPoll(t, srv.URL, code.DeviceCode)
	if pollResp.StatusCode != 400 {
		t.Fatalf("pre-approval poll status = %d", pollResp.StatusCode)
	}
	if got := decodeError(t, pollResp); got != "authorization_pending" {
		t.Fatalf("error = %s, want authorization_pending", got)
	}

	// 3. Browser looks up quota, then approves via /device/approve with admin cookie.
	req, err := http.NewRequest("GET", srv.URL+"/device/lookup?user_code="+url.QueryEscape(code.UserCode), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	lookupResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer lookupResp.Body.Close()
	if lookupResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(lookupResp.Body)
		t.Fatalf("lookup status = %d, body = %s", lookupResp.StatusCode, body)
	}
	var lookup struct {
		RemainingBytes int64 `json:"remaining_bytes"`
		QuotaBytes     int64 `json:"quota_bytes"`
	}
	if err := json.NewDecoder(lookupResp.Body).Decode(&lookup); err != nil {
		t.Fatal(err)
	}
	if lookup.RemainingBytes != lookup.QuotaBytes || lookup.QuotaBytes == 0 {
		t.Fatalf("bad lookup quota: %#v", lookup)
	}

	req, err = http.NewRequest("POST", srv.URL+"/device/approve", strings.NewReader(`{"user_code":"`+code.UserCode+`","size_bytes":5368709120}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	approveResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer approveResp.Body.Close()
	if approveResp.StatusCode != 200 {
		body, _ := io.ReadAll(approveResp.Body)
		t.Fatalf("approve status = %d, body = %s", approveResp.StatusCode, body)
	}
	var approveBody struct {
		AllocationID string `json:"allocation_id"`
	}
	if err := json.NewDecoder(approveResp.Body).Decode(&approveBody); err != nil {
		t.Fatal(err)
	}
	if approveBody.AllocationID == "" {
		t.Fatal("approval response missing allocation_id")
	}

	// 4. Second poll (after slow_down window) → access_token.
	time.Sleep(devauth.PollInterval + 200*time.Millisecond)
	pollResp = postPoll(t, srv.URL, code.DeviceCode)
	if pollResp.StatusCode != 200 {
		t.Fatalf("post-approval poll status = %d", pollResp.StatusCode)
	}
	var tok struct {
		AccessToken      string    `json:"access_token"`
		AccessExpiresAt  time.Time `json:"access_expires_at"`
		RefreshToken     string    `json:"refresh_token"`
		RefreshExpiresAt time.Time `json:"refresh_expires_at"`
		ControlPlaneURL  string    `json:"control_plane_url"`
		TokenType        string    `json:"token_type"`
		AllocationID     string    `json:"allocation_id"`
		ExpiresIn        int       `json:"expires_in"`
	}
	if err := json.NewDecoder(pollResp.Body).Decode(&tok); err != nil {
		t.Fatal(err)
	}
	pollResp.Body.Close()
	if tok.AccessToken == "" || tok.RefreshToken == "" || tok.TokenType != "Bearer" || tok.ControlPlaneURL != srv.URL {
		t.Fatalf("bad token: %#v", tok)
	}
	if tok.AllocationID != approveBody.AllocationID {
		t.Fatalf("allocation_id = %q, want %q", tok.AllocationID, approveBody.AllocationID)
	}
	if !tok.AccessExpiresAt.After(time.Now()) || !tok.RefreshExpiresAt.After(tok.AccessExpiresAt) {
		t.Fatalf("bad token expiries: %#v", tok)
	}

	// 5. Token resolves through middleware to expected tenant.
	wrapped := RequireBearer(svc, sqlcdb.New(pool))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ident, ok := IdentityFromRequest(r)
		if !ok {
			t.Fatal("identity missing")
		}
		_, _ = w.Write([]byte(ident.TenantID))
	}))
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/probe", nil)
	r.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	wrapped.ServeHTTP(rec, r)
	if rec.Code != 200 || rec.Body.String() != "acme" {
		t.Fatalf("probe code=%d body=%q", rec.Code, rec.Body.String())
	}

	// 6. Refresh endpoint rotates the local session.
	req, err = http.NewRequest(http.MethodPost, srv.URL+"/auth/token/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.RefreshToken)
	refreshResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer refreshResp.Body.Close()
	if refreshResp.StatusCode != 200 {
		body, _ := io.ReadAll(refreshResp.Body)
		t.Fatalf("refresh status = %d body = %s", refreshResp.StatusCode, body)
	}
	var refreshed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(refreshResp.Body).Decode(&refreshed); err != nil {
		t.Fatal(err)
	}
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" || refreshed.RefreshToken == tok.RefreshToken {
		t.Fatalf("bad refresh response: %#v", refreshed)
	}

	req, err = http.NewRequest(http.MethodPost, srv.URL+"/auth/token/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.RefreshToken)
	reuseResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer reuseResp.Body.Close()
	if reuseResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reuse status = %d, want 401", reuseResp.StatusCode)
	}
}

func TestHTTPApproveRequiresAdminCookie(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, _, _ := httpStartServer(t, pool)

	form := url.Values{"user_code": {"ORL-ZZZZ"}, "action": {"approve"}}
	resp, err := http.Post(srv.URL+"/device/approve",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHTTPDeviceSessionQueryParamSetsCookie(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc, _ := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(srv.URL + "/device?session=" + url.QueryEscape(cookie.Value))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	found := false
	for _, c := range resp.Cookies() {
		if c.Name == devauth.AdminSessionCookie && c.Value == cookie.Value && c.HttpOnly {
			found = true
		}
	}
	if !found {
		t.Fatalf("HttpOnly admin cookie not set; cookies=%v", resp.Cookies())
	}
}

func TestHTTPEmailOTPLoginIssuesSession(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, _, mailer := httpStartServer(t, pool)
	email := "alice@example.test"

	resp, err := http.Post(srv.URL+"/auth/otp/start", "application/json", strings.NewReader(`{"email":"`+email+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("start status = %d, want 204", resp.StatusCode)
	}
	code := mailer.code(email)
	if code == "" {
		t.Fatal("mailer did not capture otp code")
	}

	resp, err = http.Post(srv.URL+"/auth/otp/verify", "application/json", strings.NewReader(`{"email":"`+email+`","code":"`+code+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("verify status = %d body = %s", resp.StatusCode, body)
	}
	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == devauth.AdminSessionCookie && c.HttpOnly {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatalf("session cookie not set; cookies=%v", resp.Cookies())
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(sessionCookie)
	meResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer meResp.Body.Close()
	if meResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(meResp.Body)
		t.Fatalf("me status = %d body = %s", meResp.StatusCode, body)
	}
	var me struct {
		UserID     string `json:"user_id"`
		TenantID   string `json:"tenant_id"`
		Purpose    string `json:"purpose"`
		Email      string `json:"email"`
		QuotaBytes int64  `json:"quota_bytes"`
		UsedBytes  int64  `json:"used_bytes"`
	}
	if err := json.NewDecoder(meResp.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	if me.UserID == "" || !strings.HasPrefix(me.TenantID, "user_") || me.Purpose != devauth.PurposeAdmin {
		t.Fatalf("bad /api/me: %#v", me)
	}
	if me.Email != email {
		t.Fatalf("/api/me email = %q, want %q", me.Email, email)
	}
	if me.QuotaBytes <= 0 {
		t.Fatalf("/api/me quota_bytes = %d, want default > 0", me.QuotaBytes)
	}
	if me.UsedBytes != 0 {
		t.Fatalf("/api/me used_bytes = %d, want 0 (no allocations)", me.UsedBytes)
	}
}

// TestHTTPEmailOTPVerifyExposesIsNewUser pins the contract the dashboard
// relies on for its one-time welcome banner: first successful verify for a
// brand-new email returns is_new_user=true; a second login by the same email
// returns is_new_user=false. Pre-OTP-submission endpoints must never leak
// this — only the verify response, after the user has proven email control.
func TestHTTPEmailOTPVerifyExposesIsNewUser(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, _, mailer := httpStartServer(t, pool)
	email := "welcome-banner@example.test"

	verify := func() bool {
		t.Helper()
		resp, err := http.Post(srv.URL+"/auth/otp/start", "application/json", strings.NewReader(`{"email":"`+email+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		code := mailer.code(email)
		if code == "" {
			t.Fatal("no otp code captured")
		}
		resp, err = http.Post(srv.URL+"/auth/otp/verify", "application/json", strings.NewReader(`{"email":"`+email+`","code":"`+code+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("verify status = %d body = %s", resp.StatusCode, body)
		}
		var body struct {
			IsNewUser bool `json:"is_new_user"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return body.IsNewUser
	}

	if !verify() {
		t.Fatal("first verify: want is_new_user=true, got false")
	}
	if verify() {
		t.Fatal("second verify: want is_new_user=false, got true")
	}
}

func TestHTTPEmailOTPSingleUse(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, _, mailer := httpStartServer(t, pool)
	email := "single@example.test"
	if resp, err := http.Post(srv.URL+"/auth/otp/start", "application/json", strings.NewReader(`{"email":"`+email+`"}`)); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
	}
	code := mailer.code(email)
	if code == "" {
		t.Fatal("mailer did not capture otp code")
	}
	body := `{"email":"` + email + `","code":"` + code + `"}`
	resp, err := http.Post(srv.URL+"/auth/otp/verify", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first verify status = %d, want 200", resp.StatusCode)
	}
	resp, err = http.Post(srv.URL+"/auth/otp/verify", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("second verify status = %d, want 401", resp.StatusCode)
	}
}

func TestHTTPEmailOTPExpired(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, _, mailer := httpStartServer(t, pool)
	email := "expired@example.test"
	resp, err := http.Post(srv.URL+"/auth/otp/start", "application/json", strings.NewReader(`{"email":"`+email+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	code := mailer.code(email)
	if code == "" {
		t.Fatal("mailer did not capture otp code")
	}
	if _, err := pool.Exec(context.Background(), "UPDATE email_otps SET expires_at = now() - interval '1 minute' WHERE email = $1", email); err != nil {
		t.Fatal(err)
	}
	resp, err = http.Post(srv.URL+"/auth/otp/verify", "application/json", strings.NewReader(`{"email":"`+email+`","code":"`+code+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("verify status = %d, want 401", resp.StatusCode)
	}
	if got := decodeError(t, resp); got != "expired_token" {
		t.Fatalf("error = %s, want expired_token", got)
	}
}

func TestHTTPEmailOTPStartRateLimitByEmail(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, _, mailer := httpStartServer(t, pool)
	email := "limit@example.test"
	for i := 0; i < 6; i++ {
		resp, err := http.Post(srv.URL+"/auth/otp/start", "application/json", strings.NewReader(`{"email":"`+email+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("start status = %d, want 204", resp.StatusCode)
		}
	}
	if got := mailer.sendCount(email); got != 5 {
		t.Fatalf("sends = %d, want 5", got)
	}
}

func TestHTTPBearerRejectsMissing(t *testing.T) {
	pool := httpOpenTestPool(t)
	_, svc, _ := httpStartServer(t, pool)
	wrapped := RequireBearer(svc, sqlcdb.New(pool))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
}

func postPoll(t *testing.T, base, deviceCode string) *http.Response {
	t.Helper()
	form := url.Values{"device_code": {deviceCode}, "grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}}
	resp, err := http.Post(base+"/auth/device/token",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func decodeError(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.Error
}

func httpCreateDeviceCode(t *testing.T, srvURL string) string {
	t.Helper()
	resp, err := http.Post(srvURL+"/auth/device/code", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var code struct {
		UserCode string `json:"user_code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&code); err != nil {
		t.Fatal(err)
	}
	return code.UserCode
}

func TestHTTPApproveReusesExistingAllocation(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc, _ := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	asvc := dashAllocSvc(pool)

	existing, err := asvc.Allocate(context.Background(), userID, 3*dashGiB)
	if err != nil {
		t.Fatal(err)
	}

	userCode := httpCreateDeviceCode(t, srv.URL)

	body := `{"user_code":"` + userCode + `","allocation_id":"` + uuidString(existing.ID) + `"}`
	req, err := http.NewRequest("POST", srv.URL+"/device/approve", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, b)
	}
	var ar struct {
		AllocationID string `json:"allocation_id"`
		SizeBytes    int64  `json:"size_bytes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		t.Fatal(err)
	}
	if ar.AllocationID != uuidString(existing.ID) {
		t.Fatalf("allocation_id = %s, want %s", ar.AllocationID, uuidString(existing.ID))
	}
	if ar.SizeBytes != 3*dashGiB {
		t.Fatalf("size_bytes = %d, want %d", ar.SizeBytes, 3*dashGiB)
	}

	rows, err := asvc.ListForUser(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("user has %d allocations, want 1 (no new disk should be created)", len(rows))
	}
}

func TestHTTPApproveCrossUserAllocation(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc, _ := httpStartServer(t, pool)
	owner, _ := httpSeedAdmin(t, pool, svc)
	other, _ := httpSeedAdmin(t, pool, svc)
	ownerID := dashGetUserID(t, owner, srv.URL)
	asvc := dashAllocSvc(pool)
	stranger, err := asvc.Allocate(context.Background(), ownerID, dashGiB)
	if err != nil {
		t.Fatal(err)
	}

	userCode := httpCreateDeviceCode(t, srv.URL)

	body := `{"user_code":"` + userCode + `","allocation_id":"` + uuidString(stranger.ID) + `"}`
	req, err := http.NewRequest("POST", srv.URL+"/device/approve", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(other)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s, want 404", resp.StatusCode, b)
	}
}

func TestHTTPApproveRevokedAllocation(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc, _ := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	asvc := dashAllocSvc(pool)
	alloc, err := asvc.Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatal(err)
	}
	if err := asvc.Revoke(context.Background(), alloc.ID, userID); err != nil {
		t.Fatal(err)
	}

	userCode := httpCreateDeviceCode(t, srv.URL)

	body := `{"user_code":"` + userCode + `","allocation_id":"` + uuidString(alloc.ID) + `"}`
	req, err := http.NewRequest("POST", srv.URL+"/device/approve", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s, want 410", resp.StatusCode, b)
	}
}

func TestHTTPApproveBothFieldsRejected(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc, _ := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	asvc := dashAllocSvc(pool)
	alloc, err := asvc.Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatal(err)
	}

	userCode := httpCreateDeviceCode(t, srv.URL)

	body := `{"user_code":"` + userCode + `","size_bytes":1073741824,"allocation_id":"` + uuidString(alloc.ID) + `"}`
	req, err := http.NewRequest("POST", srv.URL+"/device/approve", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s, want 400", resp.StatusCode, b)
	}
}

func TestHTTPApproveNeitherFieldRejected(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc, _ := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)

	userCode := httpCreateDeviceCode(t, srv.URL)

	body := `{"user_code":"` + userCode + `"}`
	req, err := http.NewRequest("POST", srv.URL+"/device/approve", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s, want 400", resp.StatusCode, b)
	}
}
