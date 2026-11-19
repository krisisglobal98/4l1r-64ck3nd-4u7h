//go:build e2e

// Black-box tests of the Authentication service over HTTP: the real handlers and database (TEST_DATABASE_URL),
// a fake Portal Master (the organisation tree) and a clock the tests move (token expiry, idle sessions).
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"alir.local/auth-service/internal/auth"
	"alir.local/auth-service/internal/oidcrp"
	"alir.local/auth-service/internal/platform/codeprefix"
	"alir.local/auth-service/internal/platform/config"
	"alir.local/auth-service/internal/platform/database"
	"alir.local/auth-service/internal/platform/httpx"
	"alir.local/auth-service/internal/platform/httpx/reqid"
	"alir.local/auth-service/internal/secretbox"
	"alir.local/auth-service/internal/token"
)

const adminPassword = "AdminAwal2026"

var (
	server *httptest.Server
	pool   *pgxpool.Pool
	svc    *auth.Service
	clock  = struct {
		sync.Mutex
		offset time.Duration
	}{}
	pmCalls struct {
		sync.Mutex
		auth []string
	}
)

// employees are the Karyawan of the fake Portal Master; tests switch them off and on.
var employees = struct {
	sync.Mutex
	list []map[string]any
}{list: []map[string]any{
	{"id": "01a1f100-0000-7000-8000-000000000001", "code": "E001", "name": "Budi Santoso", "nik": "102001", "email": "budi.santoso@contoh.co.id", "active": true},
	{"id": "01a1f100-0000-7000-8000-000000000002", "code": "E002", "name": "Sari Lestari", "nik": "102002", "email": "sari.lestari@contoh.co.id", "active": true},
	{"id": "01a1f100-0000-7000-8000-000000000003", "code": "E003", "name": "Tanpa Email", "nik": "102003", "email": nil, "active": true},
	{"id": "01a1f100-0000-7000-8000-000000000004", "code": "E004", "name": "Sudah Keluar", "nik": "102004", "email": "keluar@contoh.co.id", "active": false},
	{"id": "01a1f100-0000-7000-8000-000000000005", "code": "E005", "name": "Dewi Anggraini", "nik": "102005", "email": "dewi@contoh.co.id", "active": true},
	{"id": "01a1f100-0000-7000-8000-000000000006", "code": "E006", "name": "Mail Uji", "nik": "102006", "email": "mail.uji@contoh.co.id", "active": true},
	{"id": "01a1f100-0000-7000-8000-000000000007", "code": "E007", "name": "Nama Asli", "nik": "102007", "email": nil, "active": true},
	{"id": "01a1f100-0000-7000-8000-000000000008", "code": "E008", "name": "Rina Ganda", "nik": "102008", "email": "rina.ganda@contoh.co.id", "active": true},
}}

// setEmployeeActive switches an employee in the fake Portal Master and makes the service read it again.
func setEmployeeActive(t testing.TB, a *client, code string, active bool) {
	t.Helper()
	employees.Lock()
	for _, e := range employees.list {
		if e["code"] == code {
			e["active"] = active
		}
	}
	employees.Unlock()
	must(t, a.do(t, "POST", "/org/sync", nil), 200)
}

// advance moves the service's clock forward.
func advance(d time.Duration) {
	clock.Lock()
	clock.offset += d
	clock.Unlock()
}

func now() time.Time {
	clock.Lock()
	defer clock.Unlock()
	return time.Now().Add(clock.offset)
}

// The fake Portal Master: GAN (group) → KAL (region) → KALBAR (wilayah) → C11, C12 (companies) → C11-E1, C12-E1
// (units) → C11-E1-R1 (org1) → C11-E1-R1-A1 (org2) → C11-E1-R1-A1-B1 (org3); C12-E1 is inactive.
func fakePM() *httptest.Server {
	unit := func(code, name, level string, parent any, active bool) map[string]any {
		return map[string]any{"code": code, "name": name, "levelCode": level, "parentCode": parent, "active": active}
	}
	units := []map[string]any{
		unit("GAN", "Grup Agro", "group", nil, true), unit("KAL", "Region Kalimantan", "region", "GAN", true),
		unit("KALBAR", "Wilayah Kalbar", "wilayah", "KAL", true), unit("C11", "PT Satu", "company", "KALBAR", true),
		unit("C12", "PT Dua", "company", "KALBAR", true), unit("C11-E1", "Kebun Satu", "unit", "C11", true),
		unit("C12-E1", "Kebun Dua", "unit", "C12", false), unit("C11-E2", "Kebun Tiga", "unit", "C11", true),
		unit("C11-E1-R1", "Rayon A", "org1", "C11-E1", true), unit("C11-E1-R1-A1", "Afdeling 01", "org2", "C11-E1-R1", true),
		unit("C11-E1-R1-A1-B1", "Blok 001", "org3", "C11-E1-R1-A1", true),
	}
	levels := []map[string]any{{"code": "group", "name": "Group"}, {"code": "unit", "name": "Unit Operasional"}, {"code": "org1", "name": "Rayon"}, {"code": "org2", "name": "Afdeling"}, {"code": "org3", "name": "Blok"}}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pmCalls.Lock()
		pmCalls.auth = append(pmCalls.auth, r.Header.Get("Authorization"))
		pmCalls.Unlock()
		switch r.URL.Path {
		case "/pm/masters/org-units":
			_ = json.NewEncoder(w).Encode(units)
		case "/pm/masters/levels":
			_ = json.NewEncoder(w).Encode(levels)
		case "/pm/masters/employees":
			employees.Lock()
			_ = json.NewEncoder(w).Encode(employees.list)
			employees.Unlock()
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestMain(m *testing.M) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" || !strings.Contains(dsn, "_test") {
		fmt.Println("TEST_DATABASE_URL (a *_test database) is required")
		os.Exit(2)
	}
	ctx := context.Background()
	db, err := database.Open(ctx, dsn)
	if err != nil {
		panic(err)
	}
	pool = db.Pool
	reset()
	keys, err := token.Load(ctx, db)
	if err != nil {
		panic(err)
	}
	pm := fakePM()
	cfg := config.Config{Issuer: "alir-auth", AccessTTL: 15 * time.Minute, CookieSecure: false, CookiePath: "/auth", AdminUsername: "admin", AdminPassword: adminPassword, PMURL: pm.URL, AppBaseURL: "http://alir.test", SSOCookiePath: "/oauth2"}
	svc = &auth.Service{DB: db, Keys: keys, Cfg: cfg, Codes: codeprefix.Postgres{DB: db}, Now: now,
		Org: &auth.Org{PMURL: pm.URL, Keys: keys, Issuer: cfg.Issuer, Client: pm.Client()}}
	if _, err := svc.Bootstrap(ctx); err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	svc.Routes(mux)
	server = httptest.NewServer(httpx.Chain(mux, reqid.Middleware, httpx.Recover, httpx.JSONErrors, svc.Authenticate))
	svc.Cfg.PublicURL = server.URL
	svc.RP = &oidcrp.Client{HTTP: http.DefaultClient}
	if svc.Box, err = secretbox.New(testSecretKey); err != nil {
		panic(err)
	}
	svc.Limits = &testLimits
	code := m.Run()
	server.Close()
	pm.Close()
	reset()
	db.Pool.Close()
	os.Exit(code)
}

// testSecretKey seals the suite's secrets (32 zero-free bytes, base64).
const testSecretKey = "dGVzdC1rZXktdGVzdC1rZXktdGVzdC1rZXktMzJieXQ="

// testLimits: the whole suite signs in from one address, so per-address limits are wide; per-email limits are the
// production ones (the rate tests narrow them).
var testLimits = func() auth.Limits {
	l := auth.DefaultLimits
	wide := auth.Limit{Max: 100000, Window: time.Hour}
	l.SignupPerIP, l.ResendPerIP, l.OTPPerIP, l.LoginPerIP = wide, wide, wide, wide
	return l
}()

// reset empties the accounts, sessions and audit; roles back to the built-in four without grants.
func reset() {
	for _, q := range []string{
		`DELETE FROM auth.mail_outbox`, `DELETE FROM auth.mfa_challenge`, `DELETE FROM auth.recovery_code`, `DELETE FROM auth.mfa_factor`,
		`DELETE FROM auth.idp_login`, `DELETE FROM auth.identity_provider`, `DELETE FROM auth.email_token`, `DELETE FROM auth.login_otp`, `DELETE FROM auth.rate_event`, `DELETE FROM auth.auth_code`, `DELETE FROM auth.authz_request`, `DELETE FROM auth.oauth_grant`,
		`DELETE FROM auth.oauth_client WHERE lower(code) <> 'alir-web'`, `DELETE FROM auth.session`, `DELETE FROM auth.password_reset`, `DELETE FROM auth.password_history`, `DELETE FROM auth.audit_event`,
		`DELETE FROM auth.unit_access`, `DELETE FROM auth.identity_link`, `DELETE FROM auth.membership`, `DELETE FROM auth.identity`, `DELETE FROM auth.role_grant`,
		`DELETE FROM auth.role WHERE NOT is_system OR tenant_id <> '` + auth.DefaultTenantID + `'`,
		`UPDATE auth.role SET is_active = true, updated_at = NULL, updated_by = NULL, version = 1`,
		`DELETE FROM auth.code_prefix WHERE tenant_id <> '` + auth.DefaultTenantID + `'`,
		`DELETE FROM auth.security_policy WHERE tenant_id <> '` + auth.DefaultTenantID + `'`,
		`DELETE FROM auth.tenant WHERE id <> '` + auth.DefaultTenantID + `'`,
		`UPDATE auth.tenant SET is_active = true, version = 1, updated_at = NULL, updated_by = NULL`,
		`UPDATE auth.code_prefix SET last_number = 0`,
		`UPDATE auth.security_policy SET password_min_length = 8, require_uppercase = false, require_number = true, require_symbol = false,
		 password_expiry_days = 0, password_history = 0, max_failed_attempts = 5, lockout_minutes = 15, session_hours = 8, idle_minutes = 0,
		 allow_concurrent_sessions = true, allow_local_login = true, sso_enabled = false, sso_issuer = NULL, sso_client_id = NULL,
		 self_signup_enabled = false, self_signup_role_id = NULL, allow_email_otp = true, mfa_mode = 'optional'`,
	} {
		if _, err := pool.Exec(context.Background(), q); err != nil {
			panic(err)
		}
	}
}

/* ---------------- HTTP helpers ---------------- */

// client is one browser: its own cookie jar (the refresh cookie) and access token.
type client struct {
	http  *http.Client
	token string
}

func newClient() *client {
	jar, _ := cookiejar.New(nil)
	// Redirects are answers to look at (the OIDC flow), never followed.
	return &client{http: &http.Client{Jar: jar, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

type resp struct {
	Status int
	Raw    []byte
	Obj    map[string]any
	List   []map[string]any
}

func (r resp) str(k string) string { s, _ := r.Obj[k].(string); return s }

func (r resp) problem(field string) string {
	d, _ := r.Obj["details"].(map[string]any)
	ps, _ := d["problems"].([]any)
	for _, p := range ps {
		if m := p.(map[string]any); m["field"] == field {
			return m["message"].(string)
		}
	}
	return ""
}

// do sends a request; an expired token is renewed with the refresh cookie and the call repeated, as the frontend.
func (c *client) do(t testing.TB, method, path string, body any) resp {
	t.Helper()
	r := c.send(t, method, path, body)
	if r.Status == 401 && r.str("code") == "TOKEN_EXPIRED" && path != "/auth/refresh" {
		if x := c.send(t, "POST", "/auth/refresh", nil); x.Status == 200 {
			c.token = x.str("token")
			return c.send(t, method, path, body)
		}
	}
	return r
}

func (c *client) send(t testing.TB, method, path string, body any) resp {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, server.URL+path, rd)
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	res, err := c.http.Do(req)
	if err != nil {
		t.Errorf("%s %s: %v", method, path, err)
		return resp{}
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := resp{Status: res.StatusCode, Raw: raw}
	if len(raw) > 0 && raw[0] == '[' {
		_ = json.Unmarshal(raw, &out.List)
	} else {
		_ = json.Unmarshal(raw, &out.Obj)
	}
	return out
}

// login signs in and keeps the token; the refresh cookie stays in the jar.
func (c *client) login(t testing.TB, username, pw string) resp {
	t.Helper()
	r := c.do(t, "POST", "/auth/login", map[string]any{"username": username, "password": pw})
	if r.Status == 200 {
		c.token = r.str("token")
	}
	return r
}

func want(t testing.TB, r resp, status int) bool {
	t.Helper()
	if r.Status != status {
		t.Errorf("status %d, want %d: %s", r.Status, status, trunc(r.Raw))
		return false
	}
	return true
}

func must(t testing.TB, r resp, status int) resp {
	t.Helper()
	if r.Status != status {
		t.Fatalf("status %d, want %d: %s", r.Status, status, trunc(r.Raw))
	}
	return r
}

func trunc(b []byte) string {
	if len(b) > 300 {
		return string(b[:300]) + "…"
	}
	return string(b)
}

var adminOnce sync.Mutex
var adminPw = adminPassword

// admin is a signed-in administrator (the first sign-in changes the bootstrap password).
func admin(t testing.TB) *client {
	t.Helper()
	adminOnce.Lock()
	defer adminOnce.Unlock()
	c := newClient()
	r := must(t, c.login(t, "admin", adminPw), 200)
	if r.Obj["mustChangePassword"] != nil {
		must(t, c.do(t, "POST", "/auth/password/change", map[string]any{"next": "AdminTetap2026"}), 204)
		adminPw = "AdminTetap2026"
		must(t, c.login(t, "admin", adminPw), 200)
	}
	return c
}

var userSeq struct {
	sync.Mutex
	n int
}

// newUser makes an active account at the operational unit C11-E1 with role and a password it has already changed.
func newUser(t testing.TB, a *client, role string) (username, id string) {
	t.Helper()
	userSeq.Lock()
	userSeq.n++
	username = fmt.Sprintf("user%03d", userSeq.n)
	userSeq.Unlock()
	r := must(t, a.do(t, "POST", "/users", map[string]any{"username": username, "name": "Pengguna Uji", "role": role, "levelCode": "OPERATIONAL_UNIT",
		"companyCode": "C11", "operationalUnitCode": "C11-E1", "password": "Awal2026x"}), 201)
	c := newClient()
	must(t, c.login(t, username, "Awal2026x"), 200)
	must(t, c.do(t, "POST", "/auth/password/change", map[string]any{"next": "Tetap2026x"}), 204)
	return username, r.str("id")
}

func parallel(n, workers int, fn func(i int)) {
	var wg sync.WaitGroup
	jobs := make(chan int)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				fn(i)
			}
		}()
	}
	for i := range n {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
}
