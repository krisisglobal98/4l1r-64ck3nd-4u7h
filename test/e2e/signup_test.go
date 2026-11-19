//go:build e2e

// Self sign-up, email verification, sign-in with an email code, abuse protection, and the API applications use
// to activate, verify or upgrade members.
package e2e

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"alir.local/auth-service/internal/auth"
)

var signupSeq atomic.Int64

func newEmail(tag string) string {
	return fmt.Sprintf("%s.%d@vendor.test", tag, signupSeq.Add(1))
}

var tokenInMail = regexp.MustCompile(`token=([A-Za-z0-9_-]+)`)
var codeInSubject = regexp.MustCompile(`(\d{6})$`)

// lastMail is the newest queued mail of kind to an address ("" when none).
func lastMail(t *testing.T, kind, to string) (subject, body string) {
	t.Helper()
	m := outbox(t, kind, to)
	if len(m) == 0 {
		return "", ""
	}
	return m[len(m)-1]["subject"].(string), m[len(m)-1]["body"].(string)
}

func verifyToken(t *testing.T, email string) string {
	t.Helper()
	_, body := lastMail(t, "email_verify", email)
	m := tokenInMail.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no verification mail to %s", email)
	}
	return m[1]
}

func otpCode(t *testing.T, email string) string {
	t.Helper()
	subject, _ := lastMail(t, "login_otp", email)
	m := codeInSubject.FindStringSubmatch(subject)
	if m == nil {
		t.Fatalf("no code mail to %s", email)
	}
	return m[1]
}

var signupPolicy sync.Once

// openSignup lets gan accept sign-ups as viewer (once).
func openSignup(t *testing.T, a *client) {
	signupPolicy.Do(func() {
		p := must(t, a.do(t, "GET", "/auth/policy", nil), 200).Obj
		p["selfSignupEnabled"], p["selfSignupRole"] = true, "viewer"
		must(t, a.do(t, "PUT", "/auth/policy", p), 200)
	})
}

func signup(t *testing.T, email, pw string, extra map[string]any) resp {
	t.Helper()
	b := map[string]any{"tenant": "gan", "email": email, "name": "Vendor Uji", "password": pw, "acceptTerms": true}
	for k, v := range extra {
		b[k] = v
	}
	return newClient().do(t, "POST", "/auth/signup", b)
}

func identities(t *testing.T, email string) int {
	var n int
	_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM auth.identity WHERE email = $1`, email).Scan(&n)
	return n
}

func TestSignupPositive(t *testing.T) {
	a := admin(t)
	openSignup(t, a)

	t.Run("SP01 the company's sign-in page says sign-up and email codes are open, with the terms", func(t *testing.T) {
		o := must(t, newClient().do(t, "GET", "/auth/login-options?tenant=gan", nil), 200)
		if o.Obj["selfSignup"] != true || o.Obj["emailOtp"] != true || o.Obj["terms"].(map[string]any)["version"] == nil || o.Obj["captcha"] != nil {
			t.Errorf("options %s", o.Raw)
		}
	})

	t.Run("SP02 sign up, sign-in refused until verified, verify, sign in as an external member", func(t *testing.T) {
		email := newEmail("baru")
		r := signup(t, email, "Vendor2026x", nil)
		if r.Status != 202 || r.str("status") != "check_email" {
			t.Fatalf("signup %d %s", r.Status, r.Raw)
		}
		if x := newClient().loginIn(t, email, "Vendor2026x", ""); x.Status != 403 || x.str("code") != "EMAIL_UNVERIFIED" {
			t.Errorf("before verification: %d %s", x.Status, x.Raw)
		}
		v := must(t, newClient().do(t, "POST", "/auth/email/verify", map[string]any{"token": verifyToken(t, email)}), 200)
		if v.Obj["verified"] != true || v.Obj["tenant"].(map[string]any)["code"] != "gan" {
			t.Errorf("verify %s", v.Raw)
		}
		c := newClient()
		l := must(t, c.loginIn(t, email, "Vendor2026x", ""), 200)
		if l.Obj["user"].(map[string]any)["role"] != "viewer" || l.Obj["mustChangePassword"] != nil {
			t.Errorf("login %s", trunc(l.Raw))
		}
		for _, u := range must(t, a.do(t, "GET", "/users", nil), 200).List {
			if u["email"] == email && (u["kind"] != "external" || u["levelCode"] != nil || !strings.HasPrefix(u["username"].(string), "baru.")) {
				t.Errorf("member %v", u)
			}
		}
	})

	t.Run("SP03 sign in with a code sent by email; the code works once", func(t *testing.T) {
		email := newEmail("kode")
		signup(t, email, "Vendor2026x", nil)
		must(t, newClient().do(t, "POST", "/auth/email/verify", map[string]any{"token": verifyToken(t, email)}), 200)
		must(t, newClient().do(t, "POST", "/auth/otp/request", map[string]any{"email": email}), 202)
		code := otpCode(t, email)
		c := newClient()
		r := must(t, c.do(t, "POST", "/auth/otp/verify", map[string]any{"email": email, "code": code}), 200)
		c.token = r.str("token")
		if sessions := must(t, c.do(t, "GET", "/auth/me/sessions", nil), 200).List; len(sessions) == 0 || sessions[0]["method"] != "otp" {
			t.Errorf("session method %v", sessions)
		}
		if x := newClient().do(t, "POST", "/auth/otp/verify", map[string]any{"email": email, "code": code}); x.Status != 401 || x.str("code") != "INVALID_CODE" {
			t.Errorf("code twice: %d %s", x.Status, x.Raw)
		}
	})

	t.Run("SP04 a correct code also confirms an email that was never verified", func(t *testing.T) {
		email := newEmail("tanpaklik")
		signup(t, email, "Vendor2026x", nil)
		must(t, newClient().do(t, "POST", "/auth/otp/request", map[string]any{"email": email}), 202)
		must(t, newClient().do(t, "POST", "/auth/otp/verify", map[string]any{"email": email, "code": otpCode(t, email)}), 200)
		if x := newClient().loginIn(t, email, "Vendor2026x", ""); x.Status != 200 {
			t.Errorf("password after the code confirmed the email: %d %s", x.Status, x.Raw)
		}
	})

	t.Run("SP05 a person joins another company that accepts sign-ups", func(t *testing.T) {
		b := betaAdmin(t)
		p := must(t, b.do(t, "GET", "/auth/policy", nil), 200).Obj
		p["selfSignupEnabled"], p["selfSignupRole"] = true, "viewer"
		must(t, b.do(t, "PUT", "/auth/policy", p), 200)
		defer func() {
			p["selfSignupEnabled"], p["selfSignupRole"] = false, nil
			b.do(t, "PUT", "/auth/policy", p)
		}()
		email := newEmail("gabung")
		signup(t, email, "Vendor2026x", nil)
		must(t, newClient().do(t, "POST", "/auth/email/verify", map[string]any{"token": verifyToken(t, email)}), 200)
		c := newClient()
		must(t, c.loginIn(t, email, "Vendor2026x", ""), 200)
		j := must(t, c.do(t, "POST", "/auth/join", map[string]any{"tenant": "beta"}), 201)
		if j.str("code") != "beta" {
			t.Errorf("join %s", j.Raw)
		}
		if x := c.do(t, "POST", "/auth/join", map[string]any{"tenant": "beta"}); x.Status != 409 {
			t.Errorf("join twice: %d", x.Status)
		}
		if sw := must(t, c.do(t, "POST", "/auth/switch-tenant", map[string]any{"tenant": "beta"}), 200); tenantOf(sw) != "beta" {
			t.Errorf("switch %s", trunc(sw.Raw))
		}
	})

	t.Run("SP06 an application verifies and upgrades a member with its service token", func(t *testing.T) {
		role := must(t, a.do(t, "POST", "/roles", map[string]any{"name": "Pengelola Vendor"}), 201).str("code")
		must(t, a.do(t, "PUT", "/roles/"+role+"/permissions", map[string]any{"grants": map[string]any{"auth.users": []string{"read", "update"}}}), 200)
		svcApp := register(t, a, map[string]any{"name": "Aplikasi Tender", "serviceRole": role})
		_, tk := newClient().call(t, "POST", "/oauth2/token", url.Values{"grant_type": {"client_credentials"}}, &svcApp)
		appClient := newClient()
		appClient.token = tk.str("access_token")
		email := newEmail("tender")
		signup(t, email, "Vendor2026x", nil)
		var id string
		for _, u := range must(t, appClient.do(t, "GET", "/users", nil), 200).List {
			if u["email"] == email {
				id = u["id"].(string)
			}
		}
		if id == "" {
			t.Fatal("the application does not see the new member")
		}
		r := must(t, appClient.do(t, "POST", "/users/"+id+"/access", map[string]any{"verified": true, "role": "analyst"}), 200)
		if r.Obj["verifiedAt"] == nil || r.str("role") != "analyst" {
			t.Errorf("access %s", trunc(r.Raw))
		}
		if x := appClient.do(t, "POST", "/users/"+id+"/access", map[string]any{"role": "admin"}); x.Status != 422 {
			t.Errorf("an application makes an Admin: %d", x.Status)
		}
		if x := appClient.do(t, "POST", "/users", map[string]any{"username": "x"}); x.Status != 403 {
			t.Errorf("beyond its grants: %d", x.Status)
		}
		au := must(t, a.do(t, "GET", "/auth/audit?q=diverifikasi&size=5", nil), 200)
		if au.Obj["total"].(float64) == 0 {
			t.Errorf("no audit of the verification")
		}
	})

	t.Run("SP07 sign-ups never verified are removed after 7 days", func(t *testing.T) {
		email := newEmail("lupa")
		signup(t, email, "Vendor2026x", nil)
		_, _ = pool.Exec(context.Background(), `UPDATE auth.identity SET created_at = now() - interval '8 days' WHERE email = $1`, email)
		n, err := svc.Cleanup(context.Background())
		if err != nil || n < 1 || identities(t, email) != 0 {
			t.Errorf("cleanup: %v %d left %d", err, n, identities(t, email))
		}
		if r := signup(t, email, "Vendor2026y", nil); r.Status != 202 || identities(t, email) != 1 {
			t.Errorf("the email is free again: %d", r.Status)
		}
	})
}

func TestSignupNegative(t *testing.T) {
	a := admin(t)
	openSignup(t, a)
	b := betaAdmin(t)

	t.Run("SN01 a company that does not accept sign-ups, an unknown or missing company", func(t *testing.T) {
		if r := signup(t, newEmail("x"), "Vendor2026x", map[string]any{"tenant": "beta"}); r.Status != 403 || r.str("code") != "SIGNUP_CLOSED" {
			t.Errorf("closed: %d %s", r.Status, r.Raw)
		}
		if r := signup(t, newEmail("x"), "Vendor2026x", map[string]any{"tenant": "tidak-ada"}); r.Status != 422 {
			t.Errorf("unknown: %d", r.Status)
		}
		if r := signup(t, newEmail("x"), "Vendor2026x", map[string]any{"tenant": ""}); r.Status != 422 {
			t.Errorf("missing: %d", r.Status)
		}
	})

	t.Run("SN02 the form is checked: email, password rules, terms", func(t *testing.T) {
		for name, x := range map[string]map[string]any{
			"bad email": {"email": "bukan-email"}, "weak password": {"password": "pendek"}, "no terms": {"acceptTerms": false},
			"no name": {"name": " "},
		} {
			email, _ := x["email"].(string)
			if email == "" {
				email = newEmail("form")
			}
			pw, _ := x["password"].(string)
			if pw == "" {
				pw = "Vendor2026x"
			}
			if r := signup(t, email, pw, x); r.Status != 422 {
				t.Errorf("%s: %d %s", name, r.Status, r.Raw)
			}
		}
	})

	t.Run("SN03 no account probing: a known email gets the same answer, a notice, and keeps its password", func(t *testing.T) {
		known := "admin@beta.test"
		r := signup(t, known, "Pengambil2026", nil)
		if r.Status != 202 || r.str("status") != "check_email" || identities(t, known) != 1 {
			t.Errorf("known email: %d %s", r.Status, r.Raw)
		}
		if s, _ := lastMail(t, "signup_exists", known); s == "" {
			t.Errorf("no notice to the owner")
		}
		if x := newClient().loginIn(t, known, "Pengambil2026", ""); x.Status != 401 {
			t.Errorf("the sign-up must not change a password: %d", x.Status)
		}
		for _, path := range []string{"/auth/email/resend", "/auth/otp/request"} {
			x := newClient().do(t, "POST", path, map[string]any{"email": "tidak.ada@vendor.test"})
			if x.Status != 202 || x.str("status") != "check_email" {
				t.Errorf("%s unknown email: %d %s", path, x.Status, x.Raw)
			}
		}
		if s, _ := lastMail(t, "login_otp", "tidak.ada@vendor.test"); s != "" {
			t.Errorf("a code mailed to an unknown email")
		}
		_ = b
	})

	t.Run("SN04 signing up again while waiting does not change the password", func(t *testing.T) {
		email := newEmail("ulang")
		signup(t, email, "Pertama2026", nil)
		signup(t, email, "Kedua20266x", nil)
		must(t, newClient().do(t, "POST", "/auth/email/verify", map[string]any{"token": verifyToken(t, email)}), 200)
		if x := newClient().loginIn(t, email, "Pertama2026", ""); x.Status != 200 {
			t.Errorf("first password: %d", x.Status)
		}
		if x := newClient().loginIn(t, email, "Kedua20266x", ""); x.Status != 401 {
			t.Errorf("second password: %d", x.Status)
		}
	})

	t.Run("SN05 email codes: five wrong tries burn the code; expired and other people's codes fail", func(t *testing.T) {
		email := newEmail("tebak")
		signup(t, email, "Vendor2026x", nil)
		must(t, newClient().do(t, "POST", "/auth/otp/request", map[string]any{"email": email}), 202)
		code := otpCode(t, email)
		wrong := fmt.Sprintf("%06d", (atoi(code)+1)%1000000)
		for i := 0; i < 5; i++ {
			newClient().do(t, "POST", "/auth/otp/verify", map[string]any{"email": email, "code": wrong})
		}
		if x := newClient().do(t, "POST", "/auth/otp/verify", map[string]any{"email": email, "code": code}); x.Status != 401 {
			t.Errorf("the code after 5 wrong tries: %d", x.Status)
		}
		must(t, newClient().do(t, "POST", "/auth/otp/request", map[string]any{"email": email}), 202)
		code = otpCode(t, email)
		other := newEmail("lain")
		signup(t, other, "Vendor2026x", nil)
		if x := newClient().do(t, "POST", "/auth/otp/verify", map[string]any{"email": other, "code": code}); x.Status != 401 {
			t.Errorf("someone else's code: %d", x.Status)
		}
		_, _ = pool.Exec(context.Background(), `UPDATE auth.login_otp SET expires_at = now() - interval '1 second' WHERE used_at IS NULL`)
		if x := newClient().do(t, "POST", "/auth/otp/verify", map[string]any{"email": email, "code": code}); x.Status != 401 {
			t.Errorf("expired code: %d", x.Status)
		}
	})

	t.Run("SN06 a verification link works once and expires", func(t *testing.T) {
		email := newEmail("tautan")
		signup(t, email, "Vendor2026x", nil)
		tok := verifyToken(t, email)
		must(t, newClient().do(t, "POST", "/auth/email/verify", map[string]any{"token": tok}), 200)
		if x := newClient().do(t, "POST", "/auth/email/verify", map[string]any{"token": tok}); x.Status != 409 {
			t.Errorf("link twice: %d", x.Status)
		}
		email = newEmail("basi")
		signup(t, email, "Vendor2026x", nil)
		tok = verifyToken(t, email)
		_, _ = pool.Exec(context.Background(), `UPDATE auth.email_token SET expires_at = now() - interval '1 second' WHERE used_at IS NULL`)
		if x := newClient().do(t, "POST", "/auth/email/verify", map[string]any{"token": tok}); x.Status != 409 {
			t.Errorf("expired link: %d", x.Status)
		}
	})

	t.Run("SN07 rate limits per email: sign-up, email codes", func(t *testing.T) {
		email := newEmail("banjir")
		for i := 0; i < 3; i++ {
			signup(t, email, "Vendor2026x", nil)
		}
		r := signup(t, email, "Vendor2026x", nil)
		if r.Status != 429 || r.str("code") != "RATE_LIMITED" || r.Obj["details"].(map[string]any)["retryAfterSeconds"] == nil {
			t.Errorf("4th sign-up in an hour: %d %s", r.Status, r.Raw)
		}
		email = newEmail("kodebanjir")
		for i := 0; i < 5; i++ {
			newClient().do(t, "POST", "/auth/otp/request", map[string]any{"email": email})
		}
		if x := newClient().do(t, "POST", "/auth/otp/request", map[string]any{"email": email}); x.Status != 429 {
			t.Errorf("6th code in 15 minutes: %d", x.Status)
		}
		// Per address: narrowed for this test only.
		narrow := testLimits
		narrow.LoginPerIP = auth.Limit{Max: 1, Window: time.Minute}
		svc.Limits = &narrow
		defer func() { svc.Limits = &testLimits }()
		_, _ = pool.Exec(context.Background(), `DELETE FROM auth.rate_event WHERE key LIKE 'login:ip:%'`)
		newClient().loginIn(t, "admin", adminPw, "")
		if x := newClient().loginIn(t, "admin", adminPw, ""); x.Status != 429 {
			t.Errorf("sign-ins beyond the address limit: %d", x.Status)
		}
	})

	t.Run("SN08 a captcha, when set up, guards the public forms", func(t *testing.T) {
		svc.Captcha = fakeCaptcha{}
		defer func() { svc.Captcha = nil }()
		if o := must(t, newClient().do(t, "GET", "/auth/login-options?tenant=gan", nil), 200); o.Obj["captcha"] == nil {
			t.Errorf("options do not name the captcha")
		}
		if r := signup(t, newEmail("robot"), "Vendor2026x", nil); r.Status != 422 || r.problem("captcha") == "" {
			t.Errorf("no captcha: %d %s", r.Status, r.Raw)
		}
		if r := signup(t, newEmail("robot"), "Vendor2026x", map[string]any{"captcha": "salah"}); r.Status != 422 {
			t.Errorf("wrong captcha: %d", r.Status)
		}
		if r := signup(t, newEmail("manusia"), "Vendor2026x", map[string]any{"captcha": "lulus"}); r.Status != 202 {
			t.Errorf("good captcha: %d %s", r.Status, r.Raw)
		}
		if x := newClient().do(t, "POST", "/auth/otp/request", map[string]any{"email": "a@b.test"}); x.Status != 422 {
			t.Errorf("code request without captcha: %d", x.Status)
		}
	})

	t.Run("SN09 the policy: no Admin role for sign-ups, a role when open, email codes switched off", func(t *testing.T) {
		p := must(t, a.do(t, "GET", "/auth/policy", nil), 200).Obj
		q := map[string]any{}
		for k, v := range p {
			q[k] = v
		}
		q["selfSignupRole"] = "admin"
		if x := a.do(t, "PUT", "/auth/policy", q); x.Status != 422 {
			t.Errorf("admin as sign-up role: %d", x.Status)
		}
		q["selfSignupRole"] = nil
		if x := a.do(t, "PUT", "/auth/policy", q); x.Status != 422 {
			t.Errorf("open without a role: %d", x.Status)
		}
		q["selfSignupRole"], q["allowEmailOtp"] = "viewer", false
		must(t, a.do(t, "PUT", "/auth/policy", q), 200)
		defer func() { q["allowEmailOtp"] = true; a.do(t, "PUT", "/auth/policy", q) }()
		email := newEmail("tanpaotp")
		signup(t, email, "Vendor2026x", nil)
		must(t, newClient().do(t, "POST", "/auth/otp/request", map[string]any{"email": email}), 202)
		if x := newClient().do(t, "POST", "/auth/otp/verify", map[string]any{"email": email, "code": otpCode(t, email)}); x.Status != 403 || x.str("code") != "OTP_DISABLED" {
			t.Errorf("codes off: %d %s", x.Status, x.Raw)
		}
	})

	t.Run("SN10 a deactivated application's service token stops at once", func(t *testing.T) {
		svcApp := register(t, a, map[string]any{"name": "Layanan Sementara", "serviceRole": "viewer"})
		_, tk := newClient().call(t, "POST", "/oauth2/token", url.Values{"grant_type": {"client_credentials"}}, &svcApp)
		c := newClient()
		c.token = tk.str("access_token")
		var cl map[string]any
		for _, x := range must(t, a.do(t, "GET", "/auth/clients", nil), 200).List {
			if x["id"] == svcApp.id {
				cl = x
			}
		}
		cl["active"] = false
		must(t, a.do(t, "PUT", "/auth/clients/"+svcApp.id, cl), 200)
		if x := c.do(t, "GET", "/roles", nil); x.Status != 401 {
			t.Errorf("token of a deactivated application: %d", x.Status)
		}
	})
}

type fakeCaptcha struct{}

func (fakeCaptcha) Verify(_ context.Context, token, _ string) (bool, error) {
	return token == "lulus", nil
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func TestSignupStress(t *testing.T) {
	a := admin(t)
	openSignup(t, a)

	t.Run("SS01 30 different people sign up at once; 10 sign-ups of one email make one person", func(t *testing.T) {
		var fails atomic.Int64
		parallel(30, 10, func(i int) {
			if r := signup(t, fmt.Sprintf("serbu.%d.%d@vendor.test", time.Now().UnixNano(), i), "Vendor2026x", nil); r.Status != 202 {
				fails.Add(1)
			}
		})
		one := newEmail("kembar")
		parallel(10, 10, func(int) {
			if r := signup(t, one, "Vendor2026x", nil); r.Status != 202 && r.Status != 429 {
				fails.Add(1)
			}
		})
		if fails.Load() != 0 || identities(t, one) != 1 {
			t.Errorf("failures %d, identities of one email %d", fails.Load(), identities(t, one))
		}
	})
}
