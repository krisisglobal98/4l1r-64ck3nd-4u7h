//go:build e2e

// Multi-factor authentication (authenticator app + recovery codes) and the Identity Provider master.
package e2e

import (
	"context"
	"encoding/base32"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"alir.local/auth-service/internal/totp"
)

// authenticator is the person's app: the secret it was given.
type authenticator struct{ secret []byte }

// code is the app's current code; the clock moves one step first, so codes never repeat a used step.
func (a authenticator) code() string {
	advance(totp.Period * time.Second)
	return totp.Code(a.secret, totp.Step(now()), totp.Digits)
}

// enroll installs an authenticator for the signed-in client and answers it with the recovery codes.
func enroll(t *testing.T, c *client) (authenticator, []string) {
	t.Helper()
	st := must(t, c.do(t, "POST", "/auth/mfa/totp/start", nil), 200)
	sec, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(st.str("secret"))
	if err != nil || !strings.HasPrefix(st.str("otpauthUrl"), "otpauth://totp/ALIR") {
		t.Fatalf("start %s", st.Raw)
	}
	app := authenticator{sec}
	r := must(t, c.do(t, "POST", "/auth/mfa/totp/confirm", map[string]any{"code": app.code()}), 200)
	var codes []string
	for _, x := range r.Obj["recoveryCodes"].([]any) {
		codes = append(codes, x.(string))
	}
	return app, codes
}

// loginMFA signs in with the password and the authenticator.
func loginMFA(t *testing.T, c *client, user, pw, tenant string, app authenticator) resp {
	t.Helper()
	r := c.loginIn(t, user, pw, tenant)
	if r.Status != 401 || r.str("code") != "MFA_REQUIRED" {
		t.Fatalf("expected MFA_REQUIRED: %d %s", r.Status, r.Raw)
	}
	tok := r.Obj["details"].(map[string]any)["mfaToken"].(string)
	v := c.do(t, "POST", "/auth/mfa/verify", map[string]any{"mfaToken": tok, "code": app.code()})
	if v.Status == 200 {
		c.token = v.str("token")
	}
	return v
}

func mfaToken(t *testing.T, r resp) string {
	t.Helper()
	if r.str("code") != "MFA_REQUIRED" {
		t.Fatalf("expected MFA_REQUIRED: %d %s", r.Status, r.Raw)
	}
	return r.Obj["details"].(map[string]any)["mfaToken"].(string)
}

var tenantN atomic.Int64

// ownTenant makes a company of its own for a test (platform administrator) and signs its Admin in.
func ownTenant(t *testing.T) (*client, string) {
	t.Helper()
	code := fmt.Sprintf("mfa%d", tenantN.Add(1))
	email := "admin@" + code + ".test"
	must(t, admin(t).do(t, "POST", "/platform/tenants", map[string]any{"code": code, "name": "PT " + strings.ToUpper(code),
		"admin": map[string]any{"username": "admin." + code, "name": "Admin " + code, "email": email, "password": "MfaAwal2026"}}), 201)
	c := newClient()
	must(t, c.loginIn(t, email, "MfaAwal2026", code), 200)
	must(t, c.do(t, "POST", "/auth/password/change", map[string]any{"next": "MfaTetap2026"}), 204)
	must(t, c.loginIn(t, email, "MfaTetap2026", code), 200)
	return c, code
}

func memberOf(t *testing.T, a *client, username, email string) {
	t.Helper()
	must(t, a.do(t, "POST", "/users", map[string]any{"username": username, "name": "Anggota " + username, "email": email, "role": "viewer",
		"levelCode": "COMPANY", "companyCode": "C11", "password": "Awal2026x"}), 201)
	c := newClient()
	must(t, c.loginIn(t, email, "Awal2026x", ""), 200)
	must(t, c.do(t, "POST", "/auth/password/change", map[string]any{"next": "Tetap2026x"}), 204)
}

func TestMFAPositive(t *testing.T) {
	a := admin(t)
	memberOf(t, a, "mfa.satu", "mfa.satu@contoh.co.id")
	var app authenticator
	var codes []string

	t.Run("MP01 enrol: a secret for the app, a code proves it, recovery codes once", func(t *testing.T) {
		c := newClient()
		must(t, c.login(t, "mfa.satu", "Tetap2026x"), 200)
		if s := must(t, c.do(t, "GET", "/auth/mfa", nil), 200); s.Obj["enrolled"] != false {
			t.Errorf("status before %s", s.Raw)
		}
		st := must(t, c.do(t, "POST", "/auth/mfa/totp/start", nil), 200)
		if x := c.do(t, "POST", "/auth/mfa/totp/confirm", map[string]any{"code": "000000"}); x.Status != 422 {
			t.Errorf("wrong code: %d", x.Status)
		}
		sec, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(st.str("secret"))
		app = authenticator{sec}
		r := must(t, c.do(t, "POST", "/auth/mfa/totp/confirm", map[string]any{"code": app.code()}), 200)
		for _, x := range r.Obj["recoveryCodes"].([]any) {
			codes = append(codes, x.(string))
		}
		if len(codes) != 10 || len(codes[0]) != 11 {
			t.Errorf("recovery codes %v", codes)
		}
		if s := must(t, c.do(t, "GET", "/auth/mfa", nil), 200); s.Obj["enrolled"] != true || s.Obj["recoveryCodesLeft"].(float64) != 10 {
			t.Errorf("status after %s", s.Raw)
		}
		var sealed string
		_ = pool.QueryRow(context.Background(), `SELECT f.secret_sealed FROM auth.mfa_factor f JOIN auth.identity i ON i.id = f.identity_id WHERE i.email = 'mfa.satu@contoh.co.id'`).Scan(&sealed)
		if !strings.HasPrefix(sealed, "v1:") || strings.Contains(sealed, st.str("secret")) {
			t.Errorf("the secret is not sealed: %s", sealed)
		}
	})

	t.Run("MP02 sign-in asks for the authenticator; the step token works once", func(t *testing.T) {
		c := newClient()
		r := c.login(t, "mfa.satu", "Tetap2026x")
		tok := mfaToken(t, r)
		if r.str("token") != "" {
			t.Errorf("no session before the second factor")
		}
		v := must(t, c.do(t, "POST", "/auth/mfa/verify", map[string]any{"mfaToken": tok, "code": app.code()}), 200)
		c.token = v.str("token")
		must(t, c.do(t, "GET", "/auth/me", nil), 200)
		if x := newClient().do(t, "POST", "/auth/mfa/verify", map[string]any{"mfaToken": tok, "code": app.code()}); x.Status != 401 || x.str("code") != "MFA_EXPIRED" {
			t.Errorf("step token twice: %d %s", x.Status, x.Raw)
		}
	})

	t.Run("MP03 a recovery code signs in once", func(t *testing.T) {
		c := newClient()
		tok := mfaToken(t, c.login(t, "mfa.satu", "Tetap2026x"))
		v := must(t, c.do(t, "POST", "/auth/mfa/verify", map[string]any{"mfaToken": tok, "recoveryCode": strings.ToUpper(codes[0])}), 200)
		c.token = v.str("token")
		tok = mfaToken(t, newClient().login(t, "mfa.satu", "Tetap2026x"))
		if x := newClient().do(t, "POST", "/auth/mfa/verify", map[string]any{"mfaToken": tok, "recoveryCode": codes[0]}); x.Status != 401 {
			t.Errorf("recovery code twice: %d", x.Status)
		}
		if s := must(t, c.do(t, "GET", "/auth/mfa", nil), 200); s.Obj["recoveryCodesLeft"].(float64) != 9 {
			t.Errorf("codes left %s", s.Raw)
		}
		r := must(t, c.do(t, "POST", "/auth/mfa/recovery-codes", map[string]any{"code": app.code()}), 200)
		if len(r.Obj["recoveryCodes"].([]any)) != 10 {
			t.Errorf("regenerated %s", r.Raw)
		}
		codes = nil
		for _, x := range r.Obj["recoveryCodes"].([]any) {
			codes = append(codes, x.(string))
		}
	})

	t.Run("MP04 an email code is a first factor too: the authenticator is still asked", func(t *testing.T) {
		must(t, newClient().do(t, "POST", "/auth/otp/request", map[string]any{"email": "mfa.satu@contoh.co.id"}), 202)
		r := newClient().do(t, "POST", "/auth/otp/verify", map[string]any{"email": "mfa.satu@contoh.co.id", "code": otpCode(t, "mfa.satu@contoh.co.id")})
		tok := mfaToken(t, r)
		if v := newClient().do(t, "POST", "/auth/mfa/verify", map[string]any{"mfaToken": tok, "code": app.code()}); v.Status != 200 {
			t.Errorf("after the email code: %d %s", v.Status, v.Raw)
		}
	})

	t.Run("MP05 a company that requires MFA: the session grants nothing until enrolled, everywhere", func(t *testing.T) {
		g, code := ownTenant(t)
		if x := g.do(t, "PUT", "/auth/policy", policyWith(t, g, "mfaMode", "required")); x.Status != 422 || x.problem("mfaMode") == "" {
			t.Errorf("requiring MFA without one's own: %d %s", x.Status, x.Raw)
		}
		gapp, _ := enroll(t, g)
		must(t, g.do(t, "PUT", "/auth/policy", policyWith(t, g, "mfaMode", "required")), 200)
		email := "wajib@" + code + ".test"
		memberOfIn(t, g, "wajib", email)
		c := newClient()
		r := must(t, c.loginIn(t, email, "Tetap2026x", code), 200)
		if r.Obj["mustEnrollMfa"] != true || tokenClaims(t, c.token)["grants"] != nil {
			t.Errorf("must enrol, no grants: %s", trunc(r.Raw))
		}
		if x := c.do(t, "GET", "/roles", nil); x.Status != 403 || x.str("code") != "MFA_ENROLL_REQUIRED" {
			t.Errorf("before enrolling: %d %s", x.Status, x.Raw)
		}
		app2, _ := enroll(t, c)
		if x := must(t, c.send(t, "POST", "/auth/refresh", nil), 200); x.Obj["mustEnrollMfa"] != false {
			t.Errorf("after enrolling: %s", trunc(x.Raw))
		}
		if x := c.do(t, "POST", "/auth/mfa/disable", map[string]any{"code": app2.code()}); x.Status != 409 || x.str("code") != "MFA_REQUIRED_BY_TENANT" {
			t.Errorf("disable while required: %d %s", x.Status, x.Raw)
		}
		if v := loginMFA(t, newClient(), email, "Tetap2026x", code, app2); v.Status != 200 {
			t.Errorf("sign-in with MFA: %d", v.Status)
		}
		_ = gapp
	})

	t.Run("MP06 disable with a code; the next sign-in is the password only", func(t *testing.T) {
		c := newClient()
		loginMFA(t, c, "mfa.satu", "Tetap2026x", "", app)
		if x := c.do(t, "POST", "/auth/mfa/disable", map[string]any{"code": "123456"}); x.Status != 422 {
			t.Errorf("disable with a wrong code: %d", x.Status)
		}
		must(t, c.do(t, "POST", "/auth/mfa/disable", map[string]any{"recoveryCode": codes[1]}), 204)
		if r := newClient().login(t, "mfa.satu", "Tetap2026x"); r.Status != 200 {
			t.Errorf("after disabling: %d %s", r.Status, r.Raw)
		}
	})

	t.Run("MP07 an administrator resets a lost authenticator", func(t *testing.T) {
		memberOf(t, a, "mfa.hilang", "mfa.hilang@contoh.co.id")
		c := newClient()
		must(t, c.login(t, "mfa.hilang", "Tetap2026x"), 200)
		enroll(t, c)
		id := userID(t, a, "mfa.hilang")
		r := must(t, a.do(t, "POST", "/users/"+id+"/mfa/reset", nil), 200)
		if r.Obj["mfaEnrolled"] != false {
			t.Errorf("reset %s", trunc(r.Raw))
		}
		if x := c.do(t, "GET", "/auth/me", nil); x.Status != 401 {
			t.Errorf("their sessions end: %d", x.Status)
		}
		if x := newClient().login(t, "mfa.hilang", "Tetap2026x"); x.Status != 200 {
			t.Errorf("password only after reset: %d", x.Status)
		}
	})
}

// policyWith is the client's company policy with one field changed.
func policyWith(t *testing.T, c *client, key string, v any) map[string]any {
	t.Helper()
	p := must(t, c.do(t, "GET", "/auth/policy", nil), 200).Obj
	p[key] = v
	return p
}

// memberOfIn adds a member to the client's company (no organisation scope: a company of its own has no tree).
func memberOfIn(t *testing.T, a *client, username, email string) {
	t.Helper()
	must(t, a.do(t, "POST", "/users", map[string]any{"username": username, "name": "Anggota " + username, "email": email, "role": "viewer",
		"levelCode": "COMPANY", "companyCode": "C11", "password": "Awal2026x"}), 201)
	c := newClient()
	r := c.loginIn(t, email, "Awal2026x", "")
	if r.Status != 200 {
		t.Fatalf("first sign-in %d %s", r.Status, r.Raw)
	}
	must(t, c.do(t, "POST", "/auth/password/change", map[string]any{"next": "Tetap2026x"}), 204)
}

func TestMFANegative(t *testing.T) {
	a := admin(t)
	memberOf(t, a, "mfa.dua", "mfa.dua@contoh.co.id")
	c := newClient()
	must(t, c.login(t, "mfa.dua", "Tetap2026x"), 200)
	app, _ := enroll(t, c)

	t.Run("MN01 a used code never works again; old codes fail", func(t *testing.T) {
		code := app.code()
		tok := mfaToken(t, newClient().login(t, "mfa.dua", "Tetap2026x"))
		must(t, newClient().do(t, "POST", "/auth/mfa/verify", map[string]any{"mfaToken": tok, "code": code}), 200)
		tok = mfaToken(t, newClient().login(t, "mfa.dua", "Tetap2026x"))
		if x := newClient().do(t, "POST", "/auth/mfa/verify", map[string]any{"mfaToken": tok, "code": code}); x.Status != 401 {
			t.Errorf("replayed code: %d", x.Status)
		}
		old := totp.Code(app.secret, totp.Step(now())-3, totp.Digits)
		if x := newClient().do(t, "POST", "/auth/mfa/verify", map[string]any{"mfaToken": tok, "code": old}); x.Status != 401 {
			t.Errorf("old code: %d", x.Status)
		}
		if v := newClient().do(t, "POST", "/auth/mfa/verify", map[string]any{"mfaToken": tok, "code": app.code()}); v.Status != 200 {
			t.Errorf("the right code after wrong ones: %d %s", v.Status, v.Raw)
		}
	})

	t.Run("MN02 wrong codes count toward the lockout of the person", func(t *testing.T) {
		var last resp
		for i := 0; i < 5; i++ {
			tok := mfaToken(t, newClient().login(t, "mfa.dua", "Tetap2026x"))
			last = newClient().do(t, "POST", "/auth/mfa/verify", map[string]any{"mfaToken": tok, "code": "000000"})
		}
		if last.Status != 423 {
			t.Errorf("after 5 wrong codes: %d %s", last.Status, last.Raw)
		}
		_, _ = pool.Exec(context.Background(), `UPDATE auth.identity SET locked_until = NULL, failed_logins = 0 WHERE email = 'mfa.dua@contoh.co.id'`)
	})

	t.Run("MN03 enrolment states: already enrolled, nothing started, MFA off in the company", func(t *testing.T) {
		c := newClient()
		loginMFA(t, c, "mfa.dua", "Tetap2026x", "", app)
		if x := c.do(t, "POST", "/auth/mfa/totp/start", nil); x.Status != 409 {
			t.Errorf("start when enrolled: %d", x.Status)
		}
		g, _ := ownTenant(t)
		if x := g.do(t, "POST", "/auth/mfa/totp/confirm", map[string]any{"code": "123456"}); x.Status != 409 {
			t.Errorf("confirm without start: %d", x.Status)
		}
		must(t, g.do(t, "PUT", "/auth/policy", policyWith(t, g, "mfaMode", "off")), 200)
		if x := g.do(t, "POST", "/auth/mfa/totp/start", nil); x.Status != 409 || x.str("code") != "MFA_OFF" {
			t.Errorf("start when off: %d %s", x.Status, x.Raw)
		}
		if x := g.do(t, "PUT", "/auth/policy", policyWith(t, g, "mfaMode", "always")); x.Status != 422 {
			t.Errorf("unknown mode: %d", x.Status)
		}
	})

	t.Run("MN04 resetting another company's member, or a shared person, is refused", func(t *testing.T) {
		g, _ := ownTenant(t)
		id := userID(t, a, "mfa.dua")
		if x := g.do(t, "POST", "/users/"+id+"/mfa/reset", nil); x.Status != 404 {
			t.Errorf("other company: %d", x.Status)
		}
		if x := newClient().do(t, "POST", "/users/"+id+"/mfa/reset", nil); x.Status != 401 {
			t.Errorf("anonymous: %d", x.Status)
		}
	})

	t.Run("MN05 a person who must enrol gets no OIDC code", func(t *testing.T) {
		g, code := ownTenant(t)
		enroll(t, g)
		must(t, g.do(t, "PUT", "/auth/policy", policyWith(t, g, "mfaMode", "required")), 200)
		email := "oidc@" + code + ".test"
		memberOfIn(t, g, "oidc", email)
		appX := register(t, g, map[string]any{"name": "Aplikasi MFA"})
		b := newClient()
		loc, _ := b.authorize(t, appX, "openid", nil)
		must(t, b.loginIn(t, email, "Tetap2026x", code), 200)
		if x := b.do(t, "POST", "/oauth2/authorize/complete", map[string]any{"loginChallenge": loc.Query().Get("login_challenge")}); x.Status != 403 || x.str("code") != "MFA_ENROLL_REQUIRED" {
			t.Errorf("complete before enrolling: %d %s", x.Status, x.Raw)
		}
		if loc2, _ := b.authorize(t, appX, "openid", nil); loc2.Query().Get("code") != "" {
			t.Errorf("SSO gave a code to a person who must enrol")
		}
	})
}

func TestMFAStress(t *testing.T) {
	a := admin(t)
	memberOf(t, a, "mfa.tiga", "mfa.tiga@contoh.co.id")
	c := newClient()
	must(t, c.login(t, "mfa.tiga", "Tetap2026x"), 200)
	app, _ := enroll(t, c)

	t.Run("MS01 one code sent by 10 sign-ins at once: exactly one gets in", func(t *testing.T) {
		code := app.code()
		toks := make([]string, 10)
		for i := range toks {
			toks[i] = mfaToken(t, newClient().login(t, "mfa.tiga", "Tetap2026x"))
		}
		var ok atomic.Int64
		var wg sync.WaitGroup
		for _, tok := range toks {
			wg.Add(1)
			go func(tok string) {
				defer wg.Done()
				if r := newClient().do(t, "POST", "/auth/mfa/verify", map[string]any{"mfaToken": tok, "code": code}); r.Status == 200 {
					ok.Add(1)
				}
			}(tok)
		}
		wg.Wait()
		if ok.Load() != 1 {
			t.Errorf("%d sign-ins used one code", ok.Load())
		}
	})
}

/* ---------------- Identity providers ---------------- */

func idpBody(extra map[string]any) map[string]any {
	b := map[string]any{"name": "Masuk dengan Microsoft", "kind": "azure_ad", "issuer": "https://login.microsoftonline.com/abc/v2.0", "clientId": "app-123",
		"clientSecret": "rahasia-azure-9876", "emailDomains": []string{"grupagro.co.id"}, "active": true}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func TestIdentityProviders(t *testing.T) {
	a := admin(t)
	var code string

	t.Run("IP01 a provider is added; the secret is sealed and never answered", func(t *testing.T) {
		r := must(t, a.do(t, "POST", "/auth/identity-providers", idpBody(nil)), 201)
		code = r.str("code")
		if !strings.HasPrefix(code, "IDP") || r.Obj["secretSet"] != true || r.str("secretHint") != "9876" || r.str("subjectClaim") != "oid" || strings.Contains(string(r.Raw), "rahasia-azure") {
			t.Errorf("created %s", r.Raw)
		}
		var sealed string
		_ = pool.QueryRow(context.Background(), `SELECT client_secret_sealed FROM auth.identity_provider WHERE code = $1`, code).Scan(&sealed)
		if !strings.HasPrefix(sealed, "v1:") || strings.Contains(sealed, "rahasia") {
			t.Errorf("not sealed: %s", sealed)
		}
	})

	t.Run("IP02 a change without a secret keeps it; a new one replaces it", func(t *testing.T) {
		b := idpBody(nil)
		delete(b, "clientSecret")
		b["name"] = "Microsoft Entra ID"
		if r := must(t, a.do(t, "PUT", "/auth/identity-providers/"+code, b), 200); r.str("secretHint") != "9876" || r.str("name") != "Microsoft Entra ID" {
			t.Errorf("kept %s", r.Raw)
		}
		if r := must(t, a.do(t, "PUT", "/auth/identity-providers/"+code, idpBody(map[string]any{"clientSecret": "baru-sekali-1111"})), 200); r.str("secretHint") != "1111" {
			t.Errorf("replaced %s", r.Raw)
		}
	})

	t.Run("IN01 the form is checked", func(t *testing.T) {
		for name, x := range map[string]map[string]any{
			"http issuer": {"issuer": "http://login.test"}, "bad domain": {"emailDomains": []string{"bukan domain"}}, "unknown kind": {"kind": "ldap"},
			"jit without role": {"jitProvisioning": true}, "admin role": {"defaultRole": "admin"}, "no openid": {"scopes": []string{"email"}},
			"no secret": {"clientSecret": ""}, "bad claim": {"emailClaim": "e mail"}, "domain taken": {"emailDomains": []string{"grupagro.co.id"}},
		} {
			if r := a.do(t, "POST", "/auth/identity-providers", idpBody(x)); r.Status != 422 {
				t.Errorf("%s: %d %s", name, r.Status, trunc(r.Raw))
			}
		}
	})

	t.Run("IN02 another company neither sees nor changes it, nor takes its domain", func(t *testing.T) {
		g, _ := ownTenant(t)
		if l := must(t, g.do(t, "GET", "/auth/identity-providers", nil), 200); len(l.List) != 0 {
			t.Errorf("another company lists %d", len(l.List))
		}
		if x := g.do(t, "PUT", "/auth/identity-providers/"+code, idpBody(nil)); x.Status != 404 {
			t.Errorf("another company changes it: %d", x.Status)
		}
		if x := g.do(t, "POST", "/auth/identity-providers", idpBody(map[string]any{"emailDomains": []string{"grupagro.co.id"}})); x.Status != 422 {
			t.Errorf("another company takes the domain: %d", x.Status)
		}
		viewer, _ := newUser(t, a, "viewer")
		v := newClient()
		must(t, v.login(t, viewer, "Tetap2026x"), 200)
		if x := v.do(t, "GET", "/auth/identity-providers", nil); x.Status != 403 {
			t.Errorf("a viewer: %d", x.Status)
		}
	})

	t.Run("IN03 a deleted provider is gone, its secret wiped, its domain free", func(t *testing.T) {
		must(t, a.do(t, "DELETE", "/auth/identity-providers/"+code, nil), 204)
		for _, x := range must(t, a.do(t, "GET", "/auth/identity-providers", nil), 200).List {
			if x["code"] == code {
				t.Errorf("still listed")
			}
		}
		var sealed *string
		_ = pool.QueryRow(context.Background(), `SELECT client_secret_sealed FROM auth.identity_provider WHERE code = $1`, code).Scan(&sealed)
		if sealed != nil {
			t.Errorf("the secret of a deleted provider stays")
		}
		must(t, a.do(t, "POST", "/auth/identity-providers", idpBody(nil)), 201)
	})
}
