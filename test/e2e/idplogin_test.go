//go:build e2e

// Sign-in through a company's identity provider (Entra ID / Google / OIDC), against a fake provider over HTTPS that
// checks PKCE and the client secret and signs RS256 ID tokens (or forged ones, on request).
package e2e

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"alir.local/auth-service/internal/oidcrp"
)

type pendingCode struct {
	claims              map[string]any
	challenge, redirect string
}

// fakeIdP is the company's identity provider.
type fakeIdP struct {
	srv        *httptest.Server
	key, other *rsa.PrivateKey
	mu         sync.Mutex
	codes      map[string]pendingCode
	secret     string
	forge      string // "", other-key, none, aud, nonce, expired
	tokenCalls atomic.Int64
}

func newFakeIdP(t *testing.T) *fakeIdP {
	f := &fakeIdP{codes: map[string]pendingCode{}, secret: "rahasia-idp-4321"}
	f.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	f.other, _ = rsa.GenerateKey(rand.Reader, 2048)
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/keys"})
	case "/keys":
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes())}}})
	case "/token":
		f.tokenCalls.Add(1)
		_ = r.ParseForm()
		f.mu.Lock()
		p, ok := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		switch {
		case !ok, r.PostForm.Get("client_secret") != f.secret, r.PostForm.Get("client_id") != "alir-test",
			base64.RawURLEncoding.EncodeToString(sum[:]) != p.challenge, r.PostForm.Get("redirect_uri") != p.redirect:
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "x", "token_type": "Bearer", "id_token": f.sign(p.claims)})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeIdP) sign(claims map[string]any) string {
	// The provider's clock is the service's (the suite moves it forward for the authenticator codes).
	c := map[string]any{"iss": f.srv.URL, "aud": "alir-test", "iat": now().Unix(), "exp": now().Add(5 * time.Minute).Unix()}
	for k, v := range claims {
		c[k] = v
	}
	alg, key := "RS256", f.key
	switch f.forge {
	case "other-key":
		key = f.other
	case "none":
		alg = "none"
	case "aud":
		c["aud"] = "aplikasi-lain"
	case "nonce":
		c["nonce"] = "nonce-lain"
	case "expired":
		c["exp"] = now().Add(-10 * time.Minute).Unix()
	}
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": "k1", "typ": "JWT"})
	b, _ := json.Marshal(c)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
	if alg == "none" {
		return in + "."
	}
	d := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// signIn is the person signing in at the provider: start at ALIR, the provider answers with a code for claims, the
// browser comes back to ALIR's callback. It answers where ALIR sends the browser at the end.
func (f *fakeIdP) signIn(t *testing.T, c *client, startQuery url.Values, claims map[string]any) *url.URL {
	t.Helper()
	res, _ := c.call(t, "GET", "/auth/idp/start?"+startQuery.Encode(), nil, nil)
	to, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != 302 || !strings.HasPrefix(to.String(), f.srv.URL+"/authorize") {
		t.Fatalf("start did not go to the provider: %d %s", res.StatusCode, to)
	}
	q := to.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("state") == "" || q.Get("nonce") == "" || q.Get("client_id") != "alir-test" {
		t.Fatalf("authorization request %s", to)
	}
	cl := map[string]any{"nonce": q.Get("nonce")}
	for k, v := range claims {
		cl[k] = v
	}
	code := randomCode()
	f.mu.Lock()
	f.codes[code] = pendingCode{cl, q.Get("code_challenge"), q.Get("redirect_uri")}
	f.mu.Unlock()
	back := strings.TrimPrefix(q.Get("redirect_uri"), server.URL)
	res, _ = c.call(t, "GET", back+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), nil, nil)
	end, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != 302 {
		t.Fatalf("callback %d", res.StatusCode)
	}
	return end
}

func randomCode() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// sessionAfter is the session the sign-in left in the browser (its refresh cookie), "" when none.
func sessionAfter(t *testing.T, c *client) resp {
	t.Helper()
	r := c.send(t, "POST", "/auth/refresh", nil)
	if r.Status == 200 {
		c.token = r.str("token")
	}
	return r
}

func TestIdpLogin(t *testing.T) {
	a := admin(t)
	idp := newFakeIdP(t)
	svc.RP = &oidcrp.Client{HTTP: idp.srv.Client()}
	defer func() { svc.RP = &oidcrp.Client{HTTP: http.DefaultClient} }()
	reg := func(body map[string]any) string {
		b := map[string]any{"name": "Masuk dengan SSO Kantor", "kind": "oidc", "issuer": idp.srv.URL, "clientId": "alir-test", "clientSecret": idp.secret,
			"emailDomains": []string{"idp.test"}, "active": true}
		for k, v := range body {
			b[k] = v
		}
		return must(t, a.do(t, "POST", "/auth/identity-providers", b), 201).str("code")
	}
	code := reg(nil)
	start := func(extra url.Values) url.Values {
		q := url.Values{"tenant": {"gan"}, "idp": {code}}
		for k, v := range extra {
			q[k] = v
		}
		return q
	}
	ssoErr := func(u *url.URL) string { return u.Query().Get("sso_error") }
	memberOf(t, a, "rudi", "rudi@idp.test")

	t.Run("IL01 the sign-in page offers the provider; an email of its domain finds it", func(t *testing.T) {
		o := must(t, newClient().do(t, "GET", "/auth/login-options?tenant=gan", nil), 200)
		list, _ := o.Obj["identityProviders"].([]any)
		if len(list) != 1 || list[0].(map[string]any)["code"] != code {
			t.Errorf("options %s", trunc(o.Raw))
		}
		if d := must(t, newClient().do(t, "POST", "/auth/idp/discover", map[string]any{"email": "Siapa@IDP.test"}), 200); d.Obj["provider"] == nil {
			t.Errorf("discover %s", d.Raw)
		}
		if d := must(t, newClient().do(t, "POST", "/auth/idp/discover", map[string]any{"email": "a@lain.test"}), 200); d.Obj["provider"] != nil {
			t.Errorf("another domain: %s", d.Raw)
		}
		if l := must(t, a.do(t, "GET", "/auth/identity-providers", nil), 200); l.List[0]["redirectUri"] != server.URL+"/auth/idp/callback" {
			t.Errorf("redirect uri to register: %v", l.List[0]["redirectUri"])
		}
		if su := must(t, a.do(t, "GET", "/auth/identity-providers-setup", nil), 200); su.str("redirectUri") != server.URL+"/auth/idp/callback" {
			t.Errorf("setup before any provider: %s", su.Raw)
		}
		if x := newClient().do(t, "GET", "/auth/identity-providers-setup", nil); x.Status != 401 {
			t.Errorf("setup anonymous: %d", x.Status)
		}
	})

	t.Run("IL02 a member signs in by the email the provider vouches for; later by the linked account", func(t *testing.T) {
		c := newClient()
		end := idp.signIn(t, c, start(nil), map[string]any{"sub": "azure-rudi", "email": "rudi@idp.test", "name": "Rudi Hartono"})
		if !strings.HasSuffix(end.Path, "/auth/sso-done") || ssoErr(end) != "" {
			t.Fatalf("end %s", end)
		}
		r := sessionAfter(t, c)
		if r.Status != 200 || r.Obj["user"].(map[string]any)["username"] != "rudi" {
			t.Fatalf("session %d %s", r.Status, trunc(r.Raw))
		}
		if s := must(t, c.do(t, "GET", "/auth/me/sessions", nil), 200).List; s[0]["method"] != "idp" {
			t.Errorf("method %v", s[0]["method"])
		}
		c2 := newClient()
		idp.signIn(t, c2, start(nil), map[string]any{"sub": "azure-rudi", "email": "rudi.baru@idp.test"})
		if r := sessionAfter(t, c2); r.Status != 200 || r.Obj["user"].(map[string]any)["username"] != "rudi" {
			t.Errorf("by the link after an email change: %d %s", r.Status, trunc(r.Raw))
		}
	})

	t.Run("IL03 not registered and no just-in-time: refused, no session", func(t *testing.T) {
		c := newClient()
		end := idp.signIn(t, c, start(nil), map[string]any{"sub": "azure-asing", "email": "asing@idp.test"})
		if ssoErr(end) != "NOT_REGISTERED" || end.Query().Get("tenant") != "gan" {
			t.Errorf("end %s", end)
		}
		if r := sessionAfter(t, c); r.Status == 200 {
			t.Errorf("a session was left")
		}
	})

	t.Run("IL04 just-in-time: the first sign-in makes a workforce member with the initial role, no password", func(t *testing.T) {
		jit := reg(map[string]any{"name": "SSO JIT", "emailDomains": []string{"jit.test"}, "jitProvisioning": true, "defaultRole": "viewer"})
		c := newClient()
		end := idp.signIn(t, c, url.Values{"tenant": {"gan"}, "idp": {jit}}, map[string]any{"sub": "g-baru", "email": "pendatang@jit.test", "name": "Pendatang Baru"})
		r := sessionAfter(t, c)
		if ssoErr(end) != "" || r.Status != 200 || r.Obj["user"].(map[string]any)["role"] != "viewer" {
			t.Fatalf("jit %s %d %s", end, r.Status, trunc(r.Raw))
		}
		var origin string
		var hasPw bool
		_ = pool.QueryRow(context.Background(), `SELECT origin, password_hash IS NOT NULL FROM auth.identity WHERE email = 'pendatang@jit.test'`).Scan(&origin, &hasPw)
		if origin != "idp" || hasPw {
			t.Errorf("identity origin %s password %v", origin, hasPw)
		}
		for _, u := range must(t, a.do(t, "GET", "/users", nil), 200).List {
			if u["email"] == "pendatang@jit.test" && (u["kind"] != "workforce" || u["name"] != "Pendatang Baru") {
				t.Errorf("member %v", u)
			}
		}
	})

	t.Run("IL05 a person with an authenticator still gives the code after the provider", func(t *testing.T) {
		c := newClient()
		must(t, c.login(t, "rudi", "Tetap2026x"), 200)
		app, _ := enroll(t, c)
		b := newClient()
		end := idp.signIn(t, b, start(nil), map[string]any{"sub": "azure-rudi", "email": "rudi@idp.test"})
		tok := end.Query().Get("mfa")
		if tok == "" || sessionAfter(t, b).Status == 200 {
			t.Fatalf("expected the MFA step: %s", end)
		}
		if v := b.do(t, "POST", "/auth/mfa/verify", map[string]any{"mfaToken": tok, "code": app.code()}); v.Status != 200 {
			t.Errorf("after MFA: %d %s", v.Status, v.Raw)
		}
		_, _ = pool.Exec(context.Background(), `DELETE FROM auth.mfa_factor WHERE identity_id = (SELECT identity_id FROM auth.membership WHERE username = 'rudi' AND tenant_id = '00000000-0000-7000-8000-0000000000a1')`)
	})

	t.Run("IL06 a waiting OIDC sign-in and a return path are carried; another site is never a return", func(t *testing.T) {
		end := idp.signIn(t, newClient(), start(url.Values{"login_challenge": {"ch-123"}}), map[string]any{"sub": "azure-rudi", "email": "rudi@idp.test"})
		if end.Query().Get("login_challenge") != "ch-123" {
			t.Errorf("challenge %s", end)
		}
		end = idp.signIn(t, newClient(), start(url.Values{"return": {"/auth/users"}}), map[string]any{"sub": "azure-rudi", "email": "rudi@idp.test"})
		if end.Query().Get("return") != "/auth/users" {
			t.Errorf("return %s", end)
		}
		for _, evil := range []string{"//evil.test/x", "https://evil.test", "/\\evil.test"} {
			end = idp.signIn(t, newClient(), start(url.Values{"return": {evil}}), map[string]any{"sub": "azure-rudi", "email": "rudi@idp.test"})
			if end.Query().Get("return") != "" || !strings.HasPrefix(end.String(), "http://alir.test/") {
				t.Errorf("return %q went to %s", evil, end)
			}
		}
	})

	t.Run("IN01 forged or wrong ID tokens are refused and leave no session", func(t *testing.T) {
		defer func() { idp.forge = "" }()
		for _, mode := range []string{"other-key", "none", "aud", "nonce", "expired"} {
			idp.forge = mode
			c := newClient()
			end := idp.signIn(t, c, start(nil), map[string]any{"sub": "azure-rudi", "email": "rudi@idp.test"})
			if ssoErr(end) != "IDP_TOKEN" || sessionAfter(t, c).Status == 200 {
				t.Errorf("%s: %s", mode, end)
			}
		}
	})

	t.Run("IN02 an email the provider does not vouch for links nobody", func(t *testing.T) {
		for name, claims := range map[string]map[string]any{
			"unverified":      {"sub": "x-1", "email": "rudi@idp.test", "email_verified": false},
			"other domain":    {"sub": "x-2", "email": "rudi@gmail.com"},
			"no email at all": {"sub": "x-3"},
		} {
			if end := idp.signIn(t, newClient(), start(nil), claims); ssoErr(end) != "NOT_REGISTERED" {
				t.Errorf("%s: %s", name, end)
			}
		}
	})

	t.Run("IN03 the state works once and expires; the provider's refusal is reported", func(t *testing.T) {
		c := newClient()
		res, _ := c.call(t, "GET", "/auth/idp/start?"+start(nil).Encode(), nil, nil)
		to, _ := url.Parse(res.Header.Get("Location"))
		state := to.Query().Get("state")
		res, _ = c.call(t, "GET", "/auth/idp/callback?"+url.Values{"error": {"access_denied"}, "state": {state}}.Encode(), nil, nil)
		if u, _ := url.Parse(res.Header.Get("Location")); ssoErr(u) != "IDP_REFUSED" {
			t.Errorf("refusal %s", u)
		}
		res, _ = c.call(t, "GET", "/auth/idp/callback?"+url.Values{"code": {"x"}, "state": {state}}.Encode(), nil, nil)
		if u, _ := url.Parse(res.Header.Get("Location")); ssoErr(u) != "IDP_STATE" {
			t.Errorf("state twice %s", u)
		}
		res, _ = c.call(t, "GET", "/auth/idp/start?"+start(nil).Encode(), nil, nil)
		to, _ = url.Parse(res.Header.Get("Location"))
		_, _ = pool.Exec(context.Background(), `UPDATE auth.idp_login SET expires_at = now() - interval '1 second' WHERE used_at IS NULL`)
		res, _ = c.call(t, "GET", "/auth/idp/callback?"+url.Values{"code": {"x"}, "state": {to.Query().Get("state")}}.Encode(), nil, nil)
		if u, _ := url.Parse(res.Header.Get("Location")); ssoErr(u) != "IDP_STATE" {
			t.Errorf("expired state %s", u)
		}
	})

	t.Run("IN04 a wrong client secret, a deactivated provider", func(t *testing.T) {
		idp.secret = "rahasia-baru-0000" // the provider rotated it; ALIR still has the old one
		end := idp.signIn(t, newClient(), start(nil), map[string]any{"sub": "azure-rudi", "email": "rudi@idp.test"})
		idp.secret = "rahasia-idp-4321"
		if ssoErr(end) != "IDP_TOKEN" {
			t.Errorf("old secret: %s", end)
		}
		var x map[string]any
		for _, y := range must(t, a.do(t, "GET", "/auth/identity-providers", nil), 200).List {
			if y["code"] == code {
				x = y
			}
		}
		x["active"] = false
		must(t, a.do(t, "PUT", "/auth/identity-providers/"+code, x), 200)
		res, _ := newClient().call(t, "GET", "/auth/idp/start?"+start(nil).Encode(), nil, nil)
		if u, _ := url.Parse(res.Header.Get("Location")); ssoErr(u) != "IDP_UNAVAILABLE" {
			t.Errorf("deactivated: %s", u)
		}
		for _, y := range must(t, a.do(t, "GET", "/auth/identity-providers", nil), 200).List {
			if y["code"] == code {
				y["active"] = true
				must(t, a.do(t, "PUT", "/auth/identity-providers/"+code, y), 200)
			}
		}
	})

	t.Run("IS01 10 first sign-ins of one new person at once make one person and one member", func(t *testing.T) {
		jit := reg(map[string]any{"name": "SSO Serbu", "emailDomains": []string{"serbu.test"}, "jitProvisioning": true, "defaultRole": "viewer"})
		var wg sync.WaitGroup
		var ok atomic.Int64
		for range 10 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c := newClient()
				idp.signIn(t, c, url.Values{"tenant": {"gan"}, "idp": {jit}}, map[string]any{"sub": "serbu-1", "email": "serbu@serbu.test"})
				if sessionAfter(t, c).Status == 200 {
					ok.Add(1)
				}
			}()
		}
		wg.Wait()
		var people, members int
		_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM auth.identity WHERE email = 'serbu@serbu.test'`).Scan(&people)
		_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM auth.membership m JOIN auth.identity i ON i.id = m.identity_id WHERE i.email = 'serbu@serbu.test'`).Scan(&members)
		if ok.Load() != 10 || people != 1 || members != 1 {
			t.Errorf("signed in %d, people %d, members %d", ok.Load(), people, members)
		}
	})
}
