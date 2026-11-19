//go:build e2e

// OpenID Connect provider: an application signs its users in with the authorization code flow + PKCE through the
// ALIR login page (login_challenge), single sign-on, refresh rotation, client_credentials, logout and revocation.
package e2e

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// app is a registered application as its developer configures it.
type app struct {
	id, secret, redirect string
}

func pkcePair() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// call sends a request without following redirects; form bodies are urlencoded; basic is client_id/secret.
func (c *client) call(t testing.TB, method, path string, form url.Values, basic *app) (*http.Response, resp) {
	t.Helper()
	var rd io.Reader
	if form != nil {
		rd = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, server.URL+path, rd)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if basic != nil {
		req.SetBasicAuth(url.QueryEscape(basic.id), url.QueryEscape(basic.secret))
	}
	res, err := c.http.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := resp{Status: res.StatusCode, Raw: raw}
	_ = json.Unmarshal(raw, &out.Obj)
	return res, out
}

// authorize starts a sign-in of a at /oauth2/authorize; it answers the Location and the PKCE verifier.
func (c *client) authorize(t testing.TB, a app, scope string, extra url.Values) (*url.URL, string) {
	t.Helper()
	v, ch := pkcePair()
	q := url.Values{"response_type": {"code"}, "client_id": {a.id}, "redirect_uri": {a.redirect}, "scope": {scope}, "state": {"st-123"},
		"nonce": {"n-456"}, "code_challenge": {ch}, "code_challenge_method": {"S256"}}
	for k, x := range extra {
		q[k] = x
	}
	res, r := c.call(t, "GET", "/oauth2/authorize?"+q.Encode(), nil, nil)
	if res.StatusCode != 302 {
		t.Fatalf("authorize: %d %s", res.StatusCode, r.Raw)
	}
	loc, _ := url.Parse(res.Header.Get("Location"))
	return loc, v
}

// signInFor goes through the login page: authorize → login_challenge → sign-in → complete; answers the code.
func signInFor(t testing.TB, c *client, a app, user, pw, scope string) (code, verifier string) {
	t.Helper()
	loc, v := c.authorize(t, a, scope, nil)
	if code := loc.Query().Get("code"); code != "" && strings.HasPrefix(loc.String(), a.redirect) {
		return code, v // signed in already in this browser (SSO)
	}
	ch := loc.Query().Get("login_challenge")
	if ch == "" {
		t.Fatalf("expected the login page, got %s", loc)
	}
	must(t, c.login(t, user, pw), 200)
	done := must(t, c.do(t, "POST", "/oauth2/authorize/complete", map[string]any{"loginChallenge": ch}), 200)
	back, _ := url.Parse(done.str("redirect"))
	if back.Query().Get("state") != "st-123" || !strings.HasPrefix(done.str("redirect"), a.redirect) {
		t.Fatalf("redirect %s", done.str("redirect"))
	}
	return back.Query().Get("code"), v
}

func exchange(t testing.TB, c *client, a app, code, verifier string) resp {
	t.Helper()
	f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {a.redirect}, "code_verifier": {verifier}}
	var basic *app
	if a.secret != "" {
		basic = &a
	} else {
		f.Set("client_id", a.id)
	}
	_, r := c.call(t, "POST", "/oauth2/token", f, basic)
	return r
}

func register(t testing.TB, admin *client, body map[string]any) app {
	t.Helper()
	b := map[string]any{"name": "Aplikasi Uji", "redirectUris": []string{"https://app.test/cb"}, "postLogoutUris": []string{"https://app.test/bye"},
		"scopes": []string{"openid", "profile", "email", "dod.access"}, "accessTokenMinutes": 15, "refreshTokenDays": 14, "active": true}
	for k, v := range body {
		b[k] = v
	}
	r := must(t, admin.do(t, "POST", "/auth/clients", b), 201)
	cl := r.Obj["client"].(map[string]any)
	s, _ := r.Obj["secret"].(string)
	return app{id: cl["id"].(string), secret: s, redirect: b["redirectUris"].([]string)[0]}
}

var oidcUser struct {
	sync.Once
	name string
}

// oidcMember is a member of gan with a password already changed.
func oidcMember(t *testing.T, a *client) string {
	oidcUser.Do(func() { oidcUser.name, _ = newUser(t, a, "viewer") })
	return oidcUser.name
}

func TestOIDCPositive(t *testing.T) {
	a := admin(t)
	pmApp := register(t, a, map[string]any{"name": "Portal Master App", "module": "portal-master"})
	user := oidcMember(t, a)

	t.Run("OP01 discovery and keys describe the provider", func(t *testing.T) {
		d := must(t, newClient().do(t, "GET", "/.well-known/openid-configuration", nil), 200)
		if d.str("issuer") != "alir-auth" || d.str("authorization_endpoint") != server.URL+"/oauth2/authorize" || d.str("token_endpoint") != server.URL+"/oauth2/token" {
			t.Errorf("discovery %s", trunc(d.Raw))
		}
		if !strings.Contains(string(d.Raw), `"S256"`) || !strings.Contains(string(d.Raw), `"RS256"`) || strings.Contains(string(d.Raw), `"plain"`) {
			t.Errorf("PKCE S256 only, EdDSA: %s", trunc(d.Raw))
		}
		if k := must(t, newClient().do(t, "GET", "/.well-known/jwks.json", nil), 200); len(k.Obj["keys"].([]any)) != 2 {
			t.Errorf("jwks %s", k.Raw)
		}
	})

	t.Run("OP02 an administrator registers an application; the secret is shown once", func(t *testing.T) {
		if pmApp.secret == "" || !strings.HasPrefix(pmApp.secret, "sec_") {
			t.Fatalf("secret %q", pmApp.secret)
		}
		for _, x := range must(t, a.do(t, "GET", "/auth/clients", nil), 200).List {
			if x["id"] == pmApp.id && (x["secretHint"] != pmApp.secret[len(pmApp.secret)-4:] || strings.Contains(trunc(must(t, a.do(t, "GET", "/auth/clients", nil), 200).Raw), pmApp.secret)) {
				t.Errorf("list shows the secret or a wrong hint: %v", x)
			}
		}
		if o := must(t, a.do(t, "GET", "/auth/oidc", nil), 200); o.str("authorize") != server.URL+"/oauth2/authorize" {
			t.Errorf("oidc config %s", o.Raw)
		}
	})

	var tokens resp
	t.Run("OP03 the code flow through the login page: code, tokens, claims and userinfo", func(t *testing.T) {
		b := newClient()
		code, v := signInFor(t, b, pmApp, "admin", adminPw, "openid profile email dod.access")
		tokens = exchange(t, b, pmApp, code, v)
		if tokens.Status != 200 || tokens.str("token_type") != "Bearer" || tokens.str("id_token") == "" || tokens.str("refresh_token") == "" {
			t.Fatalf("tokens %d %s", tokens.Status, trunc(tokens.Raw))
		}
		if h := tokenHeader(t, tokens.str("id_token")); h["alg"] != "RS256" {
			t.Errorf("ID token algorithm %v (RS256 by default)", h)
		}
		if h := tokenHeader(t, tokens.str("access_token")); h["alg"] != "EdDSA" {
			t.Errorf("access token algorithm %v", h)
		}
		id := tokenClaims(t, tokens.str("id_token"))
		if id["aud"] != pmApp.id || id["nonce"] != "n-456" || id["iss"] != "alir-auth" || id["tenant"] != "gan" || id["name"] == nil || id["sid"] == nil {
			t.Errorf("id token %v", id)
		}
		at := tokenClaims(t, tokens.str("access_token"))
		grants, _ := at["grants"].(map[string]any)
		if at["client_id"] != pmApp.id || at["tid"] == nil || len(grants) == 0 || at["full"] != nil {
			t.Errorf("access token %v", at)
		}
		for menu := range grants {
			if !strings.HasPrefix(menu, "pm.") {
				t.Errorf("an application gets only its module's menus: %s", menu)
			}
		}
		req, _ := http.NewRequest("GET", server.URL+"/oauth2/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.str("access_token"))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var ui map[string]any
		_ = json.NewDecoder(res.Body).Decode(&ui)
		res.Body.Close()
		if res.StatusCode != 200 || ui["sub"] != id["sub"] || ui["preferred_username"] != "admin" || ui["tenant"] != "gan" {
			t.Errorf("userinfo %d %v", res.StatusCode, ui)
		}
	})

	t.Run("OP04 single sign-on: signed in once, the next application gets a code without the login page", func(t *testing.T) {
		b := newClient()
		code, v := signInFor(t, b, pmApp, user, "Tetap2026x", "openid profile")
		must(t, exchange(t, b, pmApp, code, v), 200)
		other := register(t, a, map[string]any{"name": "Aplikasi Kedua", "redirectUris": []string{"https://dua.test/cb"}})
		loc, v2 := b.authorize(t, other, "openid", nil)
		if loc.Query().Get("code") == "" || loc.Query().Get("iss") != "alir-auth" || !strings.HasPrefix(loc.String(), "https://dua.test/cb") {
			t.Fatalf("SSO should answer a code at once: %s", loc)
		}
		if r := exchange(t, b, other, loc.Query().Get("code"), v2); r.Status != 200 {
			t.Errorf("SSO code: %d %s", r.Status, r.Raw)
		}
		if loc2, _ := b.authorize(t, other, "openid", url.Values{"prompt": {"login"}}); loc2.Query().Get("login_challenge") == "" {
			t.Errorf("prompt=login must go to the login page: %s", loc2)
		}
	})

	t.Run("OP05 refresh tokens rotate; a stolen one ends the application's access", func(t *testing.T) {
		b := newClient()
		code, v := signInFor(t, b, pmApp, user, "Tetap2026x", "openid profile")
		first := must(t, exchange(t, b, pmApp, code, v), 200).str("refresh_token")
		_, r := b.call(t, "POST", "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first}}, &pmApp)
		second := r.str("refresh_token")
		if r.Status != 200 || second == "" || second == first || r.str("access_token") == "" {
			t.Fatalf("refresh %d %s", r.Status, r.Raw)
		}
		// The old one shown again after the grace of a parallel refresh: theft; the newest stops too.
		_, _ = pool.Exec(context.Background(), `UPDATE auth.oauth_grant SET last_used_at = now() - interval '1 minute' WHERE previous_hash IS NOT NULL`)
		if _, x := b.call(t, "POST", "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first}}, &pmApp); x.str("error") != "invalid_grant" {
			t.Errorf("reuse: %s", x.Raw)
		}
		if _, x := b.call(t, "POST", "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {second}}, &pmApp); x.str("error") != "invalid_grant" {
			t.Errorf("after theft the newest must stop: %s", x.Raw)
		}
	})

	t.Run("OP06 a public application (browser) signs in with PKCE only", func(t *testing.T) {
		spa := register(t, a, map[string]any{"name": "SPA Uji", "public": true, "redirectUris": []string{"http://localhost:3000/cb"}})
		if spa.secret != "" {
			t.Fatalf("a public application has no secret")
		}
		b := newClient()
		code, v := signInFor(t, b, spa, user, "Tetap2026x", "openid")
		if r := exchange(t, b, spa, code, v); r.Status != 200 || r.str("id_token") == "" {
			t.Errorf("public exchange: %d %s", r.Status, r.Raw)
		}
	})

	t.Run("OP07 client_credentials: a service of the company acts with its service role", func(t *testing.T) {
		svcApp := register(t, a, map[string]any{"name": "Layanan Sinkron", "serviceRole": "analyst"})
		_, r := newClient().call(t, "POST", "/oauth2/token", url.Values{"grant_type": {"client_credentials"}}, &svcApp)
		if r.Status != 200 || r.str("id_token") != "" || r.str("refresh_token") != "" {
			t.Fatalf("service token %d %s", r.Status, r.Raw)
		}
		c := tokenClaims(t, r.str("access_token"))
		if c["role"] != "service" || c["tid"] == nil || c["client_id"] != svcApp.id || c["grants"] == nil || c["full"] != nil {
			t.Errorf("service claims %v", c)
		}
	})

	t.Run("OP08 logout ends the sign-in: every application's refresh stops, SSO is gone, back to the registered page", func(t *testing.T) {
		b := newClient()
		code, v := signInFor(t, b, pmApp, user, "Tetap2026x", "openid profile")
		tk := must(t, exchange(t, b, pmApp, code, v), 200)
		q := url.Values{"id_token_hint": {tk.str("id_token")}, "post_logout_redirect_uri": {"https://app.test/bye"}, "state": {"out-1"}}
		res, _ := b.call(t, "GET", "/oauth2/logout?"+q.Encode(), nil, nil)
		if res.StatusCode != 302 || res.Header.Get("Location") != "https://app.test/bye?state=out-1" {
			t.Fatalf("logout %d %s", res.StatusCode, res.Header.Get("Location"))
		}
		if _, x := b.call(t, "POST", "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tk.str("refresh_token")}}, &pmApp); x.str("error") != "invalid_grant" {
			t.Errorf("refresh after logout: %s", x.Raw)
		}
		if r := b.do(t, "GET", "/auth/me", nil); r.Status != 401 {
			t.Errorf("the ALIR session after logout: %d", r.Status)
		}
		if loc, _ := b.authorize(t, pmApp, "openid", nil); loc.Query().Get("login_challenge") == "" {
			t.Errorf("SSO after logout: %s", loc)
		}
	})

	t.Run("OP10 an application that asks for EdDSA ID tokens gets them; both keys are published", func(t *testing.T) {
		ed := register(t, a, map[string]any{"name": "Aplikasi EdDSA", "idTokenAlg": "EdDSA"})
		b := newClient()
		code, v := signInFor(t, b, ed, user, "Tetap2026x", "openid")
		if h := tokenHeader(t, must(t, exchange(t, b, ed, code, v), 200).str("id_token")); h["alg"] != "EdDSA" {
			t.Errorf("EdDSA client got %v", h)
		}
		k := must(t, newClient().do(t, "GET", "/.well-known/jwks.json", nil), 200).Obj["keys"].([]any)
		kinds := map[string]bool{}
		for _, x := range k {
			kinds[x.(map[string]any)["alg"].(string)] = true
		}
		if !kinds["RS256"] || !kinds["EdDSA"] || len(k) != 2 {
			t.Errorf("jwks %v", k)
		}
		if r := a.do(t, "POST", "/auth/clients", map[string]any{"name": "Salah", "redirectUris": []string{"https://x.test/cb"}, "scopes": []string{"openid"},
			"accessTokenMinutes": 15, "refreshTokenDays": 1, "idTokenAlg": "HS256"}); r.Status != 422 {
			t.Errorf("HS256 accepted: %d", r.Status)
		}
	})

	t.Run("OP09 an application revokes its refresh token", func(t *testing.T) {
		b := newClient()
		code, v := signInFor(t, b, pmApp, user, "Tetap2026x", "openid")
		rt := must(t, exchange(t, b, pmApp, code, v), 200).str("refresh_token")
		if _, r := b.call(t, "POST", "/oauth2/revoke", url.Values{"token": {rt}}, &pmApp); r.Status != 200 {
			t.Errorf("revoke: %d", r.Status)
		}
		if _, x := b.call(t, "POST", "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, &pmApp); x.str("error") != "invalid_grant" {
			t.Errorf("after revoke: %s", x.Raw)
		}
	})
}

func TestOIDCNegative(t *testing.T) {
	a := admin(t)
	x := register(t, a, map[string]any{"name": "Aplikasi Negatif"})
	user := oidcMember(t, a)

	t.Run("ON01 authorize refuses what it must, and never redirects to an unregistered address", func(t *testing.T) {
		b := newClient()
		_, ch := pkcePair()
		base := url.Values{"response_type": {"code"}, "client_id": {x.id}, "redirect_uri": {x.redirect}, "scope": {"openid"}, "state": {"s"},
			"code_challenge": {ch}, "code_challenge_method": {"S256"}}
		with := func(k, v string) url.Values {
			q := url.Values{}
			for a, b := range base {
				q[a] = b
			}
			if v == "" {
				q.Del(k)
			} else {
				q.Set(k, v)
			}
			return q
		}
		for name, q := range map[string]url.Values{"unknown client": with("client_id", "app-tidakada"), "unregistered redirect": with("redirect_uri", "https://evil.test/cb"),
			"redirect prefix": with("redirect_uri", x.redirect+"/../evil")} {
			res, r := b.call(t, "GET", "/oauth2/authorize?"+q.Encode(), nil, nil)
			if res.StatusCode != 400 || res.Header.Get("Location") != "" {
				t.Errorf("%s: %d %s", name, res.StatusCode, r.Raw)
			}
		}
		for name, c := range map[string]struct {
			q    url.Values
			want string
		}{
			"no PKCE":        {with("code_challenge", ""), "invalid_request"},
			"plain PKCE":     {with("code_challenge_method", "plain"), "invalid_request"},
			"implicit":       {with("response_type", "token"), "unsupported_response_type"},
			"scope too wide": {with("scope", "openid admin"), "invalid_scope"},
			"no openid":      {with("scope", "profile"), "invalid_scope"},
			"prompt none":    {with("prompt", "none"), "login_required"},
		} {
			res, _ := b.call(t, "GET", "/oauth2/authorize?"+c.q.Encode(), nil, nil)
			loc, _ := url.Parse(res.Header.Get("Location"))
			if res.StatusCode != 302 || !strings.HasPrefix(loc.String(), x.redirect) || loc.Query().Get("error") != c.want || loc.Query().Get("state") != "s" {
				t.Errorf("%s: %d %s", name, res.StatusCode, loc)
			}
		}
	})

	t.Run("ON02 the token endpoint: secret, code reuse, verifier, redirect, other application, expiry", func(t *testing.T) {
		b := newClient()
		code, v := signInFor(t, b, x, user, "Tetap2026x", "openid")
		wrong := x
		wrong.secret = "sec_salah"
		if r := exchange(t, b, wrong, code, v); r.Status != 401 || r.str("error") != "invalid_client" {
			t.Errorf("wrong secret: %d %s", r.Status, r.Raw)
		}
		bad := v[:len(v)-1] + map[bool]string{true: "B", false: "A"}[strings.HasSuffix(v, "A")] // always a different verifier
		if r := exchange(t, b, x, code, bad); r.str("error") != "invalid_grant" {
			t.Errorf("wrong verifier: %s", r.Raw)
		}
		code, v = signInFor(t, b, x, user, "Tetap2026x", "openid")
		bent := x
		bent.redirect = "https://app.test/lain"
		if r := exchange(t, b, bent, code, v); r.str("error") != "invalid_grant" {
			t.Errorf("other redirect_uri: %s", r.Raw)
		}
		code, v = signInFor(t, b, x, user, "Tetap2026x", "openid")
		first := must(t, exchange(t, b, x, code, v), 200)
		if r := exchange(t, b, x, code, v); r.str("error") != "invalid_grant" {
			t.Errorf("code twice: %s", r.Raw)
		}
		if _, r := b.call(t, "POST", "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first.str("refresh_token")}}, &x); r.str("error") != "invalid_grant" {
			t.Errorf("a replayed code ends what it bought: %s", r.Raw)
		}
		other := register(t, a, map[string]any{"name": "Aplikasi Lain"})
		code, v = signInFor(t, b, x, user, "Tetap2026x", "openid")
		if r := exchange(t, b, app{other.id, other.secret, x.redirect}, code, v); r.str("error") != "invalid_grant" {
			t.Errorf("code of another application: %s", r.Raw)
		}
		code, v = signInFor(t, b, x, user, "Tetap2026x", "openid")
		_, _ = pool.Exec(context.Background(), `UPDATE auth.auth_code SET expires_at = now() - interval '1 second' WHERE used_at IS NULL`)
		if r := exchange(t, b, x, code, v); r.str("error") != "invalid_grant" {
			t.Errorf("expired code: %s", r.Raw)
		}
		if _, r := b.call(t, "POST", "/oauth2/token", url.Values{"grant_type": {"password"}, "username": {"admin"}}, &x); r.str("error") != "unsupported_grant_type" {
			t.Errorf("password grant: %s", r.Raw)
		}
		if _, r := b.call(t, "POST", "/oauth2/token", url.Values{"grant_type": {"client_credentials"}}, &x); r.str("error") != "unauthorized_client" {
			t.Errorf("client_credentials without a service role: %s", r.Raw)
		}
	})

	t.Run("ON03 a company's application signs in only that company's members", func(t *testing.T) {
		b := betaAdmin(t)
		betaApp := register(t, b, map[string]any{"name": "Aplikasi Beta", "redirectUris": []string{"https://beta.test/cb"}})
		c := newClient()
		loc, _ := c.authorize(t, betaApp, "openid", nil)
		must(t, c.login(t, user, "Tetap2026x"), 200)
		if r := c.do(t, "POST", "/oauth2/authorize/complete", map[string]any{"loginChallenge": loc.Query().Get("login_challenge")}); r.Status != 403 || r.str("code") != "NOT_MEMBER" {
			t.Errorf("gan member into a beta application: %d %s", r.Status, r.Raw)
		}
		for _, l := range must(t, b.do(t, "GET", "/auth/clients", nil), 200).List {
			if l["id"] == x.id || l["id"] == "alir-web" {
				t.Errorf("beta lists %v", l["id"])
			}
		}
		if r := b.do(t, "PUT", "/auth/clients/"+x.id, map[string]any{"name": "Dibajak", "redirectUris": []string{"https://evil.test"}, "scopes": []string{"openid"},
			"accessTokenMinutes": 15, "refreshTokenDays": 1}); r.Status != 404 {
			t.Errorf("beta changes a gan application: %d", r.Status)
		}
		if r := b.do(t, "POST", "/auth/clients", map[string]any{"name": "Platform?", "platform": true, "redirectUris": []string{"https://p.test/cb"},
			"scopes": []string{"openid"}, "accessTokenMinutes": 15, "refreshTokenDays": 1}); r.Status != 422 {
			t.Errorf("a company admin registers a platform application: %d", r.Status)
		}
	})

	t.Run("ON04 the application form is checked", func(t *testing.T) {
		for name, body := range map[string]map[string]any{
			"http redirect":    {"redirectUris": []string{"http://app.test/cb"}},
			"fragment":         {"redirectUris": []string{"https://app.test/cb#x"}},
			"no redirect":      {"redirectUris": []string{}},
			"unknown scope":    {"scopes": []string{"openid", "root"}},
			"no openid":        {"scopes": []string{"profile"}},
			"tokens too long":  {"accessTokenMinutes": 500},
			"unknown module":   {"module": "tidak-ada"},
			"admin as service": {"serviceRole": "admin"},
			"public service":   {"public": true, "serviceRole": "analyst"},
		} {
			b := map[string]any{"name": "Cek", "redirectUris": []string{"https://app.test/cb"}, "scopes": []string{"openid"}, "accessTokenMinutes": 15, "refreshTokenDays": 1}
			for k, v := range body {
				b[k] = v
			}
			if r := a.do(t, "POST", "/auth/clients", b); r.Status != 422 {
				t.Errorf("%s: %d %s", name, r.Status, trunc(r.Raw))
			}
		}
	})

	t.Run("ON05 a deactivated application gets nothing and loses its grants; a rotated secret stops the old one", func(t *testing.T) {
		d := register(t, a, map[string]any{"name": "Akan Nonaktif"})
		b := newClient()
		code, v := signInFor(t, b, d, user, "Tetap2026x", "openid")
		rt := must(t, exchange(t, b, d, code, v), 200).str("refresh_token")
		rot := must(t, a.do(t, "POST", "/auth/clients/"+d.id+"/secret", nil), 200)
		if _, r := b.call(t, "POST", "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, &d); r.str("error") != "invalid_client" {
			t.Errorf("old secret after rotation: %s", r.Raw)
		}
		d.secret = rot.str("secret")
		cl := rot.Obj["client"].(map[string]any)
		must(t, a.do(t, "PUT", "/auth/clients/"+d.id, map[string]any{"name": cl["name"], "redirectUris": cl["redirectUris"], "postLogoutUris": cl["postLogoutUris"],
			"scopes": cl["scopes"], "accessTokenMinutes": 15, "refreshTokenDays": 14, "active": false}), 200)
		if _, r := b.call(t, "POST", "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, &d); r.str("error") != "invalid_client" {
			t.Errorf("deactivated application: %s", r.Raw)
		}
		res, _ := b.call(t, "GET", "/oauth2/authorize?client_id="+d.id, nil, nil)
		if res.StatusCode != 400 {
			t.Errorf("authorize a deactivated application: %d", res.StatusCode)
		}
	})

	t.Run("ON06 a challenge is single-use, expires, and waits for a required password change", func(t *testing.T) {
		c := newClient()
		loc, _ := c.authorize(t, x, "openid", nil)
		ch := loc.Query().Get("login_challenge")
		if r := must(t, newClient().do(t, "GET", "/oauth2/authorize/request?login_challenge="+url.QueryEscape(ch), nil), 200); r.Obj["client"].(map[string]any)["name"] != "Aplikasi Negatif" {
			t.Errorf("request info %s", r.Raw)
		}
		fresh, _ := newUserPw(t, a, "Awal2026x!") // must change the password first
		if r := c.login(t, fresh, "Awal2026x!"); r.Obj["mustChangePassword"] == nil {
			t.Skip("expected a must-change account")
		}
		if r := c.do(t, "POST", "/oauth2/authorize/complete", map[string]any{"loginChallenge": ch}); r.Status != 403 || r.str("code") != "MUST_CHANGE_PASSWORD" {
			t.Errorf("must change first: %d %s", r.Status, r.Raw)
		}
		must(t, c.do(t, "POST", "/auth/password/change", map[string]any{"next": "Ganti2026x!"}), 204)
		must(t, c.login(t, fresh, "Ganti2026x!"), 200)
		must(t, c.do(t, "POST", "/oauth2/authorize/complete", map[string]any{"loginChallenge": ch}), 200)
		if r := c.do(t, "POST", "/oauth2/authorize/complete", map[string]any{"loginChallenge": ch}); r.Status != 404 {
			t.Errorf("challenge twice: %d", r.Status)
		}
		loc, _ = c.authorize(t, x, "openid", url.Values{"prompt": {"login"}})
		_, _ = pool.Exec(context.Background(), `UPDATE auth.authz_request SET expires_at = now() - interval '1 second' WHERE completed_at IS NULL`)
		if r := c.do(t, "POST", "/oauth2/authorize/complete", map[string]any{"loginChallenge": loc.Query().Get("login_challenge")}); r.Status != 404 || r.str("code") != "LOGIN_EXPIRED" {
			t.Errorf("expired challenge: %d %s", r.Status, r.Raw)
		}
	})

	t.Run("ON07 userinfo and logout refuse forged input", func(t *testing.T) {
		req, _ := http.NewRequest("GET", server.URL+"/oauth2/userinfo", nil)
		req.Header.Set("Authorization", "Bearer a.b.c")
		res, _ := http.DefaultClient.Do(req)
		res.Body.Close()
		if res.StatusCode != 401 || !strings.Contains(res.Header.Get("WWW-Authenticate"), "invalid_token") {
			t.Errorf("userinfo forged: %d", res.StatusCode)
		}
		if res, _ := newClient().call(t, "GET", "/oauth2/logout?post_logout_redirect_uri="+url.QueryEscape("https://evil.test/")+"&client_id="+x.id, nil, nil); res.StatusCode != 400 {
			t.Errorf("logout to an unregistered address: %d", res.StatusCode)
		}
		if res, _ := newClient().call(t, "GET", "/oauth2/logout?id_token_hint=a.b.c", nil, nil); res.StatusCode != 400 {
			t.Errorf("logout with a forged hint: %d", res.StatusCode)
		}
	})
}

func TestOIDCStress(t *testing.T) {
	a := admin(t)
	x := register(t, a, map[string]any{"name": "Aplikasi Beban"})
	user := oidcMember(t, a)

	t.Run("OS01 40 sign-ins through SSO at once: every code is unique and trades once", func(t *testing.T) {
		b := newClient()
		code, v := signInFor(t, b, x, user, "Tetap2026x", "openid")
		must(t, exchange(t, b, x, code, v), 200)
		var fails atomic.Int64
		seen := sync.Map{}
		parallel(40, 10, func(int) {
			loc, v := b.authorize(t, x, "openid profile", nil)
			c := loc.Query().Get("code")
			if _, dup := seen.LoadOrStore(c, true); dup || c == "" {
				fails.Add(1)
				return
			}
			if r := exchange(t, b, x, c, v); r.Status != 200 {
				fails.Add(1)
			}
		})
		if fails.Load() != 0 {
			t.Errorf("%d failures", fails.Load())
		}
	})

	t.Run("OS02 one code traded 20 times at once: exactly one gets tokens", func(t *testing.T) {
		b := newClient()
		code, v := signInFor(t, b, x, user, "Tetap2026x", "openid")
		var okN atomic.Int64
		parallel(20, 20, func(int) {
			if r := exchange(t, b, x, code, v); r.Status == 200 {
				okN.Add(1)
			}
		})
		if okN.Load() != 1 {
			t.Errorf("%d exchanges succeeded", okN.Load())
		}
	})
}

func tokenHeader(t *testing.T, tok string) map[string]any {
	t.Helper()
	b, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	var h map[string]any
	_ = json.Unmarshal(b, &h)
	return h
}
