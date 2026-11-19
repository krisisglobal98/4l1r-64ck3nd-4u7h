//go:build e2e

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

/* ---------------- Sign-in and sessions ---------------- */

func TestSignIn(t *testing.T) {
	a := admin(t)

	t.Run("AP01 the first administrator must change the bootstrap password; then full access", func(t *testing.T) {
		r := a.do(t, "GET", "/auth/me/access", nil)
		if want(t, r, 200) && (r.Obj["full"] != true || r.Obj["role"] != "admin") {
			t.Errorf("got %s", r.Raw)
		}
		me := a.do(t, "GET", "/auth/me", nil)
		if want(t, me, 200) && (me.str("username") != "admin" || me.str("method") != "local") {
			t.Errorf("me: %s", me.Raw)
		}
	})

	t.Run("AP02 a new account must change its password first; until then nothing else", func(t *testing.T) {
		must(t, a.do(t, "POST", "/users", map[string]any{"username": "baru.satu", "name": "Baru Satu", "role": "viewer", "levelCode": "COMPANY", "companyCode": "C11", "password": "Awal2026x"}), 201)
		c := newClient()
		r := must(t, c.login(t, "baru.satu", "Awal2026x"), 200)
		if r.Obj["mustChangePassword"] != "first" {
			t.Errorf("must: %v", r.Obj["mustChangePassword"])
		}
		if x := c.do(t, "GET", "/users", nil); x.Status != 403 || x.str("code") != "MUST_CHANGE_PASSWORD" {
			t.Errorf("blocked: %d %s", x.Status, x.Raw)
		}
		if claims := tokenClaims(t, c.token); claims["grants"] != nil || claims["full"] == true {
			t.Errorf("a token before the password change grants nothing (Portal Master refuses it): %v", claims)
		}
		if x := c.do(t, "POST", "/auth/password/change", map[string]any{"next": "pendek"}); want(t, x, 422) && !strings.Contains(x.problem("next"), "minimal 8 karakter") {
			t.Errorf("rule: %s", x.Raw)
		}
		if x := c.do(t, "POST", "/auth/password/change", map[string]any{"next": "Awal2026x"}); want(t, x, 422) && x.problem("next") != "Password baru harus berbeda dari yang lama." {
			t.Errorf("same: %s", x.Raw)
		}
		must(t, c.do(t, "POST", "/auth/password/change", map[string]any{"next": "Baru2026x"}), 204)
		if x := c.login(t, "baru.satu", "Baru2026x"); want(t, x, 200) && x.Obj["mustChangePassword"] != nil {
			t.Errorf("after: %s", x.Raw)
		}
	})

	t.Run("AP03 refresh rotates the cookie: the old one reused later ends the session", func(t *testing.T) {
		u, _ := newUser(t, a, "viewer")
		c := newClient()
		must(t, c.login(t, u, "Tetap2026x"), 200)
		old := c.http.Jar.Cookies(mustURL(server.URL + "/auth"))
		r := must(t, c.do(t, "POST", "/auth/refresh", nil), 200)
		if r.str("token") == "" || r.str("token") == c.token {
			t.Errorf("new token: %s", r.Raw)
		}
		c.token = r.str("token")
		// a thief with the old cookie, after the grace period (a database instant)
		_, _ = pool.Exec(context.Background(), `UPDATE auth.session SET last_seen_at = now() - interval '1 minute' WHERE previous_hash IS NOT NULL AND membership_id = (SELECT id FROM auth.membership WHERE username = $1)`, u)
		thief := newClient()
		thief.http.Jar.SetCookies(mustURL(server.URL+"/auth"), old)
		if x := thief.do(t, "POST", "/auth/refresh", nil); x.Status != 401 || x.str("code") != "SESSION_ENDED" {
			t.Errorf("reuse: %d %s", x.Status, x.Raw)
		}
		if x := c.do(t, "GET", "/auth/me", nil); x.Status != 401 || x.str("code") != "SESSION_ENDED" {
			t.Errorf("the stolen session ends for its owner too: %d %s", x.Status, x.Raw)
		}
	})

	t.Run("AP04 an expired access token: 401 TOKEN_EXPIRED, refresh, go on", func(t *testing.T) {
		u, _ := newUser(t, a, "viewer")
		c := newClient()
		must(t, c.login(t, u, "Tetap2026x"), 200)
		advance(16 * time.Minute)
		if x := c.send(t, "GET", "/auth/me", nil); x.Status != 401 || x.str("code") != "TOKEN_EXPIRED" {
			t.Errorf("expired: %d %s", x.Status, x.Raw)
		}
		r := must(t, c.send(t, "POST", "/auth/refresh", nil), 200)
		c.token = r.str("token")
		want(t, c.send(t, "GET", "/auth/me", nil), 200)
	})

	t.Run("AP05 logout ends the session and drops the cookie", func(t *testing.T) {
		u, _ := newUser(t, a, "viewer")
		c := newClient()
		must(t, c.login(t, u, "Tetap2026x"), 200)
		must(t, c.do(t, "POST", "/auth/logout", nil), 204)
		if x := c.do(t, "GET", "/auth/me", nil); x.Status != 401 {
			t.Errorf("after logout: %d", x.Status)
		}
		if x := c.do(t, "POST", "/auth/refresh", nil); x.Status != 401 {
			t.Errorf("refresh after logout: %d", x.Status)
		}
	})

	t.Run("AP06 sessions: list own, end another, not the current; administrator ends any", func(t *testing.T) {
		u, id := newUser(t, a, "viewer")
		c1, c2 := newClient(), newClient()
		must(t, c1.login(t, u, "Tetap2026x"), 200)
		must(t, c2.login(t, u, "Tetap2026x"), 200)
		current := sessionOf(t, c1)
		other := sessionOf(t, c2) // the user's other session, as c2 sees it
		if x := c1.do(t, "DELETE", "/auth/me/sessions/"+current, nil); x.Status != 409 {
			t.Errorf("current: %d", x.Status)
		}
		must(t, c1.do(t, "DELETE", "/auth/me/sessions/"+other, nil), 204)
		if x := c2.do(t, "GET", "/auth/me", nil); x.Status != 401 {
			t.Errorf("ended session still works: %d", x.Status)
		}
		r := must(t, a.do(t, "POST", "/users/"+id+"/revoke-sessions", nil), 200)
		if r.Obj["revoked"].(float64) < 1 { // c1's, and the one newUser signed in with
			t.Errorf("revoked %v", r.Obj["revoked"])
		}
		if x := c1.do(t, "GET", "/auth/me", nil); x.Status != 401 {
			t.Errorf("after admin revoke: %d", x.Status)
		}
	})

	t.Run("AP07 a reset link from the administrator: single use, ends every session", func(t *testing.T) {
		u, id := newUser(t, a, "viewer")
		c := newClient()
		must(t, c.login(t, u, "Tetap2026x"), 200)
		link := must(t, a.do(t, "POST", "/users/"+id+"/reset-link", nil), 200).str("link")
		tok := strings.TrimPrefix(link, "/reset-password?token=")
		anon := newClient()
		if x := anon.do(t, "POST", "/auth/password/reset", map[string]any{"token": tok, "password": "x"}); want(t, x, 422) && x.problem("password") == "" {
			t.Errorf("rules: %s", x.Raw)
		}
		must(t, anon.do(t, "POST", "/auth/password/reset", map[string]any{"token": tok, "password": "Reset2026x"}), 204)
		if x := anon.do(t, "POST", "/auth/password/reset", map[string]any{"token": tok, "password": "Lagi2026x"}); x.Status != 409 {
			t.Errorf("second use: %d", x.Status)
		}
		if x := c.do(t, "GET", "/auth/me", nil); x.Status != 401 {
			t.Errorf("old session: %d", x.Status)
		}
		want(t, newClient().login(t, u, "Reset2026x"), 200)
	})

	t.Run("AP08 forgot password answers the same whether the account exists or not", func(t *testing.T) {
		x := newClient().do(t, "POST", "/auth/password/forgot", map[string]any{"username": "admin"})
		y := newClient().do(t, "POST", "/auth/password/forgot", map[string]any{"username": "tidak.ada"})
		if x.Status != 200 || y.Status != 200 || string(x.Raw) != string(y.Raw) {
			t.Errorf("%d %s / %d %s", x.Status, x.Raw, y.Status, y.Raw)
		}
	})

	t.Run("AP09 login options and JWKS are public", func(t *testing.T) {
		o := must(t, newClient().do(t, "GET", "/auth/login-options", nil), 200)
		if o.Obj["localEnabled"] != true || o.Obj["password"].(map[string]any)["passwordMinLength"] != 8.0 {
			t.Errorf("options %s", o.Raw)
		}
		k := must(t, newClient().do(t, "GET", "/.well-known/jwks.json", nil), 200)
		keys := k.Obj["keys"].([]any)
		// The Ed25519 key of the access tokens and the RSA key of ID tokens; never a private part (d, p, q, …).
		if len(keys) != 2 || keys[0].(map[string]any)["crv"] != "Ed25519" || keys[1].(map[string]any)["kty"] != "RSA" {
			t.Errorf("jwks %s", k.Raw)
		}
		for _, x := range keys {
			for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
				if x.(map[string]any)[private] != nil {
					t.Errorf("private part %s published", private)
				}
			}
		}
	})
}

func mustURL(s string) *url.URL { u, _ := url.Parse(s); return u }

/* ---------------- Refused sign-ins ---------------- */

func TestSignInRefused(t *testing.T) {
	a := admin(t)

	t.Run("AN01 wrong password and unknown user answer the same", func(t *testing.T) {
		x := newClient().login(t, "admin", "salah")
		y := newClient().login(t, "tidak.ada", "salah")
		if x.Status != 401 || y.Status != 401 || x.str("message") != y.str("message") || x.str("message") != "Username/email atau password salah." {
			t.Errorf("%s / %s", x.Raw, y.Raw)
		}
	})

	t.Run("AN02 five wrong passwords lock the account; the right one is refused while locked; unlock", func(t *testing.T) {
		u, id := newUser(t, a, "viewer")
		for i := 1; i <= 4; i++ {
			if x := newClient().login(t, u, "salah"); x.Status != 401 {
				t.Errorf("try %d: %d", i, x.Status)
			}
		}
		if x := newClient().login(t, u, "salah"); x.Status != 423 || x.str("code") != "LOCKED" {
			t.Errorf("5th: %d %s", x.Status, x.Raw)
		}
		if x := newClient().login(t, u, "Tetap2026x"); x.Status != 423 {
			t.Errorf("right password while locked: %d", x.Status)
		}
		list := must(t, a.do(t, "GET", "/users/"+id, nil), 200)
		if list.Obj["lockedUntil"] == nil {
			t.Errorf("lockedUntil not shown: %s", list.Raw)
		}
		must(t, a.do(t, "POST", "/users/"+id+"/unlock", nil), 200)
		want(t, newClient().login(t, u, "Tetap2026x"), 200)
	})

	t.Run("AN03 the lock ends by itself after lockoutMinutes", func(t *testing.T) {
		u, _ := newUser(t, a, "viewer")
		for range 5 {
			newClient().login(t, u, "salah")
		}
		// the lock is a database instant: let it pass there
		_, _ = pool.Exec(context.Background(), `UPDATE auth.identity SET locked_until = now() - interval '1 second' WHERE id = (SELECT identity_id FROM auth.membership WHERE username = $1)`, u)
		want(t, newClient().login(t, u, "Tetap2026x"), 200)
	})

	t.Run("AN04 an inactive account is refused after the password check, and loses its sessions", func(t *testing.T) {
		u, id := newUser(t, a, "viewer")
		c := newClient()
		must(t, c.login(t, u, "Tetap2026x"), 200)
		g := must(t, a.do(t, "GET", "/users/"+id, nil), 200)
		body := userBody(g)
		body["active"] = false
		must(t, a.do(t, "PUT", "/users/"+id, body), 200)
		if x := c.do(t, "GET", "/auth/me", nil); x.Status != 401 {
			t.Errorf("session of a deactivated account: %d", x.Status)
		}
		if x := newClient().login(t, u, "Tetap2026x"); x.Status != 403 || x.str("code") != "INACTIVE" {
			t.Errorf("login: %d %s", x.Status, x.Raw)
		}
		if x := newClient().login(t, u, "salah"); x.Status != 401 {
			t.Errorf("a wrong guess does not tell it is inactive: %d", x.Status)
		}
	})

	t.Run("AN05 forged, foreign and garbage tokens; no token", func(t *testing.T) {
		c := newClient()
		for _, tok := range []string{"x.y.z", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.", strings.Repeat("a", 20000)} {
			c.token = tok
			if x := c.do(t, "GET", "/users", nil); x.Status != 401 {
				t.Errorf("token %q: %d", tok[:5], x.Status)
			}
		}
		c.token = ""
		if x := c.do(t, "GET", "/users", nil); x.Status != 401 {
			t.Errorf("no token: %d", x.Status)
		}
	})

	t.Run("AN06 login body problems", func(t *testing.T) {
		if x := newClient().do(t, "POST", "/auth/login", map[string]any{"username": ""}); x.Status != 422 {
			t.Errorf("empty: %d", x.Status)
		}
		if x := newClient().do(t, "POST", "/auth/login", "nope"); x.Status != 400 && x.Status != 422 {
			t.Errorf("string body: %d", x.Status)
		}
	})
}

/* ---------------- Accounts ---------------- */

func userBody(r resp) map[string]any {
	b := map[string]any{"username": r.Obj["username"], "name": r.Obj["name"], "role": r.Obj["role"], "levelCode": r.Obj["levelCode"],
		"ownershipCode": r.Obj["ownershipCode"], "identityIssuer": r.Obj["identityIssuer"], "externalSubject": r.Obj["externalSubject"],
		"active": r.Obj["active"], "version": r.Obj["version"]}
	for k, v := range r.Obj["scope"].(map[string]any) {
		b[k] = v
	}
	return b
}

func TestUsers(t *testing.T) {
	a := admin(t)

	t.Run("AU01 an account down to organisation level 3: codes, names, generated code", func(t *testing.T) {
		r := must(t, a.do(t, "POST", "/users", map[string]any{"username": "Mandor.Satu", "name": "Mandor Satu", "role": "viewer", "levelCode": "ORG_LEVEL_3",
			"groupCode": "GAN", "regionCode": "KAL", "wilayahCode": "KALBAR", "companyCode": "C11", "operationalUnitCode": "C11-E1",
			"orgLevel1Code": "C11-E1-R1", "orgLevel2Code": "C11-E1-R1-A1", "orgLevel3Code": "C11-E1-R1-A1-B1", "ownerCode": "X", "gmkCode": "Y", "password": "Awal2026x"}), 201)
		names := r.Obj["scopeNames"].(map[string]any)
		scope := r.Obj["scope"].(map[string]any)
		if r.str("username") != "mandor.satu" || !strings.HasPrefix(r.str("code"), "MUS") || names["orgLevel3Code"] != "Blok 001" || names["operationalUnitCode"] != "Kebun Satu" ||
			scope["ownerCode"] != nil || scope["gmkCode"] != nil || r.Obj["mustChangePassword"] != true {
			t.Errorf("got %s", r.Raw)
		}
	})

	t.Run("AU02 scope problems: missing at the level, not fitting above, inactive unit, below the level cleared", func(t *testing.T) {
		base := func(extra map[string]any) map[string]any {
			b := map[string]any{"username": "scope.test", "name": "Scope Test", "role": "viewer", "password": "Awal2026x"}
			for k, v := range extra {
				b[k] = v
			}
			return b
		}
		for name, c := range map[string]struct {
			body  map[string]any
			field string
		}{
			"no level":        {base(map[string]any{}), "levelCode"},
			"missing unit":    {base(map[string]any{"levelCode": "OPERATIONAL_UNIT", "companyCode": "C11"}), "operationalUnitCode"},
			"unit of another": {base(map[string]any{"levelCode": "OPERATIONAL_UNIT", "companyCode": "C12", "operationalUnitCode": "C11-E1"}), "operationalUnitCode"},
			"inactive unit":   {base(map[string]any{"levelCode": "OPERATIONAL_UNIT", "operationalUnitCode": "C12-E1"}), "operationalUnitCode"},
			"org1 of another": {base(map[string]any{"levelCode": "ORG_LEVEL_1", "operationalUnitCode": "C11-E2", "orgLevel1Code": "C11-E1-R1"}), "orgLevel1Code"},
			"unknown group":   {base(map[string]any{"levelCode": "GROUP", "groupCode": "NOPE"}), "groupCode"},
		} {
			if x := a.do(t, "POST", "/users", c.body); x.Status != 422 || x.problem(c.field) == "" {
				t.Errorf("%s: %d %s", name, x.Status, trunc(x.Raw))
			}
		}
		r := must(t, a.do(t, "POST", "/users", base(map[string]any{"levelCode": "COMPANY", "companyCode": "C11", "operationalUnitCode": "C11-E1", "groupCode": "ALL"})), 201)
		if sc := r.Obj["scope"].(map[string]any); sc["operationalUnitCode"] != nil || sc["groupCode"] != "ALL" || r.Obj["scopeNames"].(map[string]any)["groupCode"] != "Semua group" {
			t.Errorf("below cleared, ALL kept: %s", r.Raw)
		}
	})

	t.Run("AU03 account problems: username taken or bad, role, password rules, SSO pair, no password", func(t *testing.T) {
		ok := map[string]any{"name": "Nama", "role": "viewer", "levelCode": "COMPANY", "companyCode": "C11", "password": "Awal2026x"}
		with := func(k string, v any) map[string]any {
			b := map[string]any{"username": "akun.uji"}
			for a, x := range ok {
				b[a] = x
			}
			b[k] = v
			return b
		}
		must(t, a.do(t, "POST", "/users", with("username", "akun.ada")), 201)
		for name, c := range map[string]struct {
			body       map[string]any
			field, msg string
		}{
			"taken":      {with("username", "AKUN.ADA"), "username", "Username sudah dipakai."},
			"space":      {with("username", "akun uji"), "username", "Username berisi huruf kecil, angka, titik, - atau _ tanpa spasi."},
			"role":       {with("role", "nope"), "role", "Peran tidak tersedia."},
			"short pw":   {with("password", "abc1"), "password", "Password belum memenuhi: minimal 8 karakter."},
			"no number":  {with("password", "abcdefgh"), "password", "Password belum memenuhi: angka (0–9)."},
			"no pw":      {with("password", nil), "password", "Password awal wajib diisi."},
			"sso half":   {with("identityIssuer", "https://sso.x"), "externalSubject", "Isi identity issuer dan external subject SSO berpasangan, atau kosongkan keduanya."},
			"short name": {with("name", "A"), "name", "Nama lengkap minimal 2 karakter."},
			"null char":  {with("name", "a\x00b"), "name", "Nama lengkap berisi karakter yang tidak diizinkan."},
		} {
			if x := a.do(t, "POST", "/users", c.body); x.Status != 422 || x.problem(c.field) != c.msg {
				t.Errorf("%s: %d %q (%s)", name, x.Status, x.problem(c.field), trunc(x.Raw))
			}
		}
	})

	t.Run("AU04 edit: stale version refused, password set by the administrator must be changed, unknown id 404", func(t *testing.T) {
		u, id := newUser(t, a, "viewer")
		g := must(t, a.do(t, "GET", "/users/"+id, nil), 200)
		b := userBody(g)
		b["name"] = "Nama Baru"
		must(t, a.do(t, "PUT", "/users/"+id, b), 200)
		b["name"] = "Basi"
		if x := a.do(t, "PUT", "/users/"+id, b); x.Status != 409 || x.str("code") != "STALE" {
			t.Errorf("stale: %d", x.Status)
		}
		g = must(t, a.do(t, "GET", "/users/"+id, nil), 200)
		b = userBody(g)
		b["password"] = "Admin2026x"
		must(t, a.do(t, "PUT", "/users/"+id, b), 200)
		if x := newClient().login(t, u, "Admin2026x"); x.Obj["mustChangePassword"] != "reset" {
			t.Errorf("reset: %s", x.Raw)
		}
		for _, bad := range []string{"nope", "00000000-0000-7000-8000-00000000ffff", "%00"} {
			if x := a.do(t, "GET", "/users/"+bad, nil); x.Status != 404 {
				t.Errorf("%s: %d", bad, x.Status)
			}
		}
	})

	t.Run("AU05 an administrator cannot deactivate or delete themselves; the last active Admin stays", func(t *testing.T) {
		me := must(t, a.do(t, "GET", "/auth/me", nil), 200).str("id")
		g := must(t, a.do(t, "GET", "/users/"+me, nil), 200)
		b := userBody(g)
		b["active"], b["levelCode"], b["groupCode"] = false, "GROUP", "GAN"
		if x := a.do(t, "PUT", "/users/"+me, b); x.Status != 422 || x.problem("active") == "" || x.problem("role") == "" {
			t.Errorf("self deactivate: %d %s", x.Status, x.Raw)
		}
		if x := a.do(t, "DELETE", "/users/"+me, nil); x.Status != 409 {
			t.Errorf("self delete: %d", x.Status)
		}
	})

	t.Run("AU06 delete is soft: the account leaves the list and cannot sign in; its username is free again", func(t *testing.T) {
		u, id := newUser(t, a, "viewer")
		must(t, a.do(t, "DELETE", "/users/"+id, nil), 204)
		if x := a.do(t, "GET", "/users/"+id, nil); x.Status != 404 {
			t.Errorf("get: %d", x.Status)
		}
		if x := newClient().login(t, u, "Tetap2026x"); x.Status != 401 {
			t.Errorf("login: %d", x.Status)
		}
		var deleted bool
		_ = pool.QueryRow(context.Background(), `SELECT is_deleted FROM auth.membership WHERE id = $1`, id).Scan(&deleted)
		if !deleted {
			t.Error("row not kept")
		}
		must(t, a.do(t, "POST", "/users", map[string]any{"username": u, "name": "Lagi", "role": "viewer", "levelCode": "COMPANY", "companyCode": "C11", "password": "Awal2026x"}), 201)
	})
}

/* ---------------- Roles and access ---------------- */

func TestRolesAndAccess(t *testing.T) {
	a := admin(t)

	t.Run("AR01 a new role: generated code; its grants become the access of its users", func(t *testing.T) {
		r := must(t, a.do(t, "POST", "/roles", map[string]any{"code": "typed", "name": "Mandor Panen", "description": "Panen afdeling"}), 201)
		code := r.str("code")
		if !strings.HasPrefix(code, "MRL") || r.Obj["system"] != false {
			t.Errorf("role %s", r.Raw)
		}
		must(t, a.do(t, "PUT", "/roles/"+code+"/permissions", map[string]any{"grants": map[string]any{"pm.orgUnit": []string{"read", "export"}, "ess.leave": []string{"read", "create"}}}), 200)
		u, _ := newUser(t, a, code)
		c := newClient()
		acc := must(t, c.login(t, u, "Tetap2026x"), 200).Obj["access"].(map[string]any)
		g := acc["grants"].(map[string]any)
		if fmt.Sprint(g["pm.orgUnit"]) != "[read export]" || acc["full"] != false || !slices.Contains(toStrings(acc["modules"]), "portal-master") {
			t.Errorf("access %v", acc)
		}
		if x := c.do(t, "GET", "/users", nil); x.Status != 403 {
			t.Errorf("no auth.users: %d", x.Status)
		}
		// a change of the role's grants takes effect at once on the Authentication service
		must(t, a.do(t, "PUT", "/roles/"+code+"/permissions", map[string]any{"grants": map[string]any{"auth.users": []string{"read"}}}), 200)
		want(t, c.do(t, "GET", "/users", nil), 200)
		if x := a.do(t, "DELETE", "/roles/"+code, nil); x.Status != 409 || !strings.Contains(x.str("message"), "1 pengguna") {
			t.Errorf("delete in use: %d %s", x.Status, x.Raw)
		}
	})

	t.Run("AR02 grant problems; Admin is locked; built-in roles stay", func(t *testing.T) {
		for name, g := range map[string]map[string]any{
			"unknown menu":   {"x.y": []string{"read"}},
			"unknown action": {"pm.orgUnit": []string{"read", "fly"}},
			"no read":        {"pm.orgUnit": []string{"export"}},
		} {
			if x := a.do(t, "PUT", "/roles/viewer/permissions", map[string]any{"grants": g}); x.Status != 422 {
				t.Errorf("%s: %d", name, x.Status)
			}
		}
		if x := a.do(t, "PUT", "/roles/admin/permissions", map[string]any{"grants": map[string]any{}}); x.Status != 409 {
			t.Errorf("admin locked: %d", x.Status)
		}
		if x := a.do(t, "DELETE", "/roles/viewer", nil); x.Status != 409 {
			t.Errorf("built in: %d", x.Status)
		}
		r := must(t, a.do(t, "PUT", "/roles/viewer", map[string]any{"name": "Viewer", "active": false}), 200)
		if r.Obj["active"] != true {
			t.Errorf("a built-in role stays active: %s", r.Raw)
		}
	})

	t.Run("AR03 unit access limits the modules of users at the unit, not above it", func(t *testing.T) {
		r := must(t, a.do(t, "POST", "/roles", map[string]any{"name": "Dua Modul"}), 201).str("code")
		must(t, a.do(t, "PUT", "/roles/"+r+"/permissions", map[string]any{"grants": map[string]any{"pm.orgUnit": []string{"read"}, "ess.leave": []string{"read"}}}), 200)
		must(t, a.do(t, "PUT", "/access/units/C11-E1", map[string]any{"all": false, "modules": []string{"employee-self-service"}}), 200)
		defer a.do(t, "PUT", "/access/units/C11-E1", map[string]any{"all": true})
		u, _ := newUser(t, a, r)
		acc := must(t, newClient().login(t, u, "Tetap2026x"), 200).Obj["access"].(map[string]any)
		if fmt.Sprint(acc["modules"]) != "[employee-self-service]" || acc["unit"] != "C11-E1" || acc["grants"].(map[string]any)["pm.orgUnit"] != nil {
			t.Errorf("limited: %v", acc)
		}
		if x := a.do(t, "PUT", "/access/units/C11", map[string]any{"all": true}); x.Status != 404 {
			t.Errorf("a company is not a unit: %d", x.Status)
		}
		if x := a.do(t, "PUT", "/access/units/C11-E1", map[string]any{"all": false, "modules": []string{}}); x.Status != 422 {
			t.Errorf("no module: %d", x.Status)
		}
	})

	t.Run("AR04 the organisation copy reads Portal Master with a service token", func(t *testing.T) {
		o := must(t, a.do(t, "GET", "/org/options", nil), 200)
		if len(o.Obj["units"].([]any)) != 2 || o.Obj["levelNames"].(map[string]any)["org1"] != "Rayon" || len(o.Obj["orgLevel3s"].([]any)) != 1 {
			t.Errorf("options %s", o.Raw)
		}
		must(t, a.do(t, "POST", "/org/sync", nil), 200)
		pmCalls.Lock()
		last := pmCalls.auth[len(pmCalls.auth)-1]
		pmCalls.Unlock()
		if !strings.HasPrefix(last, "Bearer ") {
			t.Errorf("Portal Master called without a token: %q", last)
		}
	})
}

func toStrings(x any) []string {
	var out []string
	for _, v := range x.([]any) {
		out = append(out, v.(string))
	}
	return out
}

/* ---------------- Policy and audit ---------------- */

func TestPolicyAndAudit(t *testing.T) {
	a := admin(t)

	t.Run("AA01 the policy decides the password rules and the lock", func(t *testing.T) {
		p := must(t, a.do(t, "GET", "/auth/policy", nil), 200).Obj
		p["requireSymbol"], p["maxFailedAttempts"] = true, 2
		must(t, a.do(t, "PUT", "/auth/policy", p), 200)
		defer func() {
			p["requireSymbol"], p["maxFailedAttempts"] = false, 5
			a.do(t, "PUT", "/auth/policy", p)
		}()
		if x := a.do(t, "POST", "/users", map[string]any{"username": "simbol.uji", "name": "Simbol", "role": "viewer", "levelCode": "COMPANY", "companyCode": "C11", "password": "Awal2026x"}); x.Status != 422 || !strings.Contains(x.problem("password"), "simbol") {
			t.Errorf("symbol: %d %s", x.Status, x.Raw)
		}
		u, _ := newUserPw(t, a, "Awal2026x!")
		newClient().login(t, u, "salah")
		if x := newClient().login(t, u, "salah"); x.Status != 423 {
			t.Errorf("locked after 2: %d", x.Status)
		}
		q := map[string]any{}
		for k, v := range p {
			q[k] = v
		}
		q["allowLocalLogin"], q["ssoEnabled"] = false, false
		if x := a.do(t, "PUT", "/auth/policy", q); x.Status != 422 {
			t.Errorf("nobody could sign in: %d", x.Status)
		}
	})

	t.Run("AA02 the audit log records sign-ins, failures, locks and changes, by type and term", func(t *testing.T) {
		r := must(t, a.do(t, "GET", "/auth/audit?type=login_failed&size=5", nil), 200)
		items := r.Obj["items"].([]any)
		if len(items) == 0 || r.Obj["total"].(float64) < float64(len(items)) || items[0].(map[string]any)["type"] != "login_failed" {
			t.Errorf("audit %s", trunc(r.Raw))
		}
		for _, typ := range []string{"login", "locked", "user_created", "access_changed", "policy_changed", "session_revoked"} {
			if x := must(t, a.do(t, "GET", "/auth/audit?type="+typ+"&size=1", nil), 200); x.Obj["total"].(float64) == 0 {
				t.Errorf("no %s event", typ)
			}
		}
		if x := must(t, a.do(t, "GET", "/auth/audit?q=%25_&size=1", nil), 200); x.Status != 200 {
			t.Errorf("wildcards in the term are text")
		}
	})
}

func newUserPw(t testing.TB, a *client, pw string) (string, string) {
	t.Helper()
	userSeq.Lock()
	userSeq.n++
	username := fmt.Sprintf("user%03d", userSeq.n)
	userSeq.Unlock()
	r := must(t, a.do(t, "POST", "/users", map[string]any{"username": username, "name": "Pengguna Uji", "role": "viewer", "levelCode": "COMPANY", "companyCode": "C11", "password": pw}), 201)
	return username, r.str("id")
}

/* ---------------- Stress ---------------- */

func TestStress(t *testing.T) {
	a := admin(t)

	t.Run("AS01 40 wrong passwords at once: locked exactly, never a 500", func(t *testing.T) {
		u, _ := newUser(t, a, "viewer")
		var mu sync.Mutex
		st := map[int]int{}
		parallel(40, 40, func(int) {
			r := newClient().login(t, u, "salah")
			mu.Lock()
			st[r.Status]++
			mu.Unlock()
		})
		if st[500] > 0 || st[401] != 4 || st[423] != 36 {
			t.Errorf("statuses %v (want 4 × 401 then 423)", st)
		}
	})

	t.Run("AS02 100 sign-ins at once of 10 accounts: all in, sessions counted", func(t *testing.T) {
		var users []string
		for range 10 {
			u, _ := newUser(t, a, "viewer")
			users = append(users, u)
		}
		var mu sync.Mutex
		st := map[int]int{}
		start := time.Now()
		parallel(100, 25, func(i int) {
			r := newClient().login(t, users[i%10], "Tetap2026x")
			mu.Lock()
			st[r.Status]++
			mu.Unlock()
		})
		t.Logf("100 sign-ins (argon2id) in %v", time.Since(start))
		if st[200] != 100 {
			t.Errorf("statuses %v", st)
		}
	})

	t.Run("AS03 one cookie refreshed by 10 tabs at once: one wins, the others retry, the session lives", func(t *testing.T) {
		u, _ := newUser(t, a, "viewer")
		c := newClient()
		must(t, c.login(t, u, "Tetap2026x"), 200)
		var mu sync.Mutex
		st := map[int]int{}
		parallel(10, 10, func(int) {
			r := c.do(t, "POST", "/auth/refresh", nil)
			mu.Lock()
			st[r.Status]++
			mu.Unlock()
		})
		if st[500] > 0 || st[401] > 0 || st[200] < 1 {
			t.Errorf("statuses %v", st)
		}
		if x := c.do(t, "POST", "/auth/refresh", nil); x.Status != 200 {
			t.Errorf("the session lives on: %d %s", x.Status, x.Raw)
		}
	})

	t.Run("AS04 one username raced 15 times: one account", func(t *testing.T) {
		var mu sync.Mutex
		st := map[int]int{}
		parallel(15, 15, func(int) {
			r := a.do(t, "POST", "/users", map[string]any{"username": "kembar", "name": "Kembar", "role": "viewer", "levelCode": "COMPANY", "companyCode": "C11", "password": "Awal2026x"})
			mu.Lock()
			st[r.Status]++
			mu.Unlock()
		})
		if st[201] != 1 || st[500] > 0 {
			t.Errorf("statuses %v", st)
		}
	})
}

var _ = http.StatusOK

func TestStaleTokenOnPublicEndpoints(t *testing.T) {
	a := admin(t)
	u, _ := newUser(t, a, "viewer")
	c := newClient()
	must(t, c.login(t, u, "Tetap2026x"), 200)
	advance(16 * time.Minute)
	t.Run("AN07 an expired token sent with refresh, login options and logout does not block them", func(t *testing.T) {
		if x := c.send(t, "POST", "/auth/refresh", nil); x.Status != 200 {
			t.Errorf("refresh: %d %s", x.Status, x.Raw)
		}
		c.token = "x.y.z"
		want(t, c.send(t, "GET", "/auth/login-options", nil), 200)
		want(t, c.send(t, "POST", "/auth/logout", nil), 204)
		if x := c.send(t, "POST", "/auth/refresh", nil); x.Status != 401 {
			t.Errorf("logout with a stale token still ended the session through the cookie: %d", x.Status)
		}
	})
}

// sessionOf is the id of the client's current session.
func sessionOf(t *testing.T, c *client) string {
	t.Helper()
	for _, x := range must(t, c.do(t, "GET", "/auth/me/sessions", nil), 200).List {
		if x["current"] == true {
			return x["id"].(string)
		}
	}
	t.Fatal("no current session")
	return ""
}

// tokenClaims reads the claims of an access token (no signature check: the service made it).
func tokenClaims(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q", tok)
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c map[string]any
	_ = json.Unmarshal(b, &c)
	return c
}
