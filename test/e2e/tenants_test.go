//go:build e2e

// Multi-tenant identity: one person (identity), a membership per company (tenant), sign-in with username or email,
// the choice and the switch of company, platform administration, and isolation between companies.
package e2e

import (
	"strings"
	"sync/atomic"
	"testing"

	"alir.local/auth-service/internal/auth"
)

// loginIn signs in naming a company ("" = none).
func (c *client) loginIn(t testing.TB, ident, pw, tenant string) resp {
	t.Helper()
	body := map[string]any{"username": ident, "password": pw}
	if tenant != "" {
		body["tenant"] = tenant
	}
	r := c.do(t, "POST", "/auth/login", body)
	if r.Status == 200 {
		c.token = r.str("token")
	}
	return r
}

func tenantOf(r resp) string {
	t, _ := r.Obj["tenant"].(map[string]any)
	s, _ := t["code"].(string)
	return s
}

func codes(x any) []string {
	var out []string
	for _, t := range x.([]any) {
		out = append(out, t.(map[string]any)["code"].(string))
	}
	return out
}

// betaAdmin makes company "beta" once (platform administrator) and signs its first Admin in.
var betaOnce struct {
	done bool
	id   string
}

func betaAdmin(t *testing.T) *client {
	t.Helper()
	if !betaOnce.done {
		r := must(t, admin(t).do(t, "POST", "/platform/tenants", map[string]any{"code": "beta", "name": "PT Beta Sejahtera",
			"admin": map[string]any{"username": "admin.beta", "name": "Admin Beta", "email": "admin@beta.test", "password": "BetaAwal2026"}}), 201)
		betaOnce.done, betaOnce.id = true, r.str("id")
		c := newClient()
		must(t, c.loginIn(t, "admin.beta", "BetaAwal2026", "beta"), 200)
		must(t, c.do(t, "POST", "/auth/password/change", map[string]any{"next": "BetaTetap2026"}), 204)
	}
	c := newClient()
	must(t, c.loginIn(t, "admin@beta.test", "BetaTetap2026", ""), 200)
	return c
}

func TestTenantsPositive(t *testing.T) {
	a := admin(t)

	t.Run("TP01 the token names the person, the membership and the company; the answer lists the companies", func(t *testing.T) {
		c := newClient()
		r := must(t, c.login(t, "admin", adminPw), 200)
		claims := tokenClaims(t, c.token)
		user := r.Obj["user"].(map[string]any)
		if claims["tid"] != auth.DefaultTenantID || claims["mid"] != user["id"] || claims["sub"] != user["identityId"] {
			t.Errorf("claims %v user %v", claims, user)
		}
		if tenantOf(r) != "gan" || len(r.Obj["tenants"].([]any)) < 1 || r.Obj["platformAdmin"] != true {
			t.Errorf("tenant %s tenants %v platform %v", tenantOf(r), r.Obj["tenants"], r.Obj["platformAdmin"])
		}
	})

	t.Run("TP02 the platform administrator adds a company: built-in roles, policy and its first Admin", func(t *testing.T) {
		b := betaAdmin(t)
		roles := must(t, b.do(t, "GET", "/roles", nil), 200)
		if len(roles.List) != 4 {
			t.Errorf("a new company has the 4 built-in roles: %d", len(roles.List))
		}
		if p := must(t, b.do(t, "GET", "/auth/policy", nil), 200); p.Obj["passwordMinLength"].(float64) != 8 {
			t.Errorf("default policy: %s", p.Raw)
		}
		l := must(t, a.do(t, "GET", "/platform/tenants", nil), 200)
		if got := strings.Join(func() []string {
			var c []string
			for _, x := range l.List {
				c = append(c, x["code"].(string))
			}
			return c
		}(), ","); !strings.Contains(got, "beta") || !strings.Contains(got, "gan") {
			t.Errorf("tenants: %s", got)
		}
		if lk := must(t, newClient().do(t, "GET", "/auth/tenants/lookup?tenant=BETA", nil), 200); lk.str("name") != "PT Beta Sejahtera" {
			t.Errorf("lookup: %s", lk.Raw)
		}
	})

	t.Run("TP03 the same username in two companies: the company decides, email always works", func(t *testing.T) {
		b := betaAdmin(t)
		for _, c := range []*client{a, b} {
			must(t, c.do(t, "POST", "/users", map[string]any{"username": "dua.nama", "name": "Orang Kembar", "role": "viewer", "levelCode": "COMPANY",
				"companyCode": "C11", "password": "Kembar2026"}), 201)
		}
		if r := newClient().loginIn(t, "dua.nama", "Kembar2026", ""); r.Status != 409 || r.str("code") != "TENANT_REQUIRED" {
			t.Errorf("ambiguous username: %d %s", r.Status, r.Raw)
		}
		if r := newClient().loginIn(t, "dua.nama", "Kembar2026", "beta"); r.Status != 200 || tenantOf(r) != "beta" {
			t.Errorf("username in beta: %d %s", r.Status, r.Raw)
		}
		if r := newClient().loginIn(t, "DUA.NAMA", "Kembar2026", "gan"); r.Status != 200 || tenantOf(r) != "gan" {
			t.Errorf("username in gan: %d %s", r.Status, r.Raw)
		}
	})

	t.Run("TP04 one person in two companies: one identity, a choice at sign-in, a switch without signing in again", func(t *testing.T) {
		b := betaAdmin(t)
		ga := must(t, a.do(t, "POST", "/users", map[string]any{"username": "rina", "employeeCode": "E008", "role": "viewer", "levelCode": "COMPANY",
			"companyCode": "C11", "password": "Rina2026x"}), 201)
		c := newClient()
		must(t, c.login(t, "rina", "Rina2026x"), 200)
		must(t, c.do(t, "POST", "/auth/password/change", map[string]any{"next": "RinaTetap26"}), 204)
		// Beta adds the same person (the employee's email names her identity): the typed password is not used.
		bm := must(t, b.do(t, "POST", "/users", map[string]any{"username": "rina.g", "employeeCode": "E008", "role": "analyst", "levelCode": "COMPANY",
			"companyCode": "C11", "password": "TidakDipakai1"}), 201)
		if bm.Obj["identityId"] != ga.Obj["identityId"] || bm.Obj["sharedIdentity"] != true || bm.Obj["mustChangePassword"] != false {
			t.Errorf("same identity: %v vs %v, shared %v", bm.Obj["identityId"], ga.Obj["identityId"], bm.Obj["sharedIdentity"])
		}
		if r := newClient().loginIn(t, "rina", "TidakDipakai1", "gan"); r.Status != 401 {
			t.Errorf("beta's typed password must not work: %d", r.Status)
		}
		r := newClient().loginIn(t, "rina.ganda@contoh.co.id", "RinaTetap26", "")
		if r.Status != 409 || r.str("code") != "TENANT_CHOICE" {
			t.Fatalf("choice: %d %s", r.Status, r.Raw)
		}
		if got := codes(r.Obj["details"].(map[string]any)["tenants"]); strings.Join(got, ",") != "gan,beta" && strings.Join(got, ",") != "beta,gan" {
			t.Errorf("choices %v", got)
		}
		s := newClient()
		r = must(t, s.loginIn(t, "rina.ganda@contoh.co.id", "RinaTetap26", "beta"), 200)
		if tenantOf(r) != "beta" || r.Obj["user"].(map[string]any)["role"] != "analyst" || len(r.Obj["tenants"].([]any)) != 2 {
			t.Errorf("in beta: %s", trunc(r.Raw))
		}
		old := s.token
		sw := must(t, s.do(t, "POST", "/auth/switch-tenant", map[string]any{"tenant": "gan"}), 200)
		s.token = sw.str("token")
		if tenantOf(sw) != "gan" || sw.Obj["user"].(map[string]any)["role"] != "viewer" || tokenClaims(t, s.token)["tid"] != auth.DefaultTenantID {
			t.Errorf("switched: %s", trunc(sw.Raw))
		}
		if x := (&client{http: s.http, token: old}).send(t, "GET", "/auth/me", nil); x.Status != 401 {
			t.Errorf("the token of the company left must stop: %d", x.Status)
		}
		if me := must(t, s.do(t, "GET", "/auth/me", nil), 200); tenantOf(me) != "gan" || me.str("username") != "rina" {
			t.Errorf("me after switch: %s", me.Raw)
		}
		if x := must(t, s.send(t, "POST", "/auth/refresh", nil), 200); tenantOf(x) != "gan" {
			t.Errorf("refresh keeps the company switched to: %s", x.Raw)
		}
	})

	t.Run("TP05 one password for every company: changed in one, it works in the other", func(t *testing.T) {
		c := newClient()
		must(t, c.loginIn(t, "rina", "RinaTetap26", "gan"), 200)
		must(t, c.do(t, "POST", "/auth/password/change", map[string]any{"current": "RinaTetap26", "next": "RinaBaru2026"}), 204)
		if r := newClient().loginIn(t, "rina.g", "RinaBaru2026", "beta"); r.Status != 200 {
			t.Errorf("new password in beta: %d %s", r.Status, r.Raw)
		}
	})
}

func TestTenantsNegative(t *testing.T) {
	a := admin(t)
	b := betaAdmin(t)
	ganUser := must(t, a.do(t, "POST", "/users", map[string]any{"username": "rahasia.gan", "name": "Rahasia Gan", "role": "viewer", "levelCode": "COMPANY",
		"companyCode": "C11", "password": "Rahasia2026"}), 201).str("id")
	ganRole := must(t, a.do(t, "POST", "/roles", map[string]any{"name": "Peran Gan"}), 201).str("code")

	t.Run("TN01 an administrator sees and changes only their own company", func(t *testing.T) {
		for _, u := range must(t, b.do(t, "GET", "/users", nil), 200).List {
			if u["username"] == "rahasia.gan" || u["username"] == "admin" {
				t.Errorf("beta lists a gan member: %v", u["username"])
			}
		}
		for _, x := range []struct{ m, p string }{{"GET", "/users/" + ganUser}, {"PUT", "/users/" + ganUser}, {"DELETE", "/users/" + ganUser},
			{"POST", "/users/" + ganUser + "/unlock"}, {"POST", "/users/" + ganUser + "/reset-link"}, {"POST", "/users/" + ganUser + "/revoke-sessions"},
			{"GET", "/roles/" + ganRole + "/permissions"}, {"PUT", "/roles/" + ganRole}, {"DELETE", "/roles/" + ganRole}} {
			if r := b.do(t, x.m, x.p, map[string]any{"name": "Dibajak", "username": "dibajak", "role": "viewer", "levelCode": "COMPANY", "companyCode": "C11"}); r.Status != 404 {
				t.Errorf("%s %s from beta: %d %s", x.m, x.p, r.Status, trunc(r.Raw))
			}
		}
		if r := must(t, a.do(t, "GET", "/users/"+ganUser, nil), 200); r.str("name") != "Rahasia Gan" {
			t.Errorf("gan member changed: %s", r.Raw)
		}
		for _, s := range must(t, b.do(t, "GET", "/auth/sessions", nil), 200).List {
			if s["tenant"].(map[string]any)["code"] != "beta" {
				t.Errorf("beta sees a session of %v", s["tenant"])
			}
		}
		au := must(t, b.do(t, "GET", "/auth/audit?q=rahasia&size=50", nil), 200)
		if au.Obj["total"].(float64) != 0 {
			t.Errorf("beta reads gan's audit: %s", trunc(au.Raw))
		}
	})

	t.Run("TN02 only the platform administrator manages companies", func(t *testing.T) {
		for _, x := range []struct{ m, p string }{{"GET", "/platform/tenants"}, {"POST", "/platform/tenants"}, {"PUT", "/platform/tenants/" + betaOnce.id}} {
			if r := b.do(t, x.m, x.p, map[string]any{"code": "x", "name": "x"}); r.Status != 403 {
				t.Errorf("%s %s by a company admin: %d", x.m, x.p, r.Status)
			}
		}
		if r := newClient().do(t, "GET", "/platform/tenants", nil); r.Status != 401 {
			t.Errorf("anonymous: %d", r.Status)
		}
	})

	t.Run("TN03 a new company: code rules, no duplicate, the Admin's email and password", func(t *testing.T) {
		for name, x := range map[string]map[string]any{
			"reserved":  {"code": "admin", "name": "X", "admin": map[string]any{"username": "a", "name": "A A", "email": "a@x.test", "password": "Awal2026x"}},
			"bad code":  {"code": "Beta Dua", "name": "X", "admin": map[string]any{"username": "a", "name": "A A", "email": "a@x.test", "password": "Awal2026x"}},
			"duplicate": {"code": "BETA", "name": "X", "admin": map[string]any{"username": "a", "name": "A A", "email": "a@x.test", "password": "Awal2026x"}},
			"no email":  {"code": "gamma", "name": "X", "admin": map[string]any{"username": "a", "name": "A A", "password": "Awal2026x"}},
			"weak pw":   {"code": "gamma", "name": "X", "admin": map[string]any{"username": "a", "name": "A A", "email": "baru@x.test", "password": "pendek"}},
		} {
			if r := a.do(t, "POST", "/platform/tenants", x); r.Status != 422 {
				t.Errorf("%s: %d %s", name, r.Status, trunc(r.Raw))
			}
		}
	})

	t.Run("TN04 a person shared with another company: their password is not this company's to set", func(t *testing.T) {
		var rinaInBeta string
		for _, u := range must(t, b.do(t, "GET", "/users", nil), 200).List {
			if u["username"] == "rina.g" {
				rinaInBeta = u["id"].(string)
				body := map[string]any{}
				for k, v := range u {
					body[k] = v
				}
				body["role"], body["password"] = "analyst", "Dicoba2026x"
				r := b.do(t, "PUT", "/users/"+rinaInBeta, body)
				if r.Status != 422 || !strings.Contains(r.problem("password"), "perusahaan lain") {
					t.Errorf("password of a shared person: %d %s", r.Status, trunc(r.Raw))
				}
			}
		}
		if rinaInBeta == "" {
			t.Skip("TP04 did not run")
		}
	})

	t.Run("TN05 switching to a company one is not a member of, or does not exist", func(t *testing.T) {
		c := newClient()
		must(t, c.login(t, "rahasia.gan", "Rahasia2026"), 200)
		must(t, c.do(t, "POST", "/auth/password/change", map[string]any{"next": "Rahasia2027"}), 204)
		if r := c.do(t, "POST", "/auth/switch-tenant", map[string]any{"tenant": "beta"}); r.Status != 403 || r.str("code") != "NOT_MEMBER" {
			t.Errorf("not a member: %d %s", r.Status, r.Raw)
		}
		if r := c.do(t, "POST", "/auth/switch-tenant", map[string]any{"tenant": "tidak-ada"}); r.Status != 422 {
			t.Errorf("unknown: %d", r.Status)
		}
		if r := newClient().loginIn(t, "rahasia.gan", "Rahasia2027", "beta"); r.Status != 401 {
			t.Errorf("username of another company: %d %s", r.Status, r.Raw)
		}
		if r := newClient().loginIn(t, "rahasia.gan", "Rahasia2027", "<script>"); r.Status != 422 {
			t.Errorf("junk tenant: %d", r.Status)
		}
	})

	t.Run("TN06 failed sign-ins are seen by every company of the person", func(t *testing.T) {
		newClient().loginIn(t, "rina.ganda@contoh.co.id", "salah-sekali", "")
		for name, c := range map[string]*client{"gan": a, "beta": b} {
			au := must(t, c.do(t, "GET", "/auth/audit?type=login_failed&q=rina.ganda&size=5", nil), 200)
			if au.Obj["total"].(float64) == 0 {
				t.Errorf("%s does not see the failure", name)
			}
		}
		// Unlock for the next tests: the counter is the person's.
		newClient().loginIn(t, "rina.ganda@contoh.co.id", "RinaBaru2026", "gan")
	})

	t.Run("TN07 a deactivated company signs no one in and its sessions end", func(t *testing.T) {
		l := must(t, a.do(t, "GET", "/platform/tenants", nil), 200)
		var version float64
		for _, x := range l.List {
			if x["code"] == "beta" {
				version = x["version"].(float64)
			}
		}
		must(t, a.do(t, "PUT", "/platform/tenants/"+betaOnce.id, map[string]any{"name": "PT Beta Sejahtera", "active": false, "version": version}), 200)
		if r := b.do(t, "GET", "/users", nil); r.Status != 401 {
			t.Errorf("a session of the deactivated company: %d", r.Status)
		}
		if r := newClient().loginIn(t, "admin.beta", "BetaTetap2026", "beta"); r.Status != 422 {
			t.Errorf("sign-in to it: %d %s", r.Status, r.Raw)
		}
		// The shared person now goes straight into the company left.
		if r := newClient().loginIn(t, "rina.ganda@contoh.co.id", "RinaBaru2026", ""); r.Status != 200 || tenantOf(r) != "gan" {
			t.Errorf("shared person: %d %s", r.Status, trunc(r.Raw))
		}
		if r := a.do(t, "PUT", "/platform/tenants/"+auth.DefaultTenantID, map[string]any{"name": "Grup Agro Nusantara", "active": false}); r.Status != 422 {
			t.Errorf("the platform admin's own company: %d", r.Status)
		}
		must(t, a.do(t, "PUT", "/platform/tenants/"+betaOnce.id, map[string]any{"name": "PT Beta Sejahtera", "active": true, "version": version + 1}), 200)
	})
}

func TestTenantsStress(t *testing.T) {
	a := admin(t)
	b := betaAdmin(t)

	t.Run("TS01 200 interleaved requests of two companies' administrators: no answer carries the other company", func(t *testing.T) {
		var leaks, fails atomic.Int64
		parallel(200, 20, func(i int) {
			c, mine, other := a, "rahasia.gan", "admin.beta"
			if i%2 == 1 {
				c, mine, other = b, "admin.beta", "rahasia.gan"
			}
			r := c.send(t, "GET", "/users", nil)
			if r.Status != 200 {
				fails.Add(1)
				return
			}
			seen := false
			for _, u := range r.List {
				seen = seen || u["username"] == mine
				if u["username"] == other {
					leaks.Add(1)
				}
			}
			if !seen && mine != "rahasia.gan" {
				leaks.Add(1)
			}
		})
		if leaks.Load() != 0 || fails.Load() != 0 {
			t.Errorf("leaks %d, failures %d", leaks.Load(), fails.Load())
		}
	})

	t.Run("TS02 40 sign-ins and switches of the shared person at once: each lands in the company asked for", func(t *testing.T) {
		var wrong atomic.Int64
		parallel(40, 10, func(i int) {
			want := []string{"gan", "beta"}[i%2]
			c := newClient()
			r := c.loginIn(t, "rina.ganda@contoh.co.id", "RinaBaru2026", want)
			if r.Status != 200 || tenantOf(r) != want {
				wrong.Add(1)
				return
			}
			back := []string{"beta", "gan"}[i%2]
			sw := c.do(t, "POST", "/auth/switch-tenant", map[string]any{"tenant": back})
			if sw.Status != 200 || tenantOf(sw) != back || tokenClaims(t, sw.str("token"))["tid"] == tokenClaims(t, c.token)["tid"] {
				wrong.Add(1)
			}
		})
		if wrong.Load() != 0 {
			t.Errorf("%d sign-ins or switches landed wrong", wrong.Load())
		}
	})
}
