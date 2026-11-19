package auth

import (
	"context"
	"net/http"
	"time"

	"alir.local/auth-service/internal/catalog"
	"alir.local/auth-service/internal/platform/httpx"
	"alir.local/auth-service/internal/platform/record"
)

// RefreshCookie carries the refresh token: httpOnly (no script reads it), SameSite=Strict (never sent by another
// site), Secure outside local development.
const RefreshCookie = "alir_rt"

type requestKey struct{}

// requestOf is the request a use case serves (the audit log records its address and id).
func requestOf(ctx context.Context) *http.Request {
	r, _ := ctx.Value(requestKey{}).(*http.Request)
	return r
}

func writeErr(w http.ResponseWriter, r *http.Request, err error) { httpx.WriteError(w, r, err) }

func (s *Service) setCookie(w http.ResponseWriter, raw string, expires time.Time) {
	c := &http.Cookie{Name: RefreshCookie, Value: raw, Path: s.Cfg.CookiePath, HttpOnly: true, Secure: s.Cfg.CookieSecure, SameSite: http.SameSiteStrictMode}
	if raw == "" {
		c.MaxAge = -1
	} else {
		c.Expires = expires
	}
	http.SetCookie(w, c)
}

// tenantKey is the company a public request names: ?tenant=, else the X-Tenant header (set from the company's
// address by the page or the proxy).
func tenantKey(r *http.Request) string {
	if t := r.URL.Query().Get("tenant"); t != "" {
		return t
	}
	return r.Header.Get("X-Tenant")
}

func cookie(r *http.Request) string {
	if c, err := r.Cookie(RefreshCookie); err == nil {
		return c.Value
	}
	return ""
}

// Routes registers every endpoint; Authenticate must wrap the mux.
func (s *Service) Routes(mux *http.ServeMux) {
	h := func(pattern string, fn func(w http.ResponseWriter, r *http.Request) (any, int, error)) {
		mux.Handle(pattern, httpx.Handler(func(w http.ResponseWriter, r *http.Request) error {
			r = r.WithContext(context.WithValue(r.Context(), requestKey{}, r))
			out, status, err := fn(w, r)
			if err != nil {
				return err
			}
			if status == http.StatusNoContent {
				w.WriteHeader(status)
				return nil
			}
			return httpx.JSON(w, status, out)
		}))
	}
	body := func(r *http.Request) (record.Values, error) {
		b, err := httpx.DecodeObject(r)
		return record.Values(b), err
	}
	ok := func(v any, err error) (any, int, error) { return v, http.StatusOK, err }
	none := func(err error) (any, int, error) { return nil, http.StatusNoContent, err }

	mux.Handle("GET /.well-known/jwks.json", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = httpx.JSON(w, http.StatusOK, s.Keys.JWKS())
	}))

	/* Sign-in */
	h("GET /auth/login-options", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		return ok(s.LoginOptions(r.Context(), tenantKey(r)))
	})
	h("GET /auth/tenants/lookup", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		return ok(s.LookupTenant(r.Context(), tenantKey(r)))
	})
	h("POST /auth/switch-tenant", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		res, err := s.SwitchTenant(r.Context(), r, b)
		if err != nil {
			return nil, 0, err
		}
		s.setCookie(w, res.refresh, res.refreshExpires)
		return res, http.StatusOK, nil
	})
	h("POST /auth/login", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		res, err := s.Login(r.Context(), r, b)
		if err != nil {
			return nil, 0, err
		}
		s.setCookie(w, res.refresh, res.refreshExpires)
		s.setSSOCookie(w, res.sso)
		return res, http.StatusOK, nil
	})
	h("POST /auth/refresh", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		res, err := s.Refresh(r.Context(), r, cookie(r))
		if err != nil {
			if statusOf(err) == http.StatusUnauthorized {
				s.setCookie(w, "", time.Time{}) // the session is over: drop its cookie
			}
			return nil, 0, err
		}
		s.setCookie(w, res.refresh, res.refreshExpires)
		return res, http.StatusOK, nil
	})
	h("POST /auth/logout", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		err := s.Logout(r.Context(), r, cookie(r))
		s.setCookie(w, "", time.Time{})
		s.setSSOCookie(w, "")
		return none(err)
	})
	h("POST /auth/password/change", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		return none(s.ChangePassword(r.Context(), r, b))
	})
	/* Self sign-up, email verification, email codes */
	h("POST /auth/signup", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		x, err := s.Signup(r.Context(), r, b)
		return x, http.StatusAccepted, err
	})
	h("POST /auth/email/verify", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		return ok(s.VerifyEmail(r.Context(), r, b))
	})
	h("POST /auth/email/resend", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		x, err := s.ResendVerification(r.Context(), r, b)
		return x, http.StatusAccepted, err
	})
	h("POST /auth/otp/request", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		x, err := s.RequestOTP(r.Context(), r, b)
		return x, http.StatusAccepted, err
	})
	h("POST /auth/otp/verify", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		res, err := s.VerifyOTP(r.Context(), r, b)
		if err != nil {
			return nil, 0, err
		}
		s.setCookie(w, res.refresh, res.refreshExpires)
		s.setSSOCookie(w, res.sso)
		return res, http.StatusOK, nil
	})
	h("POST /auth/join", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		t, err := s.Join(r.Context(), r, b)
		return t, http.StatusCreated, err
	})
	/* Sign-in through a company's identity provider */
	mux.HandleFunc("GET /auth/idp/start", s.IdpStart)
	mux.HandleFunc("GET /auth/idp/callback", s.IdpCallback)
	h("POST /auth/idp/discover", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		return ok(s.DiscoverIdp(r.Context(), b))
	})

	/* Multi-factor authentication */
	h("POST /auth/mfa/verify", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		res, err := s.VerifyMFA(r.Context(), r, b)
		if err != nil {
			return nil, 0, err
		}
		s.setCookie(w, res.refresh, res.refreshExpires)
		s.setSSOCookie(w, res.sso)
		return res, http.StatusOK, nil
	})
	h("GET /auth/mfa", func(w http.ResponseWriter, r *http.Request) (any, int, error) { return ok(s.MfaStatus(r.Context())) })
	h("POST /auth/mfa/totp/start", func(w http.ResponseWriter, r *http.Request) (any, int, error) { return ok(s.StartTotp(r.Context())) })
	h("POST /auth/mfa/totp/confirm", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		return ok(s.ConfirmTotp(r.Context(), r, b))
	})
	h("POST /auth/mfa/recovery-codes", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		return ok(s.RegenerateRecoveryCodes(r.Context(), r, b))
	})
	h("POST /auth/mfa/disable", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		return none(s.DisableMfa(r.Context(), r, b))
	})
	h("POST /users/{id}/mfa/reset", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		return ok(s.ResetMfa(r.Context(), r.PathValue("id")))
	})

	/* Identity providers of the company */
	h("GET /auth/identity-providers", func(w http.ResponseWriter, r *http.Request) (any, int, error) { return ok(s.ListIdps(r.Context())) })
	h("POST /auth/identity-providers", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		x, err := s.SaveIdp(r.Context(), "", b)
		return x, http.StatusCreated, err
	})
	h("PUT /auth/identity-providers/{code}", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		return ok(s.SaveIdp(r.Context(), r.PathValue("code"), b))
	})
	h("DELETE /auth/identity-providers/{code}", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		return none(s.DeleteIdp(r.Context(), r.PathValue("code")))
	})

	h("POST /users/{id}/access", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		return ok(s.SetMemberAccess(r.Context(), r.PathValue("id"), b))
	})
	h("POST /auth/password/forgot", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		return ok(s.Forgot(r.Context(), r, b))
	})
	h("POST /auth/password/reset", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		return none(s.Reset(r.Context(), r, b))
	})

	/* Own account */
	h("GET /auth/me", func(w http.ResponseWriter, r *http.Request) (any, int, error) { return ok(s.Me(r.Context())) })
	h("GET /auth/me/access", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		a := ActorFrom(r.Context())
		if a == nil {
			return nil, 0, unauthorized("SIGNED_OUT", "Sesi tidak ditemukan. Silakan masuk kembali.")
		}
		return a.Access, http.StatusOK, nil
	})
	h("GET /auth/me/sessions", func(w http.ResponseWriter, r *http.Request) (any, int, error) { return ok(s.MySessions(r.Context())) })
	h("DELETE /auth/me/sessions/{id}", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		return none(s.RevokeSession(r.Context(), r.PathValue("id"), true))
	})
	h("POST /auth/me/sessions/revoke-others", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		n, err := s.RevokeOtherSessions(r.Context())
		return ok(map[string]int64{"revoked": n}, err)
	})

	/* Accounts */
	h("GET /users", func(w http.ResponseWriter, r *http.Request) (any, int, error) { return ok(s.ListUsers(r.Context())) })
	h("GET /users/employee-options", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		return ok(s.EmployeeOptions(r.Context()))
	})
	h("GET /users/{id}", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		return ok(s.GetUser(r.Context(), r.PathValue("id")))
	})
	h("POST /users", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		u, err := s.SaveUser(r.Context(), "", b)
		return u, http.StatusCreated, err
	})
	h("PUT /users/{id}", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		return ok(s.SaveUser(r.Context(), r.PathValue("id"), b))
	})
	h("DELETE /users/{id}", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		return none(s.DeleteUser(r.Context(), r.PathValue("id")))
	})
	h("POST /users/{id}/unlock", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		return ok(s.Unlock(r.Context(), r.PathValue("id")))
	})
	h("POST /users/{id}/reset-link", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		return ok(s.AdminResetLink(r.Context(), r, r.PathValue("id")))
	})
	h("POST /users/{id}/revoke-sessions", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		n, err := s.RevokeSessions(r.Context(), r.PathValue("id"))
		return ok(map[string]int64{"revoked": n}, err)
	})

	/* Roles and grants */
	h("GET /roles", func(w http.ResponseWriter, r *http.Request) (any, int, error) { return ok(s.ListRoles(r.Context())) })
	h("POST /roles", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		x, err := s.SaveRole(r.Context(), "", b)
		return x, http.StatusCreated, err
	})
	h("PUT /roles/{code}", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		return ok(s.SaveRole(r.Context(), r.PathValue("code"), b))
	})
	h("DELETE /roles/{code}", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		return none(s.DeleteRole(r.Context(), r.PathValue("code")))
	})
	h("GET /roles/{code}/permissions", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		return ok(s.GetPermissions(r.Context(), r.PathValue("code")))
	})
	h("PUT /roles/{code}/permissions", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		return ok(s.SetPermissions(r.Context(), r.PathValue("code"), b))
	})
	h("GET /access/catalog", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		if ActorFrom(r.Context()) == nil {
			return nil, 0, unauthorized("SIGNED_OUT", "Sesi tidak ditemukan. Silakan masuk kembali.")
		}
		return catalog.Modules(), http.StatusOK, nil
	})
	h("GET /access/units", func(w http.ResponseWriter, r *http.Request) (any, int, error) { return ok(s.UnitAccess(r.Context())) })
	h("PUT /access/units/{code}", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		return ok(s.SetUnitAccess(r.Context(), r.PathValue("code"), b))
	})

	/* Sessions, policy, audit */
	h("GET /auth/sessions", func(w http.ResponseWriter, r *http.Request) (any, int, error) { return ok(s.AllSessions(r.Context())) })
	h("DELETE /auth/sessions/{id}", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		return none(s.RevokeSession(r.Context(), r.PathValue("id"), false))
	})
	h("GET /auth/policy", func(w http.ResponseWriter, r *http.Request) (any, int, error) { return ok(s.GetPolicy(r.Context())) })
	h("PUT /auth/policy", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		return ok(s.SetPolicy(r.Context(), b))
	})
	h("GET /auth/audit", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		q := map[string]string{}
		for k := range r.URL.Query() {
			q[k] = r.URL.Query().Get(k)
		}
		return ok(s.Audit(r.Context(), q))
	})

	/* OpenID Connect provider */
	mux.Handle("GET /.well-known/openid-configuration", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = httpx.JSON(w, http.StatusOK, s.Discovery())
	}))
	mux.HandleFunc("GET /oauth2/authorize", s.Authorize)
	mux.HandleFunc("POST /oauth2/authorize", s.Authorize)
	mux.HandleFunc("POST /oauth2/token", s.Token)
	mux.HandleFunc("GET /oauth2/userinfo", s.UserInfo)
	mux.HandleFunc("POST /oauth2/userinfo", s.UserInfo)
	mux.HandleFunc("POST /oauth2/revoke", s.Revoke)
	mux.HandleFunc("GET /oauth2/logout", s.EndSession)
	mux.HandleFunc("POST /oauth2/logout", s.EndSession)
	h("GET /oauth2/authorize/request", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		return ok(s.AuthorizeRequest(r.Context(), r.URL.Query().Get("login_challenge")))
	})
	h("POST /oauth2/authorize/complete", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		ch, _ := b["loginChallenge"].(string)
		return ok(s.CompleteAuthorize(r.Context(), w, ch))
	})

	/* Applications (OIDC clients) */
	h("GET /auth/oidc", func(w http.ResponseWriter, r *http.Request) (any, int, error) { return ok(s.OidcConfig(r.Context())) })
	h("GET /auth/clients", func(w http.ResponseWriter, r *http.Request) (any, int, error) { return ok(s.ListClients(r.Context())) })
	h("POST /auth/clients", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		c, secret, err := s.SaveClient(r.Context(), "", b)
		var sec any
		if secret != "" {
			sec = secret
		}
		return map[string]any{"client": c, "secret": sec}, http.StatusCreated, err
	})
	h("PUT /auth/clients/{id}", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		c, _, err := s.SaveClient(r.Context(), r.PathValue("id"), b)
		return ok(c, err)
	})
	h("POST /auth/clients/{id}/secret", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		c, secret, err := s.RotateSecret(r.Context(), r.PathValue("id"))
		return ok(map[string]any{"client": c, "secret": secret}, err)
	})

	/* Platform: the companies of the installation (platform administrator only) */
	h("GET /platform/tenants", func(w http.ResponseWriter, r *http.Request) (any, int, error) { return ok(s.ListTenants(r.Context())) })
	h("POST /platform/tenants", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		t, err := s.CreateTenant(r.Context(), b)
		return t, http.StatusCreated, err
	})
	h("PUT /platform/tenants/{id}", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		b, err := body(r)
		if err != nil {
			return nil, 0, err
		}
		return ok(s.UpdateTenant(r.Context(), r.PathValue("id"), b))
	})

	/* Organisation (copy of Portal Master) */
	h("GET /org/options", func(w http.ResponseWriter, r *http.Request) (any, int, error) { return ok(s.OrgOptions(r.Context())) })
	h("GET /org/status", func(w http.ResponseWriter, r *http.Request) (any, int, error) { return ok(s.OrgStatus(r.Context())) })
	h("POST /org/sync", func(w http.ResponseWriter, r *http.Request) (any, int, error) { return ok(s.OrgSync(r.Context())) })
}
