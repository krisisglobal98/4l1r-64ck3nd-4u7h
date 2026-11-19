package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"alir.local/auth-service/internal/catalog"
	"alir.local/auth-service/internal/platform/apperr"
	"alir.local/auth-service/internal/token"
)

// The OpenID Connect provider: authorization code flow with PKCE (S256, every client), refresh tokens that rotate,
// client_credentials for services, single sign-on through the sign-in session's cookie, and logout that ends it.
// The sign-in itself happens on the ALIR login page (the "hosted login"): /oauth2/authorize sends the browser there
// with a login_challenge, and the page completes it after the password (and a required password change).

// SSOCookie is the single sign-on cookie of a sign-in session (httpOnly, SameSite=Lax: sent on the top-level
// navigation from another application to /oauth2/authorize).
const SSOCookie = "alir_sso"

const (
	codeTTL      = 60 * time.Second
	challengeTTL = 10 * time.Minute
)

var verifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// oauthError is an RFC 6749 error answer.
type oauthError struct {
	Status      int
	Code        string
	Description string
}

func (e *oauthError) Error() string { return e.Code + ": " + e.Description }

func oerr(status int, code, desc string) *oauthError { return &oauthError{status, code, desc} }

func writeOAuth(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeOAuthErr(w http.ResponseWriter, err error) {
	var e *oauthError
	if errors.As(err, &e) {
		if e.Code == "invalid_client" {
			w.Header().Set("WWW-Authenticate", `Basic realm="alir"`)
		}
		writeOAuth(w, e.Status, map[string]string{"error": e.Code, "error_description": e.Description})
		return
	}
	writeOAuth(w, 500, map[string]string{"error": "server_error", "error_description": "Terjadi kesalahan pada server."})
}

/* ---------------- Discovery ---------------- */

func (s *Service) Discovery() map[string]any {
	p := s.Cfg.PublicURL
	return map[string]any{
		"issuer": s.Cfg.Issuer, "authorization_endpoint": p + "/oauth2/authorize", "token_endpoint": p + "/oauth2/token",
		"userinfo_endpoint": p + "/oauth2/userinfo", "jwks_uri": p + "/.well-known/jwks.json", "revocation_endpoint": p + "/oauth2/revoke",
		"end_session_endpoint": p + "/oauth2/logout", "response_types_supported": []string{"code"}, "response_modes_supported": []string{"query"},
		"grant_types_supported": []string{"authorization_code", "refresh_token", "client_credentials"}, "subject_types_supported": []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256", "EdDSA"}, "scopes_supported": knownScopes,
		"token_endpoint_auth_methods_supported":      []string{"client_secret_basic", "client_secret_post", "none"},
		"revocation_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":           []string{"S256"}, "authorization_response_iss_parameter_supported": true,
		"prompt_values_supported": []string{"none", "login"},
		"claims_supported": []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid", "azp", "name", "preferred_username", "email",
			"email_verified", "tid", "tenant", "tenant_name"},
	}
}

/* ---------------- Authorize ---------------- */

// authzParams is one authorization request.
type authzParams struct {
	client                    *OAuthClient
	redirectURI, state, nonce string
	codeChallenge, tenantHint string
	scope                     []string
	prompt                    string
}

// redirectTo is redirect_uri with the answer of an authorization (and iss, RFC 9207).
func (s *Service) redirectTo(redirectURI string, q url.Values) string {
	q.Set("iss", s.Cfg.Issuer)
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	return redirectURI + sep + q.Encode()
}

func (s *Service) redirectErr(w http.ResponseWriter, r *http.Request, p *authzParams, code, desc string) {
	q := url.Values{"error": {code}, "error_description": {desc}}
	if p.state != "" {
		q.Set("state", p.state)
	}
	http.Redirect(w, r, s.redirectTo(p.redirectURI, q), http.StatusFound)
}

// Authorize is GET /oauth2/authorize. Errors before the client and redirect_uri are known are answered here (never
// redirected to an address nobody registered); the rest go back to the application.
func (s *Service) Authorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		q = r.Form
	}
	client, err := s.clientByID(ctx, q.Get("client_id"))
	if err != nil || !client.Active {
		writeOAuth(w, 400, map[string]string{"error": "invalid_client", "error_description": "Aplikasi tidak dikenal atau nonaktif."})
		return
	}
	p := &authzParams{client: client, redirectURI: q.Get("redirect_uri"), state: q.Get("state"), nonce: q.Get("nonce"),
		codeChallenge: q.Get("code_challenge"), tenantHint: strings.ToLower(strings.TrimSpace(q.Get("tenant"))), prompt: q.Get("prompt")}
	if !slices.Contains(client.RedirectURIs, p.redirectURI) {
		writeOAuth(w, 400, map[string]string{"error": "invalid_request", "error_description": "redirect_uri tidak terdaftar untuk aplikasi ini."})
		return
	}
	switch {
	case q.Get("response_type") != "code":
		s.redirectErr(w, r, p, "unsupported_response_type", "Hanya response_type=code.")
		return
	case len(p.state) > 500 || len(p.nonce) > 500 || len(p.tenantHint) > 40:
		s.redirectErr(w, r, p, "invalid_request", "state, nonce atau tenant terlalu panjang.")
		return
	case q.Get("code_challenge_method") != "S256" || len(p.codeChallenge) < 43 || len(p.codeChallenge) > 128:
		s.redirectErr(w, r, p, "invalid_request", "PKCE wajib: code_challenge dengan code_challenge_method=S256.")
		return
	}
	for _, sc := range strings.Fields(q.Get("scope")) {
		if !slices.Contains(client.Scopes, sc) && !(sc == "offline_access" && client.RefreshTokenDays > 0) {
			s.redirectErr(w, r, p, "invalid_scope", fmt.Sprintf("Scope %s tidak diizinkan untuk aplikasi ini.", sc))
			return
		}
		if !slices.Contains(p.scope, sc) {
			p.scope = append(p.scope, sc)
		}
	}
	if !slices.Contains(p.scope, "openid") {
		s.redirectErr(w, r, p, "invalid_scope", "Scope openid wajib.")
		return
	}

	// Signed in already (the SSO cookie of a live session): a code at once, unless the application asks to sign in again.
	if !strings.Contains(p.prompt, "login") {
		if sess, ok := s.ssoSession(ctx, r); ok {
			u, err := s.memberFor(ctx, sess.identityID, sess.tenantID, client, p.tenantHint)
			if err == nil && u.MustChange == nil && !u.mustEnroll() {
				code, err := s.issueCode(ctx, p, u, sess.id)
				if err != nil {
					writeOAuthErr(w, err)
					return
				}
				q := url.Values{"code": {code}}
				if p.state != "" {
					q.Set("state", p.state)
				}
				http.Redirect(w, r, s.redirectTo(p.redirectURI, q), http.StatusFound)
				return
			}
		}
	}
	if strings.Contains(p.prompt, "none") {
		s.redirectErr(w, r, p, "login_required", "Belum masuk.")
		return
	}
	challenge, hash := newSecret()
	if _, err := s.DB.Q(ctx).Exec(ctx, `INSERT INTO auth.authz_request (challenge_hash, client_id, redirect_uri, scope, state, nonce, code_challenge, tenant_hint, expires_at)
		VALUES ($1, $2, $3, $4, nullif($5, ''), nullif($6, ''), $7, nullif($8, ''), now() + make_interval(secs => $9))`,
		hash, client.uuid, p.redirectURI, p.scope, p.state, p.nonce, p.codeChallenge, p.tenantHint, challengeTTL.Seconds()); err != nil {
		writeOAuthErr(w, err)
		return
	}
	login := url.Values{"login_challenge": {challenge}}
	if p.tenantHint != "" {
		login.Set("tenant", p.tenantHint)
	}
	http.Redirect(w, r, s.Cfg.AppBaseURL+"/login?"+login.Encode(), http.StatusFound)
}

type ssoRow struct{ id, identityID, tenantID string }

// ssoSession is the live sign-in session of the request's SSO cookie.
func (s *Service) ssoSession(ctx context.Context, r *http.Request) (ssoRow, bool) {
	c, err := r.Cookie(SSOCookie)
	if err != nil || c.Value == "" || len(c.Value) > 100 {
		return ssoRow{}, false
	}
	var x ssoRow
	err = s.DB.Q(ctx).QueryRow(ctx, `SELECT id, identity_id, tenant_id FROM auth.session WHERE sso_hash = $1 AND revoked_at IS NULL AND expires_at > now()`,
		hashOf(c.Value)).Scan(&x.id, &x.identityID, &x.tenantID)
	return x, err == nil
}

// memberFor is the membership a person signs in to an application with: the application's company when it
// belongs to one; else the company asked for (tenant), else the one the session works in.
func (s *Service) memberFor(ctx context.Context, identityID, sessionTenant string, c *OAuthClient, hint string) (*userRow, error) {
	tid := sessionTenant
	if c.tenantID != nil {
		tid = *c.tenantID
	} else if hint != "" {
		t, err := s.tenantRef(ctx, hint)
		if err != nil || t == nil {
			return nil, unknownTenant()
		}
		tid = t.ID
	}
	var mid string
	err := s.DB.Q(ctx).QueryRow(ctx, `SELECT id FROM auth.membership WHERE identity_id = $1 AND tenant_id = $2 AND NOT is_deleted`, identityID, tid).Scan(&mid)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &apperr.Error{Status: 403, Code: "NOT_MEMBER", Message: "Akun Anda tidak terdaftar di perusahaan pemilik aplikasi ini."}
	}
	if err != nil {
		return nil, err
	}
	u, err := s.userByID(ctx, tid, mid, false)
	if err != nil {
		return nil, err
	}
	if !u.usable() || !s.employeeOK(ctx, u) {
		return nil, &apperr.Error{Status: 403, Code: "INACTIVE", Message: "Akun Anda di perusahaan ini nonaktif. Hubungi administrator."}
	}
	return u, nil
}

func (s *Service) issueCode(ctx context.Context, p *authzParams, u *userRow, sessionID string) (string, error) {
	raw, hash := newSecret()
	_, err := s.DB.Q(ctx).Exec(ctx, `INSERT INTO auth.auth_code (code_hash, client_id, session_id, identity_id, membership_id, tenant_id, redirect_uri, scope, nonce,
		code_challenge, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, nullif($9, ''), $10, now() + make_interval(secs => $11))`,
		hash, p.client.uuid, sessionID, u.IdentityID, u.ID, u.TenantID, p.redirectURI, p.scope, p.nonce, p.codeChallenge, codeTTL.Seconds())
	return raw, err
}

// pendingRequest is a live authorization request of a login challenge.
func (s *Service) pendingRequest(ctx context.Context, challenge string, forUpdate bool) (*authzParams, string, error) {
	if challenge == "" || len(challenge) > 100 {
		return nil, "", apperr.NotFound()
	}
	q := `SELECT a.id, c.code, a.redirect_uri, a.scope, coalesce(a.state, ''), coalesce(a.nonce, ''), a.code_challenge, coalesce(a.tenant_hint, '')
		FROM auth.authz_request a JOIN auth.oauth_client c ON c.id = a.client_id
		WHERE a.challenge_hash = $1 AND a.completed_at IS NULL AND a.expires_at > now()`
	if forUpdate {
		q += ` FOR UPDATE OF a`
	}
	var id, clientID string
	p := &authzParams{}
	err := s.DB.Q(ctx).QueryRow(ctx, q, hashOf(challenge)).Scan(&id, &clientID, &p.redirectURI, &p.scope, &p.state, &p.nonce, &p.codeChallenge, &p.tenantHint)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", &apperr.Error{Status: 404, Code: "LOGIN_EXPIRED", Message: "Permintaan login aplikasi sudah kedaluwarsa. Buka lagi aplikasinya."}
	}
	if err != nil {
		return nil, "", err
	}
	if p.client, err = s.clientByID(ctx, clientID); err != nil || !p.client.Active {
		return nil, "", &apperr.Error{Status: 404, Code: "LOGIN_EXPIRED", Message: "Aplikasi tidak dikenal atau nonaktif."}
	}
	return p, id, nil
}

// AuthorizeRequest describes a login challenge for the login page (GET /oauth2/authorize/request?login_challenge=).
func (s *Service) AuthorizeRequest(ctx context.Context, challenge string) (map[string]any, error) {
	p, _, err := s.pendingRequest(ctx, challenge, false)
	if err != nil {
		return nil, err
	}
	var tenant *TenantRef
	if p.client.tenantID != nil {
		var t TenantRef
		if s.DB.Q(ctx).QueryRow(ctx, `SELECT id, code, name FROM auth.tenant WHERE id = $1`, *p.client.tenantID).Scan(&t.ID, &t.Code, &t.Name) == nil {
			tenant = &t
		}
	} else if p.tenantHint != "" {
		tenant, _ = s.tenantRef(ctx, p.tenantHint)
	}
	return map[string]any{"client": map[string]any{"id": p.client.ID, "name": p.client.Name, "firstParty": p.client.FirstParty}, "scopes": p.scope, "tenant": tenant}, nil
}

// CompleteAuthorize finishes a login challenge for the signed-in caller (POST /oauth2/authorize/complete
// {loginChallenge}): the code goes back to the application ({redirect}). The SSO cookie is (re)set for the session.
func (s *Service) CompleteAuthorize(ctx context.Context, w http.ResponseWriter, challenge string) (map[string]string, error) {
	a := ActorFrom(ctx)
	if a == nil {
		return nil, unauthorized("SIGNED_OUT", "Sesi tidak ditemukan. Silakan masuk kembali.")
	}
	if a.MustChange != nil {
		return nil, &apperr.Error{Status: http.StatusForbidden, Code: "MUST_CHANGE_PASSWORD", Message: "Ganti password Anda terlebih dahulu."}
	}
	if a.MustEnroll {
		return nil, mustEnrollErr()
	}
	var out map[string]string
	var sso string
	err := s.DB.InTx(ctx, func(ctx context.Context) error {
		p, id, err := s.pendingRequest(ctx, challenge, true)
		if err != nil {
			return err
		}
		u, err := s.memberFor(ctx, a.UserID, a.TenantID, p.client, p.tenantHint)
		if err != nil {
			return err
		}
		code, err := s.issueCode(ctx, p, u, a.SessionID)
		if err != nil {
			return err
		}
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.authz_request SET completed_at = now() WHERE id = $1`, id); err != nil {
			return err
		}
		var hash []byte
		sso, hash = newSecret()
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.session SET sso_hash = $2 WHERE id = $1`, a.SessionID, hash); err != nil {
			return err
		}
		q := url.Values{"code": {code}}
		if p.state != "" {
			q.Set("state", p.state)
		}
		out = map[string]string{"redirect": s.redirectTo(p.redirectURI, q)}
		s.audit(ctx, requestOf(ctx), "login", a, p.client.ID, "Masuk ke aplikasi "+p.client.Name)
		return nil
	})
	if err == nil {
		s.setSSOCookie(w, sso)
	}
	return out, err
}

func (s *Service) setSSOCookie(w http.ResponseWriter, raw string) {
	c := &http.Cookie{Name: SSOCookie, Value: raw, Path: s.Cfg.SSOCookiePath, HttpOnly: true, Secure: s.Cfg.CookieSecure, SameSite: http.SameSiteLaxMode}
	if raw == "" {
		c.MaxAge = -1
	}
	http.SetCookie(w, c)
}

/* ---------------- Token ---------------- */

// clientAuth is the application calling the token or revocation endpoint: HTTP Basic or client_id/client_secret in
// the form; a public application sends only its client_id.
func (s *Service) clientAuth(ctx context.Context, r *http.Request) (*OAuthClient, error) {
	id, secret, basic := r.BasicAuth()
	if basic {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	bad := oerr(401, "invalid_client", "Aplikasi tidak dikenal, nonaktif, atau secret salah.")
	c, err := s.clientByID(ctx, id)
	if err != nil || !c.Active {
		return nil, bad
	}
	if c.Public {
		if secret != "" {
			return nil, bad
		}
		return c, nil
	}
	if !c.secretOK(secret) {
		return nil, bad
	}
	return c, nil
}

// TokenResponse is the answer of /oauth2/token.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// Token is POST /oauth2/token (application/x-www-form-urlencoded).
func (s *Service) Token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthErr(w, oerr(400, "invalid_request", "Isian formulir tidak terbaca."))
		return
	}
	ctx := r.Context()
	c, err := s.clientAuth(ctx, r)
	if err != nil {
		writeOAuthErr(w, err)
		return
	}
	var out TokenResponse
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		out, err = s.codeGrant(ctx, c, r.PostForm)
	case "refresh_token":
		out, err = s.refreshGrant(ctx, c, r.PostForm)
	case "client_credentials":
		out, err = s.serviceGrant(ctx, c)
	default:
		err = oerr(400, "unsupported_grant_type", "grant_type tidak didukung.")
	}
	if err != nil {
		writeOAuthErr(w, err)
		return
	}
	_, _ = s.DB.Q(ctx).Exec(ctx, `UPDATE auth.oauth_client SET last_used_at = now() WHERE id = $1`, c.uuid)
	writeOAuth(w, 200, out)
}

func pkceOK(verifier, challenge string) bool {
	if !verifierPattern.MatchString(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}

func (s *Service) codeGrant(ctx context.Context, c *OAuthClient, f url.Values) (TokenResponse, error) {
	bad := oerr(400, "invalid_grant", "Kode tidak berlaku, sudah dipakai, atau tidak cocok.")
	raw := f.Get("code")
	if raw == "" || len(raw) > 100 {
		return TokenResponse{}, bad
	}
	var out TokenResponse
	var refusal error
	err := s.DB.InTx(ctx, func(ctx context.Context) error {
		refusal = nil
		var clientID, sid, mid, tid, redirect, challenge string
		var nonce, grantID *string
		var scope []string
		var expired, used bool
		err := s.DB.Q(ctx).QueryRow(ctx, `SELECT client_id, session_id, membership_id, tenant_id, redirect_uri, scope, nonce, code_challenge,
			expires_at <= now(), used_at IS NOT NULL, grant_id FROM auth.auth_code WHERE code_hash = $1 FOR UPDATE`, hashOf(raw)).Scan(
			&clientID, &sid, &mid, &tid, &redirect, &scope, &nonce, &challenge, &expired, &used, &grantID)
		if errors.Is(err, pgx.ErrNoRows) {
			refusal = bad
			return nil
		}
		if err != nil {
			return err
		}
		if used {
			// A code shown twice was stolen or replayed: what it bought ends too (RFC 6749 §4.1.2).
			if grantID != nil {
				_, _ = s.DB.Q(ctx).Exec(ctx, `UPDATE auth.oauth_grant SET revoked_at = coalesce(revoked_at, now()) WHERE id = $1`, *grantID)
			}
			refusal = bad
			return nil
		}
		if expired || clientID != c.uuid || redirect != f.Get("redirect_uri") || !pkceOK(f.Get("code_verifier"), challenge) {
			refusal = bad
			return nil
		}
		u, sess, err := s.grantUser(ctx, sid, tid, mid)
		if err != nil {
			refusal = err
			return nil
		}
		gid, refresh, err := s.newGrant(ctx, c, sid, u, scope)
		if err != nil {
			return err
		}
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.auth_code SET used_at = now(), grant_id = $2 WHERE code_hash = $1`, hashOf(raw), gid); err != nil {
			return err
		}
		out, err = s.userTokens(ctx, c, u, sid, sess.authTime, scope, deref(nonce), true)
		out.RefreshToken = refresh
		return err
	})
	if err != nil {
		return TokenResponse{}, err
	}
	return out, refusal
}

type sessionInfo struct{ authTime time.Time }

// grantUser is the member behind a grant, when the sign-in session and the member may still act.
func (s *Service) grantUser(ctx context.Context, sid, tid, mid string) (*userRow, sessionInfo, error) {
	var si sessionInfo
	var revoked bool
	err := s.DB.Q(ctx).QueryRow(ctx, `SELECT created_at, revoked_at IS NOT NULL FROM auth.session WHERE id = $1`, sid).Scan(&si.authTime, &revoked)
	if err != nil || revoked {
		return nil, si, oerr(400, "invalid_grant", "Sesi login sudah berakhir.")
	}
	u, err := s.userByID(ctx, tid, mid, false)
	if err != nil || !u.usable() || !s.employeeOK(ctx, u) || u.MustChange != nil || u.mustEnroll() {
		return nil, si, oerr(400, "invalid_grant", "Akun tidak aktif atau harus mengganti password.")
	}
	return u, si, nil
}

func (s *Service) newGrant(ctx context.Context, c *OAuthClient, sid string, u *userRow, scope []string) (string, string, error) {
	var refresh string
	var hash []byte
	if c.RefreshTokenDays > 0 {
		refresh, hash = newSecret()
	}
	days := max(c.RefreshTokenDays, 1)
	var id string
	err := s.DB.Q(ctx).QueryRow(ctx, `INSERT INTO auth.oauth_grant (client_id, session_id, identity_id, membership_id, tenant_id, scope, refresh_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(days => $8)) RETURNING id`, c.uuid, sid, u.IdentityID, u.ID, u.TenantID, scope, hash, days).Scan(&id)
	return id, refresh, err
}

func (s *Service) refreshGrant(ctx context.Context, c *OAuthClient, f url.Values) (TokenResponse, error) {
	bad := oerr(400, "invalid_grant", "Refresh token tidak berlaku.")
	raw := f.Get("refresh_token")
	if raw == "" || len(raw) > 100 {
		return TokenResponse{}, bad
	}
	var out TokenResponse
	var refusal error
	err := s.DB.InTx(ctx, func(ctx context.Context) error {
		refusal = nil
		h := hashOf(raw)
		var gid, clientID, sid, mid, tid string
		var scope []string
		var alive bool
		err := s.DB.Q(ctx).QueryRow(ctx, `SELECT id, client_id, session_id, membership_id, tenant_id, scope, revoked_at IS NULL AND expires_at > now()
			FROM auth.oauth_grant WHERE refresh_hash = $1 FOR UPDATE`, h).Scan(&gid, &clientID, &sid, &mid, &tid, &scope, &alive)
		if errors.Is(err, pgx.ErrNoRows) {
			// A rotated refresh token shown again: after the grace of a parallel refresh, it was stolen.
			var recent bool
			if s.DB.Q(ctx).QueryRow(ctx, `SELECT id, last_used_at > now() - make_interval(secs => $2) FROM auth.oauth_grant
				WHERE previous_hash = $1 AND revoked_at IS NULL FOR UPDATE`, h, refreshGrace.Seconds()).Scan(&gid, &recent) == nil && !recent {
				_, _ = s.DB.Q(ctx).Exec(ctx, `UPDATE auth.oauth_grant SET revoked_at = now() WHERE id = $1`, gid)
				s.auditIn(ctx, nil, "", "session_revoked", nil, c.ID, "Refresh token aplikasi dipakai ulang; akses aplikasi dicabut")
			}
			refusal = bad
			return nil
		}
		if err != nil {
			return err
		}
		if !alive || clientID != c.uuid {
			refusal = bad
			return nil
		}
		if want := strings.Fields(f.Get("scope")); len(want) > 0 {
			for _, sc := range want {
				if !slices.Contains(scope, sc) {
					refusal = oerr(400, "invalid_scope", "Scope melebihi yang diberikan saat login.")
					return nil
				}
			}
			scope = want
		}
		u, sess, err := s.grantUser(ctx, sid, tid, mid)
		if err != nil {
			refusal = err
			return nil
		}
		next, nh := newSecret()
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.oauth_grant SET previous_hash = refresh_hash, refresh_hash = $2, last_used_at = now() WHERE id = $1`, gid, nh); err != nil {
			return err
		}
		out, err = s.userTokens(ctx, c, u, sid, sess.authTime, scope, "", slices.Contains(scope, "openid"))
		out.RefreshToken = next
		return err
	})
	if err != nil {
		return TokenResponse{}, err
	}
	return out, refusal
}

// moduleGrants limits grants to one module's menus (an application sees only its own module's access).
func moduleGrants(g catalog.Grants, module string) catalog.Grants {
	out := catalog.Grants{}
	for _, m := range catalog.Modules() {
		if m.ID != module {
			continue
		}
		for _, menu := range m.Menus {
			if a := g[menu.ID]; len(a) > 0 {
				out[menu.ID] = slices.Clone(a)
			}
		}
	}
	return out
}

// userTokens makes the access token (and the ID token) of a member for an application.
func (s *Service) userTokens(ctx context.Context, c *OAuthClient, u *userRow, sid string, authTime time.Time, scope []string, nonce string, withID bool) (TokenResponse, error) {
	u.Name = s.nameOf(ctx, u)
	now := s.now()
	exp := now.Add(time.Duration(c.AccessTokenMinutes) * time.Minute)
	jti, _ := newSecret()
	claims := token.Claims{ID: jti[:16], Issuer: s.Cfg.Issuer, Audience: token.Audience, Subject: u.IdentityID, SessionID: sid, MemberID: u.ID,
		TenantID: u.TenantID, IssuedAt: now.Unix(), Expires: exp.Unix(), Username: u.Username, Name: u.Name, Role: u.RoleCode, ClientID: c.ID,
		Scope: strings.Join(scope, " ")}
	if slices.Contains(scope, "dod.access") {
		acc, err := s.access(ctx, u)
		if err != nil {
			return TokenResponse{}, err
		}
		switch {
		case c.Module != nil && acc.Full:
			claims.Grants = moduleGrants(catalog.Full(), *c.Module)
		case c.Module != nil:
			claims.Grants = moduleGrants(acc.Grants, *c.Module)
		case acc.Full:
			claims.Full = true
		default:
			claims.Grants = acc.Grants
		}
	}
	at, err := s.Keys.Sign(claims)
	if err != nil {
		return TokenResponse{}, err
	}
	out := TokenResponse{AccessToken: at, TokenType: "Bearer", ExpiresIn: int(exp.Sub(now).Seconds()), Scope: strings.Join(scope, " ")}
	if withID {
		id := map[string]any{"iss": s.Cfg.Issuer, "sub": u.IdentityID, "aud": c.ID, "azp": c.ID, "exp": exp.Unix(), "iat": now.Unix(),
			"auth_time": authTime.Unix(), "sid": sid, "tid": u.TenantID, "tenant": u.TenantCode, "tenant_name": u.TenantName,
			"member_kind": u.Kind, "member_verified": u.VerifiedAt != nil}
		if nonce != "" {
			id["nonce"] = nonce
		}
		for k, v := range s.profileClaims(ctx, u, scope) {
			id[k] = v
		}
		if out.IDToken, err = s.Keys.SignID(id, c.IDTokenAlg); err != nil {
			return TokenResponse{}, err
		}
	}
	return out, nil
}

// profileClaims are the person's claims a scope opens (profile: name and username; email: the email).
func (s *Service) profileClaims(ctx context.Context, u *userRow, scope []string) map[string]any {
	out := map[string]any{}
	if slices.Contains(scope, "profile") {
		out["name"], out["preferred_username"] = u.Name, u.Username
	}
	if slices.Contains(scope, "email") {
		if e := s.emailOf(ctx, u); e != "" {
			var verified bool
			_ = s.DB.Q(ctx).QueryRow(ctx, `SELECT email_verified_at IS NOT NULL AND email = $2 FROM auth.identity WHERE id = $1`, u.IdentityID, e).Scan(&verified)
			out["email"], out["email_verified"] = e, verified
		}
	}
	return out
}

// serviceGrant is client_credentials: a service of one company acting with its service role's grants.
func (s *Service) serviceGrant(ctx context.Context, c *OAuthClient) (TokenResponse, error) {
	if c.Public || c.serviceRoleID == nil || c.tenantID == nil {
		return TokenResponse{}, oerr(400, "unauthorized_client", "Aplikasi ini tidak diizinkan memakai client_credentials.")
	}
	var active bool
	if err := s.DB.Q(ctx).QueryRow(ctx, `SELECT t.is_active AND NOT t.is_deleted FROM auth.tenant t WHERE t.id = $1`, *c.tenantID).Scan(&active); err != nil || !active {
		return TokenResponse{}, oerr(400, "unauthorized_client", "Perusahaan pemilik aplikasi nonaktif.")
	}
	g := catalog.Grants{}
	rows, err := s.DB.Q(ctx).Query(ctx, `SELECT g.menu, g.actions FROM auth.role_grant g JOIN auth.role r ON r.id = g.role_id
		WHERE g.role_id = $1 AND r.is_active AND NOT r.is_deleted`, *c.serviceRoleID)
	if err != nil {
		return TokenResponse{}, err
	}
	for rows.Next() {
		var menu string
		var actions []string
		if err := rows.Scan(&menu, &actions); err != nil {
			rows.Close()
			return TokenResponse{}, err
		}
		g[menu] = actions
	}
	rows.Close()
	if c.Module != nil {
		g = moduleGrants(g, *c.Module)
	}
	now := s.now()
	exp := now.Add(time.Duration(c.AccessTokenMinutes) * time.Minute)
	jti, _ := newSecret()
	at, err := s.Keys.Sign(token.Claims{ID: jti[:16], Issuer: s.Cfg.Issuer, Audience: token.Audience, Subject: c.uuid, SessionID: "service",
		TenantID: *c.tenantID, IssuedAt: now.Unix(), Expires: exp.Unix(), Username: c.ID, Name: c.Name, Role: "service", Grants: g, ClientID: c.ID})
	if err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{AccessToken: at, TokenType: "Bearer", ExpiresIn: int(exp.Sub(now).Seconds())}, nil
}

/* ---------------- UserInfo, revocation, logout ---------------- */

// UserInfo is GET/POST /oauth2/userinfo with an access token of a person.
func (s *Service) UserInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h := r.Header.Get("Authorization")
	deny := func(desc string) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+desc+`"`)
		writeOAuth(w, 401, map[string]string{"error": "invalid_token", "error_description": desc})
	}
	if !strings.HasPrefix(h, "Bearer ") {
		deny("Token tidak ada.")
		return
	}
	c, err := s.Keys.Verify(strings.TrimPrefix(h, "Bearer "), s.Cfg.Issuer, s.now())
	if err != nil || c.MemberID == "" {
		deny("Token tidak sah atau kedaluwarsa.")
		return
	}
	u, err := s.userByID(ctx, c.TenantID, c.MemberID, false)
	if err != nil || !u.usable() {
		deny("Akun tidak aktif.")
		return
	}
	var alive bool
	if s.DB.Q(ctx).QueryRow(ctx, `SELECT revoked_at IS NULL FROM auth.session WHERE id::text = $1`, c.SessionID).Scan(&alive) != nil || !alive {
		deny("Sesi login sudah berakhir.")
		return
	}
	u.Name = s.nameOf(ctx, u)
	scope := strings.Fields(c.Scope)
	if c.ClientID == "" {
		scope = []string{"openid", "profile", "email"} // a token of the ALIR web's own session
	}
	out := map[string]any{"sub": u.IdentityID, "tid": u.TenantID, "tenant": u.TenantCode, "tenant_name": u.TenantName}
	for k, v := range s.profileClaims(ctx, u, scope) {
		out[k] = v
	}
	writeOAuth(w, 200, out)
}

// Revoke is POST /oauth2/revoke (RFC 7009): a refresh token of the calling application ends its grant. The answer
// is 200 whatever the token was.
func (s *Service) Revoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthErr(w, oerr(400, "invalid_request", "Isian formulir tidak terbaca."))
		return
	}
	ctx := r.Context()
	c, err := s.clientAuth(ctx, r)
	if err != nil {
		writeOAuthErr(w, err)
		return
	}
	if t := r.PostForm.Get("token"); t != "" && len(t) <= 100 {
		_, _ = s.DB.Q(ctx).Exec(ctx, `UPDATE auth.oauth_grant SET revoked_at = coalesce(revoked_at, now()) WHERE client_id = $1 AND refresh_hash = $2`, c.uuid, hashOf(t))
	}
	writeOAuth(w, 200, map[string]any{})
}

// EndSession is /oauth2/logout (RP-initiated logout): the sign-in session ends (and with it every application's
// grant of it), then the browser goes to the application's registered post_logout_redirect_uri, or the login page.
func (s *Service) EndSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		q = r.Form
	}
	var sid, clientID string
	if hint := q.Get("id_token_hint"); hint != "" {
		claims, err := s.Keys.Inspect(hint, s.Cfg.Issuer)
		if err != nil {
			writeOAuth(w, 400, map[string]string{"error": "invalid_request", "error_description": "id_token_hint tidak sah."})
			return
		}
		sid, _ = claims["sid"].(string)
		clientID, _ = claims["aud"].(string)
	}
	if x := q.Get("client_id"); x != "" {
		if clientID != "" && !strings.EqualFold(clientID, x) {
			writeOAuth(w, 400, map[string]string{"error": "invalid_request", "error_description": "client_id tidak cocok dengan id_token_hint."})
			return
		}
		clientID = x
	}
	target := s.Cfg.AppBaseURL + "/login"
	if to := q.Get("post_logout_redirect_uri"); to != "" {
		c, err := s.clientByID(ctx, clientID)
		if err != nil || !slices.Contains(c.PostLogoutURIs, to) {
			writeOAuth(w, 400, map[string]string{"error": "invalid_request", "error_description": "post_logout_redirect_uri tidak terdaftar untuk aplikasi ini."})
			return
		}
		target = to
		if st := q.Get("state"); st != "" && len(st) <= 500 {
			v := url.Values{"state": {st}}
			sep := "?"
			if strings.Contains(target, "?") {
				sep = "&"
			}
			target += sep + v.Encode()
		}
	}
	if sess, ok := s.ssoSession(ctx, r); ok && (sid == "" || sid == sess.id) {
		sid = sess.id
	}
	if uuidLike.MatchString(sid) {
		var tid, username string
		if s.DB.Q(ctx).QueryRow(ctx, `UPDATE auth.session x SET revoked_at = coalesce(x.revoked_at, now()) FROM auth.membership m
			WHERE x.id = $1 AND m.id = x.membership_id RETURNING x.tenant_id, m.username`, sid).Scan(&tid, &username) == nil {
			_, _ = s.DB.Q(ctx).Exec(ctx, `UPDATE auth.oauth_grant SET revoked_at = coalesce(revoked_at, now()) WHERE session_id = $1`, sid)
			s.auditIn(ctx, r, tid, "logout", nil, username, "Keluar dari semua aplikasi (OIDC logout)")
		}
	}
	s.setSSOCookie(w, "")
	s.setCookie(w, "", time.Time{})
	http.Redirect(w, r, target, http.StatusFound)
}
