package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"alir.local/auth-service/internal/oidcrp"
	"alir.local/auth-service/internal/platform/apperr"
	"alir.local/auth-service/internal/platform/codeprefix"
	"alir.local/auth-service/internal/platform/record"
)

// Sign-in through a company's identity provider (Microsoft Entra ID / Azure AD, Google Workspace, any OIDC
// provider): Authentication is the relying party. The person is matched by the account linked before (issuer +
// subject), else by an email the provider vouches for (a domain registered on it, not marked unverified), else made a
// member when the provider allows just-in-time membership. Then the rules of every sign-in apply (inactive, employee,
// MFA). The browser goes back to the ALIR pages: /auth/sso-done (signed in), /login?mfa= (authenticator awaited) or
// /login?sso_error= (refused).

const idpLoginTTL = 10 * time.Minute

// idpRedirectURI is the address registered at the provider for its answers.
func (s *Service) idpRedirectURI() string { return s.Cfg.PublicURL + "/auth/idp/callback" }

// IdpButton is a provider as the sign-in page shows it.
type IdpButton struct {
	Tenant string `json:"tenant"`
	Code   string `json:"code"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
}

// idpButtons are the providers a company's sign-in page offers (active, with a secret).
func (s *Service) idpButtons(ctx context.Context, tenantID string) ([]IdpButton, error) {
	rows, err := s.DB.Q(ctx).Query(ctx, `SELECT t.code, p.code, p.name, p.kind FROM auth.identity_provider p JOIN auth.tenant t ON t.id = p.tenant_id
		WHERE p.tenant_id = $1 AND p.is_active AND NOT p.is_deleted AND p.client_secret_sealed IS NOT NULL ORDER BY p.name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IdpButton{}
	for rows.Next() {
		var b IdpButton
		if err := rows.Scan(&b.Tenant, &b.Code, &b.Name, &b.Kind); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// DiscoverIdp names the provider of an email's domain (POST /auth/idp/discover {email}): the sign-in page offers
// "sign in with …" for a company address. It tells only that the domain has a provider, never whether the person
// has an account.
func (s *Service) DiscoverIdp(ctx context.Context, body record.Values) (map[string]any, error) {
	email, _ := body["email"].(string)
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndex(email, "@")
	if at < 1 || len(email) > 254 {
		return map[string]any{"provider": nil}, nil
	}
	var b IdpButton
	err := s.DB.Q(ctx).QueryRow(ctx, `SELECT t.code, p.code, p.name, p.kind FROM auth.identity_provider p JOIN auth.tenant t ON t.id = p.tenant_id
		WHERE $1 = ANY(p.email_domains) AND p.is_active AND NOT p.is_deleted AND p.client_secret_sealed IS NOT NULL AND t.is_active AND NOT t.is_deleted
		LIMIT 1`, email[at+1:]).Scan(&b.Tenant, &b.Code, &b.Name, &b.Kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return map[string]any{"provider": nil}, nil
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"provider": b}, nil
}

// safeReturn keeps a return address only when it is a path of the ALIR pages (never another site).
func safeReturn(p string) string {
	if p == "" || len(p) > 500 || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n") {
		return ""
	}
	return p
}

// providerRow is a provider with what the sign-in needs.
type providerRow struct {
	IdentityProvider
	tenantID, tenantCode string
}

func (s *Service) providerByTenantCode(ctx context.Context, tenantCode, code string) (*providerRow, error) {
	var tid, tcode string
	if err := s.DB.Q(ctx).QueryRow(ctx, `SELECT id, code FROM auth.tenant WHERE lower(code) = lower($1) AND is_active AND NOT is_deleted`, tenantCode).Scan(&tid, &tcode); err != nil {
		return nil, apperr.NotFound()
	}
	x, err := s.idp(ctx, tid, code, false)
	if err != nil || !x.Active || !x.SecretSet {
		return nil, apperr.NotFound()
	}
	return &providerRow{*x, tid, tcode}, nil
}

func (s *Service) providerByID(ctx context.Context, id string) (*providerRow, error) {
	var tid, tcode, code string
	err := s.DB.Q(ctx).QueryRow(ctx, `SELECT p.tenant_id, t.code, p.code FROM auth.identity_provider p JOIN auth.tenant t ON t.id = p.tenant_id
		WHERE p.id = $1 AND p.is_active AND NOT p.is_deleted AND t.is_active AND NOT t.is_deleted`, id).Scan(&tid, &tcode, &code)
	if err != nil {
		return nil, apperr.NotFound()
	}
	x, err := s.idp(ctx, tid, code, false)
	if err != nil {
		return nil, err
	}
	return &providerRow{*x, tid, tcode}, nil
}

// loginPage is the ALIR sign-in page with a refusal (or the MFA step) for the browser.
func (s *Service) loginPage(q url.Values) string { return s.Cfg.AppBaseURL + "/login?" + q.Encode() }

// IdpStart sends the browser to the provider (GET /auth/idp/start?tenant=&idp=&login_challenge=&return=).
func (s *Service) IdpStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	fail := func(code string) {
		http.Redirect(w, r, s.loginPage(url.Values{"sso_error": {code}, "tenant": {q.Get("tenant")}}), http.StatusFound)
	}
	p, err := s.providerByTenantCode(ctx, q.Get("tenant"), q.Get("idp"))
	if err != nil {
		fail("IDP_UNAVAILABLE")
		return
	}
	d, err := s.RP.Discover(ctx, p.Issuer)
	if err != nil {
		slog.Warn("identity provider discovery", "idp", p.Code, "tenant", p.tenantCode, "err", err)
		fail("IDP_UNREACHABLE")
		return
	}
	state, stateHash := newSecret()
	nonce, _ := newSecret()
	verifier, _ := newSecret()
	challenge := q.Get("login_challenge")
	if len(challenge) > 100 {
		challenge = ""
	}
	if _, err := s.DB.Q(ctx).Exec(ctx, `INSERT INTO auth.idp_login (state_hash, idp_id, nonce, code_verifier, return_to, login_challenge, expires_at)
		VALUES ($1, $2, $3, $4, nullif($5, ''), nullif($6, ''), now() + make_interval(secs => $7))`,
		stateHash, p.id, nonce, verifier, safeReturn(q.Get("return")), challenge, idpLoginTTL.Seconds()); err != nil {
		fail("IDP_UNAVAILABLE")
		return
	}
	extra := url.Values{}
	if p.Kind == "google" && len(p.EmailDomains) == 1 {
		extra.Set("hd", p.EmailDomains[0]) // Google: offer only accounts of the company's Workspace domain
	}
	if hint := q.Get("login_hint"); hint != "" && len(hint) <= 254 {
		extra.Set("login_hint", hint)
	}
	http.Redirect(w, r, oidcrp.AuthURL(d, p.ClientID, s.idpRedirectURI(), state, nonce, verifier, p.Scopes, extra), http.StatusFound)
}

// claimString is a string claim ("" when absent).
func claimString(cl map[string]any, k string) string {
	v, _ := cl[k].(string)
	return strings.TrimSpace(v)
}

// federated is what the provider says of the person.
type federated struct {
	subject, email, name string
	emailTrusted         bool
}

func (p *providerRow) person(cl map[string]any) federated {
	f := federated{subject: claimString(cl, p.SubjectClaim), name: claimString(cl, p.NameClaim)}
	candidates := []string{p.EmailClaim, "email"}
	if p.Kind == "azure_ad" {
		candidates = append(candidates, "preferred_username", "upn")
	}
	for _, k := range candidates {
		if e := strings.ToLower(claimString(cl, k)); emailPattern.MatchString(e) {
			f.email = e
			break
		}
	}
	// An email counts only for a domain registered on the provider, and not when the provider says it is unverified.
	if f.email != "" {
		verified := true
		if v, ok := cl["email_verified"].(bool); ok {
			verified = v
		}
		f.emailTrusted = verified && slices.Contains(p.EmailDomains, f.email[strings.LastIndex(f.email, "@")+1:])
	}
	if f.name == "" {
		f.name = f.email
	}
	if f.name == "" {
		f.name = "Pengguna " + p.Name
	}
	return f
}

// IdpCallback is the provider's answer (GET /auth/idp/callback?code=&state= or ?error=&state=).
func (s *Service) IdpCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	page := func(v url.Values) { http.Redirect(w, r, s.loginPage(v), http.StatusFound) }
	raw := q.Get("state")
	if raw == "" || len(raw) > 100 {
		page(url.Values{"sso_error": {"IDP_STATE"}})
		return
	}
	var idpID, nonce, verifier string
	var returnTo, challenge *string
	err := s.DB.Q(ctx).QueryRow(ctx, `UPDATE auth.idp_login SET used_at = now() WHERE state_hash = $1 AND used_at IS NULL AND expires_at > now()
		RETURNING idp_id, nonce, code_verifier, return_to, login_challenge`, hashOf(raw)).Scan(&idpID, &nonce, &verifier, &returnTo, &challenge)
	if err != nil {
		page(url.Values{"sso_error": {"IDP_STATE"}})
		return
	}
	p, err := s.providerByID(ctx, idpID)
	if err != nil {
		page(url.Values{"sso_error": {"IDP_UNAVAILABLE"}})
		return
	}
	withTenant := func(code string) url.Values {
		v := url.Values{"sso_error": {code}, "tenant": {p.tenantCode}}
		if challenge != nil {
			v.Set("login_challenge", *challenge)
		}
		return v
	}
	if e := q.Get("error"); e != "" || q.Get("code") == "" {
		s.auditIn(ctx, r, p.tenantID, "login_failed", nil, p.Name, "Penyedia identitas menolak: "+truncate(e, 100))
		page(withTenant("IDP_REFUSED"))
		return
	}
	d, err := s.RP.Discover(ctx, p.Issuer)
	if err != nil {
		page(withTenant("IDP_UNREACHABLE"))
		return
	}
	secret, err := s.idpSecret(ctx, &p.IdentityProvider)
	if err != nil || secret == "" {
		page(withTenant("IDP_UNAVAILABLE"))
		return
	}
	idt, err := s.RP.Exchange(ctx, d, p.ClientID, secret, q.Get("code"), s.idpRedirectURI(), verifier)
	if err != nil {
		slog.Warn("identity provider token", "idp", p.Code, "tenant", p.tenantCode, "err", err)
		page(withTenant("IDP_TOKEN"))
		return
	}
	claims, err := s.RP.Verify(ctx, d, idt, p.ClientID, nonce, s.now())
	if err != nil {
		slog.Warn("identity provider id token", "idp", p.Code, "tenant", p.tenantCode, "err", err)
		s.auditIn(ctx, r, p.tenantID, "login_failed", nil, p.Name, "ID token penyedia identitas ditolak")
		page(withTenant("IDP_TOKEN"))
		return
	}
	person := p.person(claims)
	if person.subject == "" {
		page(withTenant("IDP_TOKEN"))
		return
	}

	var out LoginResult
	var refusal error
	err = s.DB.InTx(ctx, func(ctx context.Context) error {
		refusal = nil
		u, why, err := s.federatedMember(ctx, r, p, person)
		if err != nil {
			return err
		}
		if why != nil {
			refusal = why
			return nil
		}
		pol, err := s.policy(ctx, u.TenantID)
		if err != nil {
			return err
		}
		var err2 error
		out, refusal, err2 = s.secondFactorOrSession(ctx, r, u, pol, "idp", s.now())
		return err2
	})
	if err != nil {
		slog.Error("identity provider sign-in", "idp", p.Code, "err", err)
		page(withTenant("IDP_UNAVAILABLE"))
		return
	}
	var e *apperr.Error
	switch {
	case refusal == nil:
		s.setCookie(w, out.refresh, out.refreshExpires)
		s.setSSOCookie(w, out.sso)
		v := url.Values{}
		if challenge != nil {
			v.Set("login_challenge", *challenge)
		} else if returnTo != nil {
			v.Set("return", *returnTo)
		}
		http.Redirect(w, r, s.Cfg.AppBaseURL+"/auth/sso-done?"+v.Encode(), http.StatusFound)
	case errors.As(refusal, &e) && e.Code == "MFA_REQUIRED":
		v := url.Values{"mfa": {e.Details.(map[string]any)["mfaToken"].(string)}, "tenant": {p.tenantCode}}
		if challenge != nil {
			v.Set("login_challenge", *challenge)
		}
		page(v)
	case errors.As(refusal, &e):
		page(withTenant(e.Code))
	default:
		page(withTenant("IDP_UNAVAILABLE"))
	}
}

// federatedMember finds (or makes, just in time) the member of the provider's company the provider vouches for.
func (s *Service) federatedMember(ctx context.Context, r *http.Request, p *providerRow, f federated) (*userRow, error, error) {
	if _, err := s.DB.Q(ctx).Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('auth.idp.' || $1::text || '|' || $2::text))`, p.Issuer, f.subject); err != nil {
		return nil, nil, err
	}
	notRegistered := &apperr.Error{Status: 403, Code: "NOT_REGISTERED", Message: "Akun ini belum terdaftar di ALIR. Hubungi administrator perusahaan Anda."}
	var iid string
	err := s.DB.Q(ctx).QueryRow(ctx, `SELECT identity_id FROM auth.identity_link WHERE issuer = $1 AND subject = $2`, p.Issuer, f.subject).Scan(&iid)
	switch {
	case err == nil:
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, nil, err
	case f.emailTrusted:
		if iid, err = s.identityByEmail(ctx, f.email); err != nil {
			return nil, nil, err
		}
		if iid == "" && p.JitProvisioning {
			if err := s.DB.Q(ctx).QueryRow(ctx, `INSERT INTO auth.identity (name, email, email_verified_at, origin, created_by) VALUES ($1, $2, now(), 'idp', $3) RETURNING id`,
				truncate(f.name, record.MaxName), f.email, SystemUserID).Scan(&iid); err != nil {
				return nil, nil, uniqueEmail(err)
			}
		}
		if iid == "" {
			return nil, notRegistered, nil
		}
		if _, err := s.DB.Q(ctx).Exec(ctx, `INSERT INTO auth.identity_link (identity_id, issuer, subject, idp_id, created_by) VALUES ($1, $2, $3, $4, $5)`,
			iid, p.Issuer, f.subject, p.id, SystemUserID); err != nil {
			return nil, nil, err
		}
		s.auditIn(ctx, r, p.tenantID, "user_updated", nil, f.email, "Akun ditautkan ke penyedia identitas "+p.Name)
	default:
		return nil, notRegistered, nil
	}
	if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.identity_link SET last_used_at = now(), idp_id = $3 WHERE issuer = $1 AND subject = $2`, p.Issuer, f.subject, p.id); err != nil {
		return nil, nil, err
	}
	var active bool
	if err := s.DB.Q(ctx).QueryRow(ctx, `SELECT is_active AND NOT is_deleted FROM auth.identity WHERE id = $1`, iid).Scan(&active); err != nil || !active {
		return nil, &apperr.Error{Status: 403, Code: "INACTIVE", Message: "Akun ini nonaktif. Hubungi administrator."}, nil
	}
	var mid string
	err = s.DB.Q(ctx).QueryRow(ctx, `SELECT id FROM auth.membership WHERE tenant_id = $1 AND identity_id = $2 AND NOT is_deleted`, p.tenantID, iid).Scan(&mid)
	if errors.Is(err, pgx.ErrNoRows) {
		if !p.JitProvisioning || p.defaultRoleID == nil {
			return nil, &apperr.Error{Status: 403, Code: "NOT_MEMBER", Message: "Akun Anda belum terdaftar di perusahaan ini."}, nil
		}
		if mid, err = s.jitMember(ctx, p, iid, f); err != nil {
			return nil, nil, err
		}
		s.auditIn(ctx, r, p.tenantID, "user_created", nil, f.email, "Anggota dibuat otomatis dari penyedia identitas "+p.Name)
	} else if err != nil {
		return nil, nil, err
	}
	u, err := s.userByID(ctx, p.tenantID, mid, true)
	if err != nil {
		return nil, nil, err
	}
	if !u.usable() {
		return nil, &apperr.Error{Status: 403, Code: "INACTIVE", Message: "Akun Anda di perusahaan ini nonaktif. Hubungi administrator."}, nil
	}
	if !s.employeeOK(ctx, u) {
		return nil, &apperr.Error{Status: 403, Code: "EMPLOYEE_INACTIVE", Message: "Karyawan pemilik akun ini nonaktif. Hubungi administrator."}, nil
	}
	return u, nil, nil
}

// jitMember makes the person a workforce member of the provider's company with its initial role.
func (s *Service) jitMember(ctx context.Context, p *providerRow, identityID string, f federated) (string, error) {
	seed := f.email
	if seed == "" {
		seed = f.subject
	}
	username, err := s.freeUsername(ctx, p.tenantID, seed)
	if err != nil {
		return "", err
	}
	ctx = codeprefix.WithTenant(ctx, p.tenantID)
	code, err := codeprefix.NextFree(ctx, s.Codes, "membership", func(ctx context.Context, c string) (bool, error) {
		var taken bool
		err := s.DB.Q(ctx).QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth.membership WHERE tenant_id = $1 AND lower(code) = lower($2))`, p.tenantID, c).Scan(&taken)
		return taken, err
	})
	if err != nil {
		return "", err
	}
	var id string
	err = s.DB.Q(ctx).QueryRow(ctx, `INSERT INTO auth.membership (tenant_id, identity_id, code, name, username, role_id, kind, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, 'workforce', $7) RETURNING id`, p.tenantID, identityID, code, truncate(f.name, record.MaxName), username, *p.defaultRoleID, SystemUserID).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("just-in-time member: %w", err)
	}
	return id, nil
}
