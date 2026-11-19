package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"alir.local/auth-service/internal/platform/apperr"
	"alir.local/auth-service/internal/platform/codeprefix"
	"alir.local/auth-service/internal/platform/record"
)

// The Identity Provider master: where a company's people may also sign in (Active Directory through Azure AD /
// Entra ID, Google Workspace, any OpenID Connect provider). Email domains route a sign-in to its provider; claims
// map to the ALIR member; a first sign-in may make the member (just-in-time) with a role. The client secret is
// sealed (AES-256-GCM) and never answered. The connectors that sign people in through these come in Stage 2.

var idpKinds = []string{"azure_ad", "google", "oidc"}

var (
	domainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	claimPattern  = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,60}$`)
)

// IdentityProvider is a provider as the page reads it.
type IdentityProvider struct {
	Code            string     `json:"code"`
	Name            string     `json:"name"`
	Description     *string    `json:"description"`
	Kind            string     `json:"kind"`
	Issuer          string     `json:"issuer"`
	ClientID        string     `json:"clientId"`
	SecretSet       bool       `json:"secretSet"`
	SecretHint      *string    `json:"secretHint"`
	Scopes          []string   `json:"scopes"`
	EmailDomains    []string   `json:"emailDomains"`
	SubjectClaim    string     `json:"subjectClaim"`
	EmailClaim      string     `json:"emailClaim"`
	NameClaim       string     `json:"nameClaim"`
	JitProvisioning bool       `json:"jitProvisioning"`
	DefaultRole     *string    `json:"defaultRole"`
	Active          bool       `json:"active"`
	UpdatedAt       *time.Time `json:"updatedAt"`
	UpdatedBy       *string    `json:"updatedBy"`
	Version         int        `json:"version"`
	RedirectURI     string     `json:"redirectUri"` // to register at the provider
	id              string
	defaultRoleID   *string
}

const idpSelect = `SELECT p.id, p.code, p.name, p.description, p.kind, p.issuer, p.client_id, p.client_secret_sealed IS NOT NULL, p.secret_hint, p.scopes,
	p.email_domains, p.subject_claim, p.email_claim, p.name_claim, p.jit_provisioning, r.code, p.default_role_id, p.is_active,
	coalesce(p.updated_at, p.created_at), ub.name, p.version
	FROM auth.identity_provider p LEFT JOIN auth.role r ON r.id = p.default_role_id LEFT JOIN auth.identity ub ON ub.id = coalesce(p.updated_by, p.created_by)`

func scanIdp(row pgx.Row) (*IdentityProvider, error) {
	var x IdentityProvider
	var at time.Time
	err := row.Scan(&x.id, &x.Code, &x.Name, &x.Description, &x.Kind, &x.Issuer, &x.ClientID, &x.SecretSet, &x.SecretHint, &x.Scopes, &x.EmailDomains,
		&x.SubjectClaim, &x.EmailClaim, &x.NameClaim, &x.JitProvisioning, &x.DefaultRole, &x.defaultRoleID, &x.Active, &at, &x.UpdatedBy, &x.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	u := at.UTC()
	x.UpdatedAt = &u
	return &x, err
}

func (s *Service) idp(ctx context.Context, tenantID, code string, forUpdate bool) (*IdentityProvider, error) {
	q := idpSelect + ` WHERE p.tenant_id = $1 AND lower(p.code) = lower($2) AND NOT p.is_deleted`
	if forUpdate {
		q += ` FOR UPDATE OF p`
	}
	return scanIdp(s.DB.Q(ctx).QueryRow(ctx, q, tenantID, code))
}

// ListIdps is the company's identity providers (GET /auth/identity-providers).
func (s *Service) ListIdps(ctx context.Context) ([]*IdentityProvider, error) {
	me, err := Require(ctx, "auth.security", "read")
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.Q(ctx).Query(ctx, idpSelect+` WHERE p.tenant_id = $1 AND NOT p.is_deleted ORDER BY p.name`, me.TenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*IdentityProvider{}
	for rows.Next() {
		x, err := scanIdp(rows)
		if err != nil {
			return nil, err
		}
		x.RedirectURI = s.idpRedirectURI()
		out = append(out, x)
	}
	return out, rows.Err()
}

func textList(v record.Values, key, label string, p *record.Problems) ([]string, bool) {
	raw, sent := v[key]
	if !sent || raw == nil {
		return nil, sent
	}
	list, ok := raw.([]any)
	if !ok {
		p.Add(key, label+" harus berupa daftar.")
		return nil, true
	}
	out := []string{}
	for _, x := range list {
		s, _ := x.(string)
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, true
}

// SaveIdp adds (code "") or changes an identity provider (POST /auth/identity-providers, PUT …/{code}). The client
// secret is written only when sent (empty keeps it).
func (s *Service) SaveIdp(ctx context.Context, code string, body record.Values) (*IdentityProvider, error) {
	me, err := Require(ctx, "auth.security", "update")
	if err != nil {
		return nil, err
	}
	ctx = me.ctx(ctx)
	var out *IdentityProvider
	err = s.DB.InTx(ctx, func(ctx context.Context) error {
		var stored *IdentityProvider
		var p record.Problems
		if code != "" {
			if stored, err = s.idp(ctx, me.TenantID, code, true); err != nil {
				return err
			}
			if want, ok := record.ExpectedVersion(body, &p); ok && want != stored.Version {
				return apperr.Conflict("STALE", fmt.Sprintf("Penyedia identitas %s sudah diubah administrator lain. Muat ulang, lalu ulangi perubahan Anda.", stored.Name))
			}
		}
		name := record.RequiredText(body, "name", "Nama", record.MaxName, &p)
		desc := record.OptionalText(body, "description", "Deskripsi", record.MaxDescription, &p)
		kind := record.RequiredText(body, "kind", "Jenis", 20, &p)
		if kind != "" && !slices.Contains(idpKinds, kind) {
			p.Add("kind", "Jenis: azure_ad, google, atau oidc.")
		}
		issuer := record.RequiredText(body, "issuer", "Issuer", 300, &p)
		if u, err := url.Parse(issuer); issuer != "" && (err != nil || u.Scheme != "https" || u.Host == "") {
			p.Add("issuer", "Issuer harus alamat https://, mis. https://login.microsoftonline.com/<tenant>/v2.0.")
		}
		clientID := record.RequiredText(body, "clientId", "Client ID", 200, &p)
		secret, _ := body["clientSecret"].(string)
		if len(secret) > 500 {
			p.Add("clientSecret", "Client secret terlalu panjang.")
		}
		if stored == nil && secret == "" {
			p.Add("clientSecret", "Client secret wajib diisi.")
		}
		scopes, _ := textList(body, "scopes", "Scope", &p)
		if len(scopes) == 0 {
			scopes = []string{"openid", "profile", "email"}
		}
		if !slices.Contains(scopes, "openid") {
			p.Add("scopes", "Scope openid wajib.")
		}
		domains, _ := textList(body, "emailDomains", "Domain email", &p)
		for _, d := range domains {
			if !domainPattern.MatchString(d) {
				p.Add("emailDomains", fmt.Sprintf("Domain %s tidak sah, mis. perusahaan.co.id.", d))
			}
		}
		claim := func(key, label, def string) string {
			c, _ := body[key].(string)
			if c = strings.TrimSpace(c); c == "" {
				return def
			}
			if !claimPattern.MatchString(c) {
				p.Add(key, label+" tidak sah.")
			}
			return c
		}
		subject, email, nameClaim := claim("subjectClaim", "Klaim subject", "sub"), claim("emailClaim", "Klaim email", "email"), claim("nameClaim", "Klaim nama", "name")
		if kind == "azure_ad" && subject == "sub" {
			subject = "oid" // the stable object id of an Entra ID account
		}
		jit := record.Bool(body, "jitProvisioning", "Buat anggota saat login pertama", false, &p)
		active := record.Bool(body, "active", "Status aktif", true, &p)
		var roleID *string
		if rc := record.OptionalText(body, "defaultRole", "Peran awal", record.MaxCode, &p); rc != nil {
			var id string
			switch {
			case *rc == "admin":
				p.Add("defaultRole", "Anggota baru dari penyedia identitas tidak boleh langsung menjadi Admin.")
			case s.DB.Q(ctx).QueryRow(ctx, `SELECT id FROM auth.role WHERE tenant_id = $1 AND code = $2 AND is_active AND NOT is_deleted`, me.TenantID, *rc).Scan(&id) != nil:
				p.Add("defaultRole", "Peran tidak tersedia.")
			default:
				roleID = &id
			}
		}
		if jit && roleID == nil && !p.Has("defaultRole") {
			p.Add("defaultRole", "Pembuatan anggota otomatis butuh peran awal.")
		}
		// An email domain routes to one provider of the installation while it is active.
		if active && len(domains) > 0 && !p.Has("emailDomains") {
			self := ""
			if stored != nil {
				self = stored.id
			}
			var taken, owner string
			err := s.DB.Q(ctx).QueryRow(ctx, `SELECT d, p.name FROM auth.identity_provider p, unnest(p.email_domains) d
				WHERE p.is_active AND NOT p.is_deleted AND p.id::text <> $1 AND d = ANY($2) LIMIT 1`, self, domains).Scan(&taken, &owner)
			if err == nil {
				p.Add("emailDomains", fmt.Sprintf("Domain %s sudah dipakai penyedia identitas lain.", taken))
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		if len(p) > 0 {
			return apperr.Validation(p)
		}
		var id string
		if stored == nil {
			c, err := codeprefix.NextFree(ctx, s.Codes, "identity_provider", func(ctx context.Context, c string) (bool, error) {
				var taken bool
				err := s.DB.Q(ctx).QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth.identity_provider WHERE tenant_id = $1 AND lower(code) = lower($2))`, me.TenantID, c).Scan(&taken)
				return taken, err
			})
			if err != nil {
				return err
			}
			if err := s.DB.Q(ctx).QueryRow(ctx, `INSERT INTO auth.identity_provider (tenant_id, code, name, description, kind, issuer, client_id, scopes, email_domains,
				subject_claim, email_claim, name_claim, jit_provisioning, default_role_id, is_active, created_by)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) RETURNING id`,
				me.TenantID, c, name, desc, kind, issuer, clientID, scopes, domains, subject, email, nameClaim, jit, roleID, active, me.UserID).Scan(&id); err != nil {
				return err
			}
			code = c
		} else {
			id = stored.id
			if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.identity_provider SET name = $2, description = $3, kind = $4, issuer = $5, client_id = $6, scopes = $7,
				email_domains = $8, subject_claim = $9, email_claim = $10, name_claim = $11, jit_provisioning = $12, default_role_id = $13, is_active = $14,
				updated_at = now(), updated_by = $15, version = version + 1 WHERE id = $1`,
				id, name, desc, kind, issuer, clientID, scopes, domains, subject, email, nameClaim, jit, roleID, active, me.UserID); err != nil {
				return err
			}
		}
		if secret != "" {
			hint := secret
			if len(hint) > 4 {
				hint = hint[len(hint)-4:]
			}
			if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.identity_provider SET client_secret_sealed = $2, secret_hint = $3 WHERE id = $1`,
				id, s.Box.Seal([]byte(secret), id), hint); err != nil {
				return err
			}
		}
		if out, err = s.idp(ctx, me.TenantID, code, false); err != nil {
			return err
		}
		out.RedirectURI = s.idpRedirectURI()
		s.audit(ctx, requestOf(ctx), "access_changed", me, out.Code, fmt.Sprintf("Penyedia identitas %s %s", out.Name, map[bool]string{true: "ditambahkan", false: "diubah"}[stored == nil]))
		return nil
	})
	return out, err
}

// DeleteIdp is a soft delete (DELETE /auth/identity-providers/{code}).
func (s *Service) DeleteIdp(ctx context.Context, code string) error {
	me, err := Require(ctx, "auth.security", "update")
	if err != nil {
		return err
	}
	return s.DB.InTx(ctx, func(ctx context.Context) error {
		x, err := s.idp(ctx, me.TenantID, code, true)
		if err != nil {
			return err
		}
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.identity_provider SET is_deleted = true, is_active = false, deleted_at = now(), deleted_by = $2,
			client_secret_sealed = NULL, updated_at = now(), updated_by = $2, version = version + 1 WHERE id = $1`, x.id, me.UserID); err != nil {
			return err
		}
		s.audit(ctx, requestOf(ctx), "access_changed", me, x.Code, fmt.Sprintf("Penyedia identitas %s dihapus", x.Name))
		return nil
	})
}

// idpSecret opens a provider's client secret (for the connectors of Stage 2).
func (s *Service) idpSecret(ctx context.Context, x *IdentityProvider) (string, error) {
	var sealed *string
	if err := s.DB.Q(ctx).QueryRow(ctx, `SELECT client_secret_sealed FROM auth.identity_provider WHERE id = $1`, x.id).Scan(&sealed); err != nil || sealed == nil {
		return "", err
	}
	b, err := s.Box.Open(*sealed, x.id)
	return string(b), err
}
