package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"alir.local/auth-service/internal/catalog"
	"alir.local/auth-service/internal/platform/apperr"
	"alir.local/auth-service/internal/platform/record"
)

// Applications that sign their users in through Authentication (OIDC clients), as the Aplikasi Terhubung page reads
// them (types/clients.ts). A company's administrator registers the company's applications; the platform
// administrator also manages the applications of the installation (platform: any company's members sign in).

// Scopes an application may ask for.
var knownScopes = []string{"openid", "profile", "email", "dod.access", "offline_access"}

// OAuthClient is an application (types/clients.ts OAuthClient) with what the backend adds.
type OAuthClient struct {
	ID                 string     `json:"id"` // the client_id
	Name               string     `json:"name"`
	Description        *string    `json:"description"`
	Module             *string    `json:"module"`
	RedirectURIs       []string   `json:"redirectUris"`
	PostLogoutURIs     []string   `json:"postLogoutUris"`
	Scopes             []string   `json:"scopes"`
	AccessTokenMinutes int        `json:"accessTokenMinutes"`
	RefreshTokenDays   int        `json:"refreshTokenDays"`
	Active             bool       `json:"active"`
	Public             bool       `json:"public"`      // browser/mobile app: no secret, PKCE only
	FirstParty         bool       `json:"firstParty"`  // part of ALIR itself
	Platform           bool       `json:"platform"`    // an application of the installation (every company)
	ServiceRole        *string    `json:"serviceRole"` // client_credentials allowed with this role's grants
	IDTokenAlg         string     `json:"idTokenAlg"`  // RS256 (default) | EdDSA
	SecretHint         *string    `json:"secretHint"`
	SecretRotatedAt    *time.Time `json:"secretRotatedAt"`
	LastUsedAt         *time.Time `json:"lastUsedAt"`
	UpdatedAt          *time.Time `json:"updatedAt"`
	UpdatedBy          *string    `json:"updatedBy"`
	Version            int        `json:"version"`
	uuid               string
	tenantID           *string
	secretHash         []byte
	serviceRoleID      *string
}

const clientSelect = `SELECT c.id, c.code, c.name, c.description, c.module, c.redirect_uris, c.post_logout_uris, c.scopes, c.access_token_minutes,
	c.refresh_token_days, c.is_active, c.is_public, c.is_first_party, c.tenant_id, r.code, c.secret_hint, c.secret_rotated_at, c.last_used_at,
	coalesce(c.updated_at, c.created_at), ub.name, c.version, c.secret_hash, c.service_role_id, c.id_token_alg
	FROM auth.oauth_client c LEFT JOIN auth.role r ON r.id = c.service_role_id LEFT JOIN auth.identity ub ON ub.id = coalesce(c.updated_by, c.created_by)`

func scanClient(row pgx.Row) (*OAuthClient, error) {
	var c OAuthClient
	var updated time.Time
	err := row.Scan(&c.uuid, &c.ID, &c.Name, &c.Description, &c.Module, &c.RedirectURIs, &c.PostLogoutURIs, &c.Scopes, &c.AccessTokenMinutes,
		&c.RefreshTokenDays, &c.Active, &c.Public, &c.FirstParty, &c.tenantID, &c.ServiceRole, &c.SecretHint, &c.SecretRotatedAt, &c.LastUsedAt,
		&updated, &c.UpdatedBy, &c.Version, &c.secretHash, &c.serviceRoleID, &c.IDTokenAlg)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	u := updated.UTC()
	c.UpdatedAt, c.SecretRotatedAt, c.LastUsedAt = &u, utc(c.SecretRotatedAt), utc(c.LastUsedAt)
	c.Platform = c.tenantID == nil
	return &c, err
}

// clientByID is a live application by client_id (any company; the OIDC endpoints).
func (s *Service) clientByID(ctx context.Context, clientID string) (*OAuthClient, error) {
	if clientID == "" || len(clientID) > 40 {
		return nil, apperr.NotFound()
	}
	return scanClient(s.DB.Q(ctx).QueryRow(ctx, clientSelect+` WHERE lower(c.code) = lower($1) AND NOT c.is_deleted`, clientID))
}

// adminClient is an application the administrator manages: their company's, or the installation's for the
// platform administrator.
func (s *Service) adminClient(ctx context.Context, me *Actor, clientID string, forUpdate bool) (*OAuthClient, error) {
	q := clientSelect + ` WHERE lower(c.code) = lower($1) AND NOT c.is_deleted AND (c.tenant_id = $2 OR ($3 AND c.tenant_id IS NULL))`
	if forUpdate {
		q += ` FOR UPDATE OF c`
	}
	return scanClient(s.DB.Q(ctx).QueryRow(ctx, q, clientID, me.TenantID, me.PlatformAdmin))
}

// secretOK compares a presented secret with the stored hash in constant time.
func (c *OAuthClient) secretOK(secret string) bool {
	return len(c.secretHash) > 0 && secret != "" && subtle.ConstantTimeCompare(hashOf(secret), c.secretHash) == 1
}

// ListClients is the administrator's applications (GET /auth/clients).
func (s *Service) ListClients(ctx context.Context) ([]*OAuthClient, error) {
	me, err := Require(ctx, "auth.clients", "read")
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.Q(ctx).Query(ctx, clientSelect+` WHERE NOT c.is_deleted AND (c.tenant_id = $1 OR ($2 AND c.tenant_id IS NULL))
		ORDER BY c.tenant_id IS NOT NULL, c.name`, me.TenantID, me.PlatformAdmin)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*OAuthClient{}
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// OidcConfig is what an application is configured with (GET /auth/oidc).
func (s *Service) OidcConfig(ctx context.Context) (map[string]string, error) {
	if _, err := Require(ctx, "auth.clients", "read"); err != nil {
		return nil, err
	}
	p := s.Cfg.PublicURL
	return map[string]string{"issuer": s.Cfg.Issuer, "discovery": p + "/.well-known/openid-configuration", "authorize": p + "/oauth2/authorize",
		"token": p + "/oauth2/token", "userinfo": p + "/oauth2/userinfo", "jwks": p + "/.well-known/jwks.json", "endSession": p + "/oauth2/logout",
		"revocation": p + "/oauth2/revoke"}, nil
}

type clientInput struct {
	Name                   string
	Description, Module    *string
	RedirectURIs, LogoutTo []string
	Scopes                 []string
	AccessMin, RefreshDays int
	Active, Public         bool
	Platform               bool
	ServiceRole            *string
	IDTokenAlg             string
}

// uriOK: https, or http on localhost (development); no fragment.
func uriOK(u string) bool {
	x, err := url.Parse(u)
	if err != nil || x.Fragment != "" || x.Host == "" || len(u) > 500 {
		return false
	}
	host := x.Hostname()
	return x.Scheme == "https" || x.Scheme == "http" && (host == "localhost" || host == "127.0.0.1")
}

func uris(v record.Values, key, label string, p *record.Problems) []string {
	raw, ok := v[key].([]any)
	if v[key] != nil && !ok {
		p.Add(key, label+" harus berupa daftar.")
		return nil
	}
	out := []string{}
	for _, x := range raw {
		s, _ := x.(string)
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !uriOK(s) {
			p.Add(key, "Setiap URI harus https:// (http://localhost hanya untuk pengembangan), tanpa #.")
			return nil
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if len(out) > 20 {
		p.Add(key, "Paling banyak 20 URI.")
	}
	return out
}

func parseClient(v record.Values, p *record.Problems) clientInput {
	in := clientInput{}
	in.Name = record.RequiredText(v, "name", "Nama", record.MaxName, p)
	if in.Name != "" && len([]rune(in.Name)) < 2 && !p.Has("name") {
		p.Add("name", "Nama minimal 2 karakter.")
	}
	in.Description = record.OptionalText(v, "description", "Deskripsi", record.MaxDescription, p)
	in.Module = record.OptionalText(v, "module", "Modul", 60, p)
	if in.Module != nil && !catalog.Known(*in.Module) {
		p.Add("module", fmt.Sprintf("Modul %s tidak dikenal.", *in.Module))
	}
	in.RedirectURIs = uris(v, "redirectUris", "Redirect URI", p)
	in.LogoutTo = uris(v, "postLogoutUris", "URI setelah keluar", p)
	in.Scopes = record.Codes(v, "scopes", "Scope", p)
	for _, sc := range in.Scopes {
		if !slices.Contains(knownScopes, sc) {
			p.Add("scopes", fmt.Sprintf("Scope %s tidak dikenal.", sc))
		}
	}
	in.AccessMin = record.RequiredInt(v, "accessTokenMinutes", "Masa access token", 5, p)
	in.RefreshDays = record.RequiredInt(v, "refreshTokenDays", "Masa refresh token", 0, p)
	if !p.Has("accessTokenMinutes") && !p.Has("refreshTokenDays") && (in.AccessMin > 120 || in.RefreshDays > 90) {
		p.Add("tokens", "Access token 5–120 menit; refresh token 0–90 hari.")
	}
	in.Active = record.Bool(v, "active", "Status aktif", true, p)
	in.Public = record.Bool(v, "public", "Aplikasi publik", false, p)
	in.Platform = record.Bool(v, "platform", "Aplikasi platform", false, p)
	in.ServiceRole = record.OptionalText(v, "serviceRole", "Peran layanan", record.MaxCode, p)
	in.IDTokenAlg = "RS256"
	if a, sent := v["idTokenAlg"]; sent && a != nil {
		if s, _ := a.(string); s == "RS256" || s == "EdDSA" {
			in.IDTokenAlg = s
		} else {
			p.Add("idTokenAlg", "Algoritma ID token: RS256 atau EdDSA.")
		}
	}
	return in
}

func newClientID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "app-" + strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(b), "="))
}

func newClientSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "sec_" + base64.RawURLEncoding.EncodeToString(b)
}

// SaveClient registers (clientID "") or changes an application. A new confidential application gets its secret
// in this answer only.
func (s *Service) SaveClient(ctx context.Context, clientID string, body record.Values) (*OAuthClient, string, error) {
	action := "create"
	if clientID != "" {
		action = "update"
	}
	me, err := Require(ctx, "auth.clients", action)
	if err != nil {
		return nil, "", err
	}
	var out *OAuthClient
	var secret string
	err = s.DB.InTx(ctx, func(ctx context.Context) error {
		var stored *OAuthClient
		var p record.Problems
		if clientID != "" {
			if stored, err = s.adminClient(ctx, me, clientID, true); err != nil {
				return err
			}
			if want, ok := record.ExpectedVersion(body, &p); ok && want != stored.Version {
				return apperr.Conflict("STALE", fmt.Sprintf("Aplikasi %s sudah diubah administrator lain. Muat ulang, lalu ulangi perubahan Anda.", stored.Name))
			}
		}
		in := parseClient(body, &p)
		keepRole := false
		if stored != nil {
			in.Public, in.Platform = stored.Public, stored.Platform // fixed once registered
			// A form that does not show these fields keeps them as they are.
			if _, sent := body["description"]; !sent {
				in.Description = stored.Description
			}
			if _, sent := body["serviceRole"]; !sent {
				in.ServiceRole, keepRole = stored.ServiceRole, true
			}
			if _, sent := body["idTokenAlg"]; !sent {
				in.IDTokenAlg = stored.IDTokenAlg
			}
		}
		if in.Platform && !me.PlatformAdmin {
			p.Add("platform", "Hanya administrator platform yang mendaftarkan aplikasi untuk semua perusahaan.")
		}
		if !slices.Contains(in.Scopes, "openid") {
			p.Add("scopes", "Scope openid wajib untuk login OIDC.")
		}
		if len(in.RedirectURIs) == 0 && !p.Has("redirectUris") {
			p.Add("redirectUris", "Isi minimal satu redirect URI.")
		}
		var roleID *string
		if keepRole {
			roleID = stored.serviceRoleID
		} else if in.ServiceRole != nil {
			switch {
			case in.Public || in.Platform:
				p.Add("serviceRole", "Akses layanan (client credentials) hanya untuk aplikasi rahasia milik satu perusahaan.")
			case *in.ServiceRole == "admin":
				p.Add("serviceRole", "Peran Admin tidak dapat dipakai sebagai peran layanan.")
			default:
				var id string
				err := s.DB.Q(ctx).QueryRow(ctx, `SELECT id FROM auth.role WHERE tenant_id = $1 AND code = $2 AND is_active AND NOT is_deleted`, me.TenantID, *in.ServiceRole).Scan(&id)
				if errors.Is(err, pgx.ErrNoRows) {
					p.Add("serviceRole", "Peran tidak tersedia.")
				} else if err != nil {
					return err
				}
				roleID = &id
			}
		}
		if len(p) > 0 {
			return apperr.Validation(p)
		}
		var tenant *string
		if !in.Platform {
			tenant = &me.TenantID
		}
		if stored == nil {
			code := newClientID()
			var hash []byte
			var hint *string
			if !in.Public {
				secret = newClientSecret()
				hash = hashOf(secret)
				h := secret[len(secret)-4:]
				hint = &h
			}
			if _, err := s.DB.Q(ctx).Exec(ctx, `INSERT INTO auth.oauth_client (code, name, description, tenant_id, module, is_public, redirect_uris, post_logout_uris,
				scopes, access_token_minutes, refresh_token_days, is_active, secret_hash, secret_hint, secret_rotated_at, service_role_id, created_by, id_token_alg)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, CASE WHEN $13::bytea IS NULL THEN NULL ELSE now() END, $15, $16, $17)`,
				code, in.Name, in.Description, tenant, in.Module, in.Public, in.RedirectURIs, in.LogoutTo, in.Scopes, in.AccessMin, in.RefreshDays,
				in.Active, hash, hint, roleID, me.UserID, in.IDTokenAlg); err != nil {
				return err
			}
			clientID = code
		} else {
			if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.oauth_client SET name = $2, description = $3, module = $4, redirect_uris = $5, post_logout_uris = $6,
				scopes = $7, access_token_minutes = $8, refresh_token_days = $9, is_active = $10, service_role_id = $11, updated_at = now(), updated_by = $12,
				id_token_alg = $13, version = version + 1 WHERE id = $1`, stored.uuid, in.Name, in.Description, in.Module, in.RedirectURIs, in.LogoutTo, in.Scopes, in.AccessMin,
				in.RefreshDays, in.Active, roleID, me.UserID, in.IDTokenAlg); err != nil {
				return err
			}
			if !in.Active {
				// A deactivated application holds nothing any more.
				if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.oauth_grant SET revoked_at = now() WHERE client_id = $1 AND revoked_at IS NULL`, stored.uuid); err != nil {
					return err
				}
			}
		}
		if out, err = s.adminClient(ctx, me, clientID, false); err != nil {
			return err
		}
		what := map[bool]string{true: "didaftarkan", false: "diubah"}[stored == nil]
		s.audit(ctx, requestOf(ctx), "access_changed", me, out.ID, fmt.Sprintf("Aplikasi %s %s", out.Name, what))
		return nil
	})
	return out, secret, err
}

// RotateSecret gives a confidential application a new secret; the old one stops working at once (POST
// /auth/clients/{id}/secret).
func (s *Service) RotateSecret(ctx context.Context, clientID string) (*OAuthClient, string, error) {
	me, err := Require(ctx, "auth.clients", "update")
	if err != nil {
		return nil, "", err
	}
	var out *OAuthClient
	secret := newClientSecret()
	err = s.DB.InTx(ctx, func(ctx context.Context) error {
		c, err := s.adminClient(ctx, me, clientID, true)
		if err != nil {
			return err
		}
		if c.Public {
			return apperr.Conflict("PUBLIC_CLIENT", "Aplikasi publik tidak memakai secret.")
		}
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.oauth_client SET secret_hash = $2, secret_hint = $3, secret_rotated_at = now(), updated_at = now(),
			updated_by = $4, version = version + 1 WHERE id = $1`, c.uuid, hashOf(secret), secret[len(secret)-4:], me.UserID); err != nil {
			return err
		}
		if out, err = s.adminClient(ctx, me, clientID, false); err != nil {
			return err
		}
		s.audit(ctx, requestOf(ctx), "access_changed", me, out.ID, fmt.Sprintf("Secret aplikasi %s diganti", out.Name))
		return nil
	})
	return out, secret, err
}

// ensureWebClient registers the ALIR web itself (the installation's first-party application) once.
func (s *Service) ensureWebClient(ctx context.Context) error {
	base := s.Cfg.AppBaseURL
	_, err := s.DB.Q(ctx).Exec(ctx, `INSERT INTO auth.oauth_client (code, name, description, is_public, is_first_party, redirect_uris, post_logout_uris, scopes,
		access_token_minutes, refresh_token_days, created_by)
		SELECT 'alir-web', 'ALIR Web', 'Aplikasi web ALIR (halaman login terpusat)', true, true, $1, $2, '{openid,profile,email,dod.access}', 15, 1, $3
		WHERE NOT EXISTS (SELECT 1 FROM auth.oauth_client WHERE lower(code) = 'alir-web')`,
		[]string{base + "/auth/callback"}, []string{base + "/login"}, SystemUserID)
	return err
}
