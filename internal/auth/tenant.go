package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"alir.local/auth-service/internal/catalog"
	"alir.local/auth-service/internal/password"
	"alir.local/auth-service/internal/platform/apperr"
	"alir.local/auth-service/internal/platform/record"
)

// A tenant is a company using ALIR. Every tenant has the built-in roles (with their default grants), its own
// security policy and its own generated codes; the platform administrator adds tenants and their first Admin.

// DefaultTenantID is the first tenant: the company whose data existed before tenants did.
const DefaultTenantID = "00000000-0000-7000-8000-0000000000a1"

var systemRoles = []struct{ code, name, description string }{
	{"admin", "Admin", "Semua menu, termasuk pengguna dan koneksi"},
	{"analyst", "Analyst", "Analisis, dataset, report, template"},
	{"publisher", "Publisher", "Menyetujui dan menayangkan halaman Publish"},
	{"viewer", "Viewer", "Melihat dashboard dan analisis"},
}

// Provision prepares a tenant (idempotent): the built-in roles, the default grants of the built-in roles when the
// tenant has no grant at all, the security policy, the code prefixes.
func (s *Service) Provision(ctx context.Context, tenantID string) error {
	return s.DB.InTx(ctx, func(ctx context.Context) error {
		q := s.DB.Q(ctx)
		for _, r := range systemRoles {
			if _, err := q.Exec(ctx, `INSERT INTO auth.role (tenant_id, code, name, description, is_system, created_by)
				SELECT $1::uuid, $2::text, $3::text, $4::text, true, $5::uuid WHERE NOT EXISTS (SELECT 1 FROM auth.role WHERE tenant_id = $1::uuid AND lower(code) = $2::text)`,
				tenantID, r.code, r.name, r.description, SystemUserID); err != nil {
				return err
			}
		}
		var grants int
		if err := q.QueryRow(ctx, `SELECT count(*) FROM auth.role_grant g JOIN auth.role r ON r.id = g.role_id WHERE r.tenant_id = $1`, tenantID).Scan(&grants); err != nil {
			return err
		}
		if grants == 0 {
			for _, code := range []string{"analyst", "publisher", "viewer"} {
				g, err := catalog.Check(catalog.Default(code))
				if err != nil {
					return fmt.Errorf("default grants of %s: %w", code, err)
				}
				for _, menu := range g.Menus() {
					if _, err := q.Exec(ctx, `INSERT INTO auth.role_grant (role_id, menu, actions) SELECT id, $3, $4 FROM auth.role
						WHERE tenant_id = $1 AND code = $2 AND NOT is_deleted`, tenantID, code, menu, g[menu]); err != nil {
						return err
					}
				}
			}
		}
		if _, err := q.Exec(ctx, `INSERT INTO auth.security_policy (tenant_id) VALUES ($1) ON CONFLICT (tenant_id) DO NOTHING`, tenantID); err != nil {
			return err
		}
		for _, p := range []struct {
			code, name, description, prefix string
			digits                          int
		}{
			{"role", "Peran", "Kode peran baru: MRL001, …", "MRL", 3},
			{"membership", "Anggota", "Kode anggota baru: MUS0001, …", "MUS", 4},
			{"identity_provider", "Penyedia Identitas", "Kode penyedia identitas baru: IDP001, …", "IDP", 3},
		} {
			if _, err := q.Exec(ctx, `INSERT INTO auth.code_prefix (tenant_id, code, name, description, prefix, digits, created_by)
				SELECT $1::uuid, $2::text, $3::text, $4::text, $5::text, $6::int, $7::uuid WHERE NOT EXISTS (SELECT 1 FROM auth.code_prefix WHERE tenant_id = $1::uuid AND lower(code) = $2::text)`,
				tenantID, p.code, p.name, p.description, p.prefix, p.digits, SystemUserID); err != nil {
				return err
			}
		}
		return nil
	})
}

// Bootstrap prepares the database on start: every tenant provisioned, and the first administrator when there is
// no identity at all (AUTH_ADMIN_USERNAME / AUTH_ADMIN_PASSWORD): a platform administrator and the Admin of the
// first tenant, who must change the password at the first sign-in.
func (s *Service) Bootstrap(ctx context.Context) (string, error) {
	return "", s.DB.InTx(ctx, func(ctx context.Context) error {
		if _, err := s.DB.Q(ctx).Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('auth.bootstrap'))`); err != nil {
			return err
		}
		rows, err := s.DB.Q(ctx).Query(ctx, `SELECT id::text FROM auth.tenant WHERE NOT is_deleted ORDER BY created_at`)
		if err != nil {
			return err
		}
		var tenants []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			tenants = append(tenants, id)
		}
		rows.Close()
		if len(tenants) == 0 {
			return errors.New("no tenant: run the migrations (000003 adds the first one)")
		}
		for _, t := range tenants {
			if err := s.Provision(ctx, t); err != nil {
				return err
			}
		}
		if err := s.ensureWebClient(ctx); err != nil {
			return err
		}
		var identities int
		if err := s.DB.Q(ctx).QueryRow(ctx, `SELECT count(*) FROM auth.identity`).Scan(&identities); err != nil {
			return err
		}
		if identities > 0 {
			return nil
		}
		if s.Cfg.AdminPassword == "" {
			return fmt.Errorf("no account yet: set AUTH_ADMIN_PASSWORD for the first administrator (%s)", s.Cfg.AdminUsername)
		}
		if msg := (password.Rules{MinLength: 8, RequireNumber: true}).Problem(s.Cfg.AdminPassword); msg != "" {
			return fmt.Errorf("AUTH_ADMIN_PASSWORD: %s", msg)
		}
		hash, err := password.Hash(s.Cfg.AdminPassword)
		if err != nil {
			return err
		}
		var iid string
		if err := s.DB.Q(ctx).QueryRow(ctx, `INSERT INTO auth.identity (name, password_hash, is_platform_admin, must_change_password, password_changed_at, created_by)
			VALUES ('Administrator', $1, true, 'first', now(), $2) RETURNING id`, hash, SystemUserID).Scan(&iid); err != nil {
			return err
		}
		_, err = s.DB.Q(ctx).Exec(ctx, `INSERT INTO auth.membership (tenant_id, identity_id, code, name, username, role_id, created_by)
			SELECT $1, $2, 'MUS0000', 'Administrator', $3, id, $4 FROM auth.role WHERE tenant_id = $1 AND code = 'admin'`, tenants[0], iid, s.Cfg.AdminUsername, SystemUserID)
		return err
	})
}

func isUnique(err error, constraint string) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505" && (constraint == "" || pg.ConstraintName == constraint)
}

/* ---------------- Platform administration: tenants ---------------- */

// Tenant is a company as the platform page reads it.
type Tenant struct {
	ID          string     `json:"id"`
	Code        string     `json:"code"`
	Name        string     `json:"name"`
	Description *string    `json:"description"`
	Active      bool       `json:"active"`
	Members     int        `json:"members"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   *time.Time `json:"updatedAt"`
	Version     int        `json:"version"`
}

func requirePlatform(ctx context.Context) (*Actor, error) {
	a := ActorFrom(ctx)
	if a == nil {
		return nil, unauthorized("SIGNED_OUT", "Sesi tidak ditemukan. Silakan masuk kembali.")
	}
	if a.MustChange != nil {
		return nil, &apperr.Error{Status: http.StatusForbidden, Code: "MUST_CHANGE_PASSWORD", Message: "Ganti password Anda terlebih dahulu."}
	}
	if !a.PlatformAdmin {
		return nil, apperr.Forbidden()
	}
	return a, nil
}

const tenantSelect = `SELECT t.id, t.code, t.name, t.description, t.is_active, (SELECT count(*) FROM auth.membership m WHERE m.tenant_id = t.id AND NOT m.is_deleted),
	t.created_at, t.updated_at, t.version FROM auth.tenant t`

func scanTenant(row pgx.Row) (Tenant, error) {
	var t Tenant
	err := row.Scan(&t.ID, &t.Code, &t.Name, &t.Description, &t.Active, &t.Members, &t.CreatedAt, &t.UpdatedAt, &t.Version)
	t.CreatedAt, t.UpdatedAt = t.CreatedAt.UTC(), utc(t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, apperr.NotFound()
	}
	return t, err
}

func (s *Service) ListTenants(ctx context.Context) ([]Tenant, error) {
	if _, err := requirePlatform(ctx); err != nil {
		return nil, err
	}
	rows, err := s.DB.Q(ctx).Query(ctx, tenantSelect+` WHERE NOT t.is_deleted ORDER BY t.name, t.code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Tenant{}
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

var tenantCodePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// reservedCodes cannot name a company: they are addresses of the installation itself.
var reservedCodes = map[string]bool{"www": true, "api": true, "auth": true, "admin": true, "platform": true, "app": true, "login": true, "static": true}

// CreateTenant adds a company and its first Admin (POST /platform/tenants {code, name, description, admin:
// {username, name, email, password}}). The Admin is the person with that email when they already have an ALIR
// identity (they keep their password), else a new identity that must change the typed password.
func (s *Service) CreateTenant(ctx context.Context, body record.Values) (Tenant, error) {
	me, err := requirePlatform(ctx)
	if err != nil {
		return Tenant{}, err
	}
	var p record.Problems
	code := strings.ToLower(record.RequiredText(body, "code", "Kode perusahaan", record.MaxCode, &p))
	if code != "" && !p.Has("code") && (!tenantCodePattern.MatchString(code) || reservedCodes[code]) {
		p.Add("code", "Kode perusahaan berisi huruf kecil, angka atau - (dipakai sebagai alamat), dan bukan kata yang dicadangkan.")
	}
	name := record.RequiredText(body, "name", "Nama perusahaan", record.MaxName, &p)
	desc := record.OptionalText(body, "description", "Deskripsi", record.MaxDescription, &p)
	adm, _ := body["admin"].(map[string]any)
	if adm == nil {
		adm = map[string]any{}
	}
	av := record.Values(adm)
	var ap record.Problems
	username := strings.ToLower(record.RequiredText(av, "username", "Username Admin", 60, &ap))
	if username != "" && !ap.Has("username") && !usernamePattern.MatchString(username) {
		ap.Add("username", "Username berisi huruf kecil, angka, titik, - atau _ tanpa spasi.")
	}
	adminName := record.RequiredText(av, "name", "Nama Admin", record.MaxName, &ap)
	email := parseEmail(av, "email", &ap)
	if email == nil && !ap.Has("email") {
		ap.Add("email", "Email Admin wajib diisi.")
	}
	pw, _ := av["password"].(string)
	for _, x := range ap {
		p.Add("admin."+x.Field, x.Message)
	}
	var out Tenant
	err = s.DB.InTx(ctx, func(ctx context.Context) error {
		if code != "" && !p.Has("code") {
			var taken bool
			if err := s.DB.Q(ctx).QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth.tenant WHERE lower(code) = $1)`, code).Scan(&taken); err != nil {
				return err
			}
			if taken {
				p.Add("code", "Kode perusahaan sudah dipakai.")
			}
		}
		identityID := ""
		if email != nil {
			if identityID, err = s.identityByEmail(ctx, *email); err != nil {
				return err
			}
		}
		existed := identityID != ""
		if identityID == "" {
			if pw == "" {
				p.Add("admin.password", "Password awal Admin wajib diisi (orang dengan email ini belum punya akun ALIR).")
			} else if msg := (password.Rules{MinLength: 8, RequireNumber: true}).Problem(pw); msg != "" {
				p.Add("admin.password", fmt.Sprintf("Password belum memenuhi: %s.", strings.ToLower(msg)))
			}
		}
		if len(p) > 0 {
			return apperr.Validation(p)
		}
		var tid string
		if err := s.DB.Q(ctx).QueryRow(ctx, `INSERT INTO auth.tenant (code, name, description, created_by) VALUES ($1, $2, $3, $4) RETURNING id`,
			code, name, desc, me.UserID).Scan(&tid); err != nil {
			if isUnique(err, "") {
				return apperr.Validation([]apperr.Problem{{Field: "code", Message: "Kode perusahaan sudah dipakai."}})
			}
			return err
		}
		if err := s.Provision(ctx, tid); err != nil {
			return err
		}
		if identityID == "" {
			hash, err := password.Hash(pw)
			if err != nil {
				return err
			}
			if err := s.DB.Q(ctx).QueryRow(ctx, `INSERT INTO auth.identity (name, email, password_hash, must_change_password, password_changed_at, created_by)
				VALUES ($1, $2, $3, 'first', now(), $4) RETURNING id`, adminName, *email, hash, me.UserID).Scan(&identityID); err != nil {
				return uniqueEmail(err)
			}
		}
		var mid string
		if err := s.DB.Q(ctx).QueryRow(ctx, `INSERT INTO auth.membership (tenant_id, identity_id, code, name, username, role_id, created_by)
			SELECT $1, $2, 'MUS0000', $3, $4, id, $5 FROM auth.role WHERE tenant_id = $1 AND code = 'admin' RETURNING id`,
			tid, identityID, adminName, username, me.UserID).Scan(&mid); err != nil {
			return err
		}
		s.auditIn(ctx, requestOf(ctx), "", "tenant_created", me, code, fmt.Sprintf("Perusahaan %s ditambahkan; Admin %s", name, username))
		s.auditIn(ctx, requestOf(ctx), tid, "user_created", me, username, "Admin pertama perusahaan")
		if u, err := s.userByID(ctx, tid, mid, false); err == nil {
			s.mailAccountCreated(ctx, u, *email, existed)
		}
		out, err = scanTenant(s.DB.Q(ctx).QueryRow(ctx, tenantSelect+` WHERE t.id = $1`, tid))
		return err
	})
	return out, err
}

// UpdateTenant changes a company's name, description and status (PUT /platform/tenants/{id}). A deactivated
// company signs no one in, and its sessions end.
func (s *Service) UpdateTenant(ctx context.Context, id string, body record.Values) (Tenant, error) {
	me, err := requirePlatform(ctx)
	if err != nil {
		return Tenant{}, err
	}
	if !uuidLike.MatchString(id) {
		return Tenant{}, apperr.NotFound()
	}
	var out Tenant
	err = s.DB.InTx(ctx, func(ctx context.Context) error {
		stored, err := scanTenant(s.DB.Q(ctx).QueryRow(ctx, tenantSelect+` WHERE t.id = $1 AND NOT t.is_deleted FOR UPDATE OF t`, id))
		if err != nil {
			return err
		}
		var p record.Problems
		if want, ok := record.ExpectedVersion(body, &p); ok && want != stored.Version {
			return apperr.Conflict("STALE", fmt.Sprintf("Perusahaan %s sudah diubah administrator lain. Muat ulang, lalu ulangi perubahan Anda.", stored.Name))
		}
		name := record.RequiredText(body, "name", "Nama perusahaan", record.MaxName, &p)
		desc := record.OptionalText(body, "description", "Deskripsi", record.MaxDescription, &p)
		active := record.Bool(body, "active", "Status aktif", true, &p)
		if !active && id == me.TenantID {
			p.Add("active", "Perusahaan yang sedang Anda pakai tidak dapat dinonaktifkan; pindah ke perusahaan lain dulu.")
		}
		if len(p) > 0 {
			return apperr.Validation(p)
		}
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.tenant SET name = $2, description = $3, is_active = $4, updated_at = now(), updated_by = $5,
			version = version + 1 WHERE id = $1`, id, name, desc, active, me.UserID); err != nil {
			return err
		}
		if !active {
			if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.session SET revoked_at = now() WHERE tenant_id = $1 AND revoked_at IS NULL`, id); err != nil {
				return err
			}
		}
		detail := "Data perusahaan diubah"
		if stored.Active != active {
			detail = map[bool]string{true: "Perusahaan diaktifkan", false: "Perusahaan dinonaktifkan; sesinya diakhiri"}[active]
		}
		s.auditIn(ctx, requestOf(ctx), "", "tenant_updated", me, stored.Code, detail)
		out, err = scanTenant(s.DB.Q(ctx).QueryRow(ctx, tenantSelect+` WHERE t.id = $1`, id))
		return err
	})
	return out, err
}
