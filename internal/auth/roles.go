package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"alir.local/auth-service/internal/catalog"
	"alir.local/auth-service/internal/platform/apperr"
	"alir.local/auth-service/internal/platform/codeprefix"
	"alir.local/auth-service/internal/platform/record"
)

var errNoRole = errors.New("no such role")

// RoleDef is a role as the roles page reads it (types/roles.ts), with the standard id and version.
type RoleDef struct {
	ID          string     `json:"id"`
	Code        string     `json:"code"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	System      bool       `json:"system"`
	Active      bool       `json:"active"`
	UserCount   int        `json:"userCount"`
	UpdatedAt   *time.Time `json:"updatedAt"`
	UpdatedBy   *string    `json:"updatedBy"`
	Version     int        `json:"version"`
}

const roleSelect = `SELECT r.id, r.code, r.name, coalesce(r.description, ''), r.is_system, r.is_active,
	(SELECT count(*) FROM auth.membership u WHERE u.role_id = r.id AND NOT u.is_deleted), r.updated_at, ub.name, r.version
	FROM auth.role r LEFT JOIN auth.identity ub ON ub.id = r.updated_by`

func scanRole(row pgx.Row) (RoleDef, error) {
	var x RoleDef
	err := row.Scan(&x.ID, &x.Code, &x.Name, &x.Description, &x.System, &x.Active, &x.UserCount, &x.UpdatedAt, &x.UpdatedBy, &x.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return x, errNoRole
	}
	x.UpdatedAt = utc(x.UpdatedAt)
	return x, err
}

// role is a live role of the tenant.
func (s *Service) role(ctx context.Context, tenantID, code string, forUpdate bool) (RoleDef, error) {
	q := roleSelect + ` WHERE r.tenant_id = $1 AND r.code = $2 AND NOT r.is_deleted`
	if forUpdate {
		q += ` FOR UPDATE OF r`
	}
	return scanRole(s.DB.Q(ctx).QueryRow(ctx, q, tenantID, code))
}

func (s *Service) ListRoles(ctx context.Context) ([]RoleDef, error) {
	// The users form lists the roles too: readable with auth.users or auth.roles.
	a := ActorFrom(ctx)
	if a == nil || !a.Access.May("auth.roles", "read") && !a.Access.May("auth.users", "read") {
		_, err := Require(ctx, "auth.roles", "read")
		return nil, err
	}
	rows, err := s.DB.Q(ctx).Query(ctx, roleSelect+` WHERE r.tenant_id = $1 AND NOT r.is_deleted ORDER BY NOT r.is_system, r.name`, a.TenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RoleDef{}
	for rows.Next() {
		x, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// SaveRole adds (code "") or changes a role. The code is generated (MRL001) and fixed; a built-in role stays active.
func (s *Service) SaveRole(ctx context.Context, code string, body record.Values) (RoleDef, error) {
	action := "create"
	if code != "" {
		action = "update"
	}
	me, err := Require(ctx, "auth.roles", action)
	if err != nil {
		return RoleDef{}, err
	}
	ctx = me.ctx(ctx)
	var out RoleDef
	err = s.DB.InTx(ctx, func(ctx context.Context) error {
		var stored *RoleDef
		var p record.Problems
		if code != "" {
			x, err := s.role(ctx, me.TenantID, code, true)
			if err != nil {
				return notFound(err)
			}
			stored = &x
			if want, ok := record.ExpectedVersion(body, &p); ok && want != x.Version {
				return apperr.Conflict("STALE", fmt.Sprintf("Peran %s sudah diubah administrator lain. Muat ulang, lalu ulangi perubahan Anda.", x.Name))
			}
		}
		name := record.RequiredText(body, "name", "Nama", record.MaxName, &p)
		desc := record.OptionalText(body, "description", "Deskripsi", record.MaxDescription, &p)
		active := record.Bool(body, "active", "Status aktif", true, &p)
		if stored != nil && stored.System {
			active = true
		}
		if stored != nil && stored.Active && !active && stored.UserCount > 0 {
			p.Add("active", fmt.Sprintf("Peran ini masih dipakai %d pengguna; pindahkan mereka ke peran lain dulu.", stored.UserCount))
		}
		if len(p) > 0 {
			return apperr.Validation(p)
		}
		if stored == nil {
			c, err := codeprefix.NextFree(ctx, s.Codes, "role", func(ctx context.Context, c string) (bool, error) {
				var taken bool
				err := s.DB.Q(ctx).QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth.role WHERE tenant_id = $1 AND lower(code) = lower($2))`, me.TenantID, c).Scan(&taken)
				return taken, err
			})
			if err != nil {
				return err
			}
			if _, err := s.DB.Q(ctx).Exec(ctx, `INSERT INTO auth.role (tenant_id, code, name, description, is_active, created_by, updated_at, updated_by)
				VALUES ($6, $1, $2, $3, $4, $5, now(), $5)`, c, name, desc, active, me.UserID, me.TenantID); err != nil {
				return err
			}
			code = c
		} else if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.role SET name = $2, description = $3, is_active = $4, updated_at = now(), updated_by = $5,
			version = version + 1 WHERE id = $1`, stored.ID, name, desc, active, me.UserID); err != nil {
			return err
		}
		if out, err = s.role(ctx, me.TenantID, code, false); err != nil {
			return err
		}
		what := "ditambahkan"
		if stored != nil {
			what = "diubah"
		}
		s.audit(ctx, requestOf(ctx), "access_changed", me, "", fmt.Sprintf("Peran %s %s", out.Name, what))
		return nil
	})
	return out, err
}

func (s *Service) DeleteRole(ctx context.Context, code string) error {
	me, err := Require(ctx, "auth.roles", "delete")
	if err != nil {
		return err
	}
	return s.DB.InTx(ctx, func(ctx context.Context) error {
		x, err := s.role(ctx, me.TenantID, code, true)
		if err != nil {
			return notFound(err)
		}
		if x.System {
			return apperr.Conflict("SYSTEM_ROLE", "Peran bawaan tidak dapat dihapus.")
		}
		if x.UserCount > 0 {
			return apperr.InUse(fmt.Sprintf("Peran %s masih dipakai %d pengguna; tidak dapat dihapus. Nonaktifkan atau pindahkan penggunanya dulu.", x.Name, x.UserCount))
		}
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.role SET is_deleted = true, is_active = false, deleted_at = now(), deleted_by = $2,
			updated_at = now(), updated_by = $2, version = version + 1 WHERE id = $1`, x.ID, me.UserID); err != nil {
			return err
		}
		s.audit(ctx, requestOf(ctx), "access_changed", me, "", fmt.Sprintf("Peran %s dihapus", x.Name))
		return nil
	})
}

// RolePermissions is the grants of a role (types/permissions.ts RolePermissions); Admin is everything, locked.
type RolePermissions struct {
	Role      string         `json:"role"`
	Grants    catalog.Grants `json:"grants"`
	Locked    bool           `json:"locked"`
	UpdatedAt *time.Time     `json:"updatedAt"`
	UpdatedBy *string        `json:"updatedBy"`
}

func (s *Service) permissions(ctx context.Context, x RoleDef) (RolePermissions, error) {
	if x.Code == "admin" {
		return RolePermissions{Role: x.Code, Grants: catalog.Full(), Locked: true}, nil
	}
	out := RolePermissions{Role: x.Code, Grants: catalog.Grants{}, UpdatedAt: x.UpdatedAt, UpdatedBy: x.UpdatedBy}
	rows, err := s.DB.Q(ctx).Query(ctx, `SELECT menu, actions FROM auth.role_grant WHERE role_id = $1`, x.ID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var menu string
		var actions []string
		if err := rows.Scan(&menu, &actions); err != nil {
			return out, err
		}
		out.Grants[menu] = actions
	}
	return out, rows.Err()
}

func (s *Service) GetPermissions(ctx context.Context, code string) (RolePermissions, error) {
	me, err := Require(ctx, "auth.roles", "read")
	if err != nil {
		return RolePermissions{}, err
	}
	x, err := s.role(ctx, me.TenantID, code, false)
	if err != nil {
		return RolePermissions{}, notFound(err)
	}
	return s.permissions(ctx, x)
}

// SetPermissions replaces the grants of a role (PUT /roles/:code/permissions {grants}).
func (s *Service) SetPermissions(ctx context.Context, code string, body record.Values) (RolePermissions, error) {
	me, err := Require(ctx, "auth.roles", "update")
	if err != nil {
		return RolePermissions{}, err
	}
	raw, ok := body["grants"].(map[string]any)
	if !ok {
		return RolePermissions{}, apperr.Validation([]apperr.Problem{{Field: "grants", Message: "Hak akses harus berupa daftar menu dan aksi."}})
	}
	g := catalog.Grants{}
	for menu, x := range raw {
		list, ok := x.([]any)
		if !ok {
			return RolePermissions{}, apperr.Validation([]apperr.Problem{{Field: "grants", Message: fmt.Sprintf("Aksi menu %s harus berupa daftar.", menu)}})
		}
		for _, a := range list {
			if s, ok := a.(string); ok {
				g[menu] = append(g[menu], s)
			}
		}
	}
	checked, err := catalog.Check(g)
	if err != nil {
		return RolePermissions{}, apperr.Validation([]apperr.Problem{{Field: "grants", Message: err.Error()}})
	}
	var out RolePermissions
	err = s.DB.InTx(ctx, func(ctx context.Context) error {
		x, err := s.role(ctx, me.TenantID, code, true)
		if err != nil {
			return notFound(err)
		}
		if x.Code == "admin" {
			return apperr.Conflict("LOCKED", "Hak akses Admin tidak dapat diubah.")
		}
		if _, err := s.DB.Q(ctx).Exec(ctx, `DELETE FROM auth.role_grant WHERE role_id = $1`, x.ID); err != nil {
			return err
		}
		for _, menu := range checked.Menus() {
			if _, err := s.DB.Q(ctx).Exec(ctx, `INSERT INTO auth.role_grant (role_id, menu, actions) VALUES ($1, $2, $3)`, x.ID, menu, checked[menu]); err != nil {
				return err
			}
		}
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.role SET updated_at = now(), updated_by = $2, version = version + 1 WHERE id = $1`, x.ID, me.UserID); err != nil {
			return err
		}
		if x, err = s.role(ctx, me.TenantID, code, false); err != nil {
			return err
		}
		if out, err = s.permissions(ctx, x); err != nil {
			return err
		}
		s.audit(ctx, requestOf(ctx), "access_changed", me, "", fmt.Sprintf("Hak akses peran %s diubah", x.Name))
		return nil
	})
	return out, err
}
