package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"alir.local/auth-service/internal/password"
	"alir.local/auth-service/internal/platform/apperr"
	"alir.local/auth-service/internal/platform/codeprefix"
	"alir.local/auth-service/internal/platform/record"
)

var errNoUser = errors.New("no such user")

// userRow is a member as stored: the membership (the person in one tenant: username, role, scope, employee) with
// its identity (the person: password, lockout, email) and its tenant. ID is the membership id.
type userRow struct {
	ID, Code, Username, Name     string
	TenantID, TenantCode         string
	TenantName                   string
	TenantActive                 bool
	IdentityID                   string
	IdentityActive               bool
	PlatformAdmin                bool
	Email                        *string // the identity's sign-in email
	Kind                         string
	PasswordHash                 *string
	RoleID, RoleCode, RoleName   string
	RoleActive                   bool
	Level, Ownership             *string
	Scope                        Scope
	IdentityIssuer, ExternalSub  *string
	EmployeeID, EmployeeCode     *string
	Active, Deleted              bool
	FailedLogins                 int
	LockedUntil                  *time.Time
	Locked                       bool // locked_until is after the database's now()
	LockMinutes                  int  // minutes left of the lock
	MustChange                   *string
	PasswordChangedAt, LastLogin *time.Time
	CreatedAt                    time.Time
	UpdatedAt                    *time.Time
	UpdatedByID, UpdatedByName   *string
	Version                      int
	VerifiedAt                   *time.Time // verified by the company or its application
	MfaEnrolled                  bool       // the person has a confirmed authenticator
	MfaMode                      string     // the company's MFA policy
}

// mustEnroll: the company requires MFA and the person has not enrolled yet.
func (u *userRow) mustEnroll() bool { return u.MfaMode == "required" && !u.MfaEnrolled }

// usable: the membership, the person and the company are all active.
func (u *userRow) usable() bool { return u.Active && !u.Deleted && u.IdentityActive && u.TenantActive }

const userColumns = `u.id, u.code, u.username, u.name, i.password_hash, r.id, r.code, r.name, r.is_active, u.level_code, u.ownership_code,
	u.owner_code, u.group_code, u.region_code, u.wilayah_code, u.gmk_code, u.company_code, u.operational_unit_code,
	u.org_level1_code, u.org_level2_code, u.org_level3_code, l.issuer, l.subject, u.is_active, u.is_deleted,
	i.failed_logins, i.locked_until, i.must_change_password, i.password_changed_at, u.last_login_at, u.created_at, u.updated_at,
	u.updated_by, ub.name, u.version, coalesce(i.locked_until > now(), false),
	greatest(0, ceil(extract(epoch FROM (i.locked_until - now())) / 60))::int, u.employee_id, u.employee_code,
	u.tenant_id, t.code, t.name, t.is_active AND NOT t.is_deleted, u.identity_id, i.is_active AND NOT i.is_deleted, i.is_platform_admin,
	i.email, u.kind, u.verified_at,
	EXISTS (SELECT 1 FROM auth.mfa_factor f WHERE f.identity_id = i.id AND f.confirmed_at IS NOT NULL),
	coalesce((SELECT p.mfa_mode FROM auth.security_policy p WHERE p.tenant_id = u.tenant_id), 'optional')`

const userFrom = ` FROM auth.membership u JOIN auth.identity i ON i.id = u.identity_id JOIN auth.tenant t ON t.id = u.tenant_id
	JOIN auth.role r ON r.id = u.role_id LEFT JOIN auth.identity ub ON ub.id = u.updated_by
	LEFT JOIN LATERAL (SELECT issuer, subject FROM auth.identity_link x WHERE x.identity_id = i.id ORDER BY x.created_at LIMIT 1) l ON true`

func scanUser(row pgx.Row) (*userRow, error) {
	var u userRow
	sc := &u.Scope
	err := row.Scan(&u.ID, &u.Code, &u.Username, &u.Name, &u.PasswordHash, &u.RoleID, &u.RoleCode, &u.RoleName, &u.RoleActive, &u.Level, &u.Ownership,
		&sc.OwnerCode, &sc.GroupCode, &sc.RegionCode, &sc.WilayahCode, &sc.GmkCode, &sc.CompanyCode, &sc.OperationalUnitCode,
		&sc.OrgLevel1Code, &sc.OrgLevel2Code, &sc.OrgLevel3Code, &u.IdentityIssuer, &u.ExternalSub, &u.Active, &u.Deleted,
		&u.FailedLogins, &u.LockedUntil, &u.MustChange, &u.PasswordChangedAt, &u.LastLogin, &u.CreatedAt, &u.UpdatedAt,
		&u.UpdatedByID, &u.UpdatedByName, &u.Version, &u.Locked, &u.LockMinutes, &u.EmployeeID, &u.EmployeeCode,
		&u.TenantID, &u.TenantCode, &u.TenantName, &u.TenantActive, &u.IdentityID, &u.IdentityActive, &u.PlatformAdmin, &u.Email, &u.Kind, &u.VerifiedAt, &u.MfaEnrolled, &u.MfaMode)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNoUser
	}
	return &u, err
}

// userByID is the live member id of a tenant; forUpdate locks the membership and the identity.
func (s *Service) userByID(ctx context.Context, tenantID, id string, forUpdate bool) (*userRow, error) {
	if !uuidLike.MatchString(id) || !uuidLike.MatchString(tenantID) {
		return nil, errNoUser
	}
	q := `SELECT ` + userColumns + userFrom + ` WHERE u.id = $1 AND u.tenant_id = $2 AND NOT u.is_deleted`
	if forUpdate {
		q += ` FOR UPDATE OF u, i`
	}
	return scanUser(s.DB.Q(ctx).QueryRow(ctx, q, id, tenantID))
}

var uuidLike = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// actorUser is the member an administrator acts on: in the administrator's own tenant only.
func (s *Service) actorUser(ctx context.Context, me *Actor, id string, forUpdate bool) (*userRow, error) {
	return s.userByID(ctx, me.TenantID, id, forUpdate)
}

// sharedElsewhere: the person is a live member of another tenant too (their password and email are not this
// tenant's to change).
func (s *Service) sharedElsewhere(ctx context.Context, u *userRow) (bool, error) {
	var other bool
	err := s.DB.Q(ctx).QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth.membership WHERE identity_id = $1 AND tenant_id <> $2 AND NOT is_deleted)`,
		u.IdentityID, u.TenantID).Scan(&other)
	return other, err
}

/* ---------------- The answer: ManagedUser ---------------- */

type person struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ManagedUser is a member as the users page reads it (types/users.ts), with the standard code and version.
type ManagedUser struct {
	ID            string             `json:"id"`
	Code          string             `json:"code"`
	Username      string             `json:"username"`
	Name          string             `json:"name"`
	Role          string             `json:"role"`
	Kind          string             `json:"kind"`
	LevelCode     *string            `json:"levelCode"`
	OwnershipCode *string            `json:"ownershipCode"`
	Scope         Scope              `json:"scope"`
	ScopeNames    map[string]*string `json:"scopeNames"`
	// The employee of the member (Portal Master → Karyawan); its name and email come from there.
	EmployeeCode   *string `json:"employeeCode"`
	EmployeeName   *string `json:"employeeName"`
	EmployeeNik    *string `json:"employeeNik"`
	Email          *string `json:"email"`
	EmployeeActive *bool   `json:"employeeActive"`
	// The person behind the member: one identity, possibly a member of other companies too.
	IdentityID         string     `json:"identityId"`
	SharedIdentity     bool       `json:"sharedIdentity"`
	IdentityIssuer     *string    `json:"identityIssuer"`
	ExternalSubject    *string    `json:"externalSubject"`
	Active             bool       `json:"active"`
	LockedUntil        *time.Time `json:"lockedUntil"`
	MustChangePassword bool       `json:"mustChangePassword"`
	LastLoginAt        *time.Time `json:"lastLoginAt"`
	CreatedAt          time.Time  `json:"createdAt"`
	UpdatedAt          time.Time  `json:"updatedAt"`
	UpdatedBy          *person    `json:"updatedBy"`
	Version            int        `json:"version"`
	VerifiedAt         *time.Time `json:"verifiedAt"` // verified by the company or its application (e.g. a vendor's documents)
	MfaEnrolled        bool       `json:"mfaEnrolled"`
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	x := t.UTC()
	return &x
}

func (s *Service) managed(u *userRow, t *tree, shared bool) ManagedUser {
	m := ManagedUser{ID: u.ID, Code: u.Code, Username: u.Username, Name: u.Name, Role: u.RoleCode, Kind: u.Kind, LevelCode: u.Level, OwnershipCode: u.Ownership,
		Scope: u.Scope, IdentityID: u.IdentityID, SharedIdentity: shared, IdentityIssuer: u.IdentityIssuer, ExternalSubject: u.ExternalSub,
		Active: u.Active && u.IdentityActive, MustChangePassword: u.MustChange != nil, Email: u.Email,
		LastLoginAt: utc(u.LastLogin), CreatedAt: u.CreatedAt.UTC(), UpdatedAt: u.CreatedAt.UTC(), Version: u.Version, VerifiedAt: utc(u.VerifiedAt), MfaEnrolled: u.MfaEnrolled}
	if u.Locked {
		m.LockedUntil = utc(u.LockedUntil)
	}
	if u.UpdatedAt != nil {
		m.UpdatedAt = u.UpdatedAt.UTC()
	}
	if u.UpdatedByID != nil && u.UpdatedByName != nil {
		m.UpdatedBy = &person{*u.UpdatedByID, *u.UpdatedByName}
	}
	if t != nil {
		m.ScopeNames = t.names(u.Scope)
	} else {
		m.ScopeNames = map[string]*string{}
	}
	m.EmployeeCode = u.EmployeeCode
	if u.EmployeeID != nil && t != nil {
		if e, ok := t.empByID[*u.EmployeeID]; ok {
			m.EmployeeCode, m.EmployeeName, m.EmployeeNik, m.EmployeeActive = &e.Code, &e.Name, &e.Nik, &e.Active
			if e.Email != nil {
				m.Email = e.Email
			}
			m.Name = e.Name // follows Master Karyawan, also after a rename there
		} else {
			off := false
			m.EmployeeActive = &off // deleted in Portal Master
		}
	}
	return m
}

// sharedSet is the identities of a tenant that are members of other tenants too.
func (s *Service) sharedSet(ctx context.Context, tenantID string) (map[string]bool, error) {
	rows, err := s.DB.Q(ctx).Query(ctx, `SELECT DISTINCT m.identity_id::text FROM auth.membership m JOIN auth.membership o ON o.identity_id = m.identity_id
		AND o.tenant_id <> m.tenant_id AND NOT o.is_deleted WHERE m.tenant_id = $1 AND NOT m.is_deleted`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

func (s *Service) ListUsers(ctx context.Context) ([]ManagedUser, error) {
	me, err := Require(ctx, "auth.users", "read")
	if err != nil {
		return nil, err
	}
	shared, err := s.sharedSet(ctx, me.TenantID)
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.Q(ctx).Query(ctx, `SELECT `+userColumns+userFrom+` WHERE u.tenant_id = $1 AND NOT u.is_deleted ORDER BY u.username`, me.TenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	t, _ := s.Org.Tree(ctx, me.TenantID, false) // names only: a member list does not fail when Portal Master is away
	out := []ManagedUser{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s.managed(u, t, shared[u.IdentityID]))
	}
	return out, rows.Err()
}

func (s *Service) GetUser(ctx context.Context, id string) (ManagedUser, error) {
	me, err := Require(ctx, "auth.users", "read")
	if err != nil {
		return ManagedUser{}, err
	}
	u, err := s.actorUser(ctx, me, id, false)
	if err != nil {
		return ManagedUser{}, notFound(err)
	}
	shared, err := s.sharedElsewhere(ctx, u)
	if err != nil {
		return ManagedUser{}, err
	}
	t, _ := s.Org.Tree(ctx, me.TenantID, false)
	return s.managed(u, t, shared), nil
}

func notFound(err error) error {
	if errors.Is(err, errNoUser) || errors.Is(err, errNoRole) {
		return apperr.NotFound()
	}
	return err
}

/* ---------------- Saving a member ---------------- */

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

var emailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

type userInput struct {
	EmployeeCode                *string
	Username, Name, Role        string
	Level                       string
	Ownership                   *string
	Scope                       Scope
	IdentityIssuer, ExternalSub *string
	Active                      bool
	Password                    *string
	Email                       *string // sign-in email of a member without an employee (vendor, external)
}

func parseUser(v record.Values, p *record.Problems) userInput {
	in := userInput{}
	in.Username = strings.ToLower(record.RequiredText(v, "username", "Username", 60, p))
	if in.Username != "" && !p.Has("username") && !usernamePattern.MatchString(in.Username) {
		p.Add("username", "Username berisi huruf kecil, angka, titik, - atau _ tanpa spasi.")
	}
	in.EmployeeCode = record.OptionalText(v, "employeeCode", "Karyawan", record.MaxCode, p)
	if s, _ := v["name"].(string); in.EmployeeCode != nil && strings.TrimSpace(s) == "" {
		in.Name = "" // the employee's name, filled by SaveUser
	} else {
		in.Name = record.RequiredText(v, "name", "Nama lengkap", record.MaxName, p)
	}
	if in.Name != "" && len([]rune(in.Name)) < 2 && !p.Has("name") {
		p.Add("name", "Nama lengkap minimal 2 karakter.")
	}
	in.Role = record.RequiredText(v, "role", "Peran", record.MaxCode, p)
	in.Level = record.RequiredText(v, "levelCode", "Level akses", 20, p)
	in.Ownership = record.OptionalText(v, "ownershipCode", "Kepemilikan", 10, p)
	for _, f := range fields {
		*f.get(&in.Scope) = record.OptionalText(v, f.key, f.label, record.MaxCode, p)
	}
	in.IdentityIssuer = record.OptionalText(v, "identityIssuer", "Identity issuer", 200, p)
	in.ExternalSub = record.OptionalText(v, "externalSubject", "External subject", 200, p)
	if (in.IdentityIssuer == nil) != (in.ExternalSub == nil) {
		p.Add("externalSubject", "Isi identity issuer dan external subject SSO berpasangan, atau kosongkan keduanya.")
	}
	in.Active = record.Bool(v, "active", "Status aktif", true, p)
	if pw, ok := v["password"].(string); ok && pw != "" {
		in.Password = &pw
	} else if v["password"] != nil && !ok {
		p.Add("password", "Password harus berupa teks.")
	}
	in.Email = parseEmail(v, "email", p)
	return in
}

// parseEmail reads an optional email (lower case).
func parseEmail(v record.Values, key string, p *record.Problems) *string {
	e := record.OptionalText(v, key, "Email", 254, p)
	if e == nil || p.Has(key) {
		return nil
	}
	x := strings.ToLower(strings.TrimSpace(*e))
	if !emailPattern.MatchString(x) {
		p.Add(key, "Email bukan alamat yang sah, mis. nama@perusahaan.co.id.")
		return nil
	}
	return &x
}

// identityByEmail is the live identity with an email ("" when none).
func (s *Service) identityByEmail(ctx context.Context, email string) (string, error) {
	var id string
	err := s.DB.Q(ctx).QueryRow(ctx, `SELECT id FROM auth.identity WHERE email = $1 AND NOT is_deleted`, email).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// SaveUser adds (id "") or changes a member of the administrator's tenant. A new member is a new person, or a
// person who already has an ALIR identity with the same email (a member of another company): then they keep their
// own password. A password typed by an administrator must be replaced at the next sign-in, and is refused for a
// person who is a member of another company too (send them a reset link).
func (s *Service) SaveUser(ctx context.Context, id string, body record.Values) (ManagedUser, error) {
	action := "create"
	if id != "" {
		action = "update"
	}
	me, err := Require(ctx, "auth.users", action)
	if err != nil {
		return ManagedUser{}, err
	}
	ctx = me.ctx(ctx)
	t, err := s.Org.Tree(ctx, me.TenantID, false)
	if err != nil {
		return ManagedUser{}, &apperr.Error{Status: 503, Code: "ORG_UNAVAILABLE", Message: "Master organisasi (Portal Master) tidak dapat dibaca; coba lagi sebentar lagi."}
	}
	var saved *userRow
	var shared bool
	err = s.DB.InTx(ctx, func(ctx context.Context) error {
		var stored *userRow
		var problems record.Problems
		if id != "" {
			if stored, err = s.actorUser(ctx, me, id, true); err != nil {
				return notFound(err)
			}
			if want, ok := record.ExpectedVersion(body, &problems); ok && want != stored.Version {
				return apperr.Conflict("STALE", fmt.Sprintf("Pengguna %s sudah diubah administrator lain. Muat ulang, lalu ulangi perubahan Anda.", stored.Username))
			}
		}
		in := parseUser(body, &problems)
		pol, err := s.policy(ctx, me.TenantID)
		if err != nil {
			return err
		}
		if !problems.Has("levelCode") {
			t.checkScope(in.Level, &in.Scope, &problems)
		}
		var roleID string
		var roleActive bool
		if in.Role != "" {
			err := s.DB.Q(ctx).QueryRow(ctx, `SELECT id, is_active FROM auth.role WHERE tenant_id = $1 AND code = $2 AND NOT is_deleted FOR SHARE`, me.TenantID, in.Role).Scan(&roleID, &roleActive)
			if errors.Is(err, pgx.ErrNoRows) || err == nil && !roleActive && (stored == nil || stored.RoleID != roleID) {
				problems.Add("role", "Peran tidak tersedia.")
			} else if err != nil {
				return err
			}
		}
		if in.Username != "" && !problems.Has("username") {
			var other string
			err := s.DB.Q(ctx).QueryRow(ctx, `SELECT id FROM auth.membership WHERE tenant_id = $1 AND username = $2 AND NOT is_deleted`, me.TenantID, in.Username).Scan(&other)
			if err == nil && (stored == nil || other != stored.ID) {
				problems.Add("username", "Username sudah dipakai.")
			} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		var employee *pmEmployee
		if in.EmployeeCode != nil && !problems.Has("employeeCode") {
			e, ok := t.employee(*in.EmployeeCode)
			switch {
			case !ok:
				problems.Add("employeeCode", fmt.Sprintf("Karyawan \"%s\" tidak ditemukan di master Karyawan.", *in.EmployeeCode))
			case !e.Active && (stored == nil || stored.EmployeeID == nil || *stored.EmployeeID != e.ID):
				problems.Add("employeeCode", fmt.Sprintf("Karyawan %s nonaktif; pilih karyawan lain.", e.Name))
			default:
				var other string
				err := s.DB.Q(ctx).QueryRow(ctx, `SELECT username FROM auth.membership WHERE tenant_id = $1 AND employee_id = $2 AND NOT is_deleted AND ($3 = '' OR id::text <> $3)`,
					me.TenantID, e.ID, map[bool]string{true: "", false: id}[stored == nil]).Scan(&other)
				if err == nil {
					problems.Add("employeeCode", fmt.Sprintf("Karyawan %s sudah punya akun %s; satu karyawan satu akun.", e.Name, other))
				} else if !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
				employee = &e
				in.Name = truncate(e.Name, 150) // the name of a linked member is the employee's
			}
		}
		if in.Name == "" && !problems.Has("name") && !problems.Has("employeeCode") {
			problems.Add("name", "Nama lengkap wajib diisi.")
		}
		// The sign-in email: the employee's (company mail), else the one typed for a member without an employee.
		email := in.Email
		if employee != nil && employee.Email != nil {
			e := strings.ToLower(*employee.Email)
			email = &e
		}

		// The person: kept on a change; on a new member, the identity that already has this email, else a new one.
		identityID, reuse := "", false
		if stored != nil {
			identityID = stored.IdentityID
			if shared, err = s.sharedElsewhere(ctx, stored); err != nil {
				return err
			}
		} else if email != nil && !problems.Has("email") {
			if identityID, err = s.identityByEmail(ctx, *email); err != nil {
				return err
			}
			if identityID != "" {
				reuse, shared = true, true
				var other string
				err := s.DB.Q(ctx).QueryRow(ctx, `SELECT username FROM auth.membership WHERE tenant_id = $1 AND identity_id = $2 AND NOT is_deleted`, me.TenantID, identityID).Scan(&other)
				if err == nil {
					problems.Add(map[bool]string{true: "employeeCode", false: "email"}[employee != nil], fmt.Sprintf("Orang dengan email %s sudah punya akun %s di perusahaan ini.", *email, other))
				} else if !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
			}
		}
		if stored == nil && !reuse && in.Password == nil && in.IdentityIssuer == nil {
			problems.Add("password", "Password awal wajib diisi.")
		}
		if in.Password != nil {
			switch {
			case reuse:
				in.Password = nil // the person keeps the password of their ALIR identity
			case shared:
				problems.Add("password", "Orang ini juga anggota perusahaan lain; passwordnya tidak diatur di sini. Kirim tautan reset password.")
			default:
				if msg := pol.Rules().Problem(*in.Password); msg != "" {
					problems.Add("password", fmt.Sprintf("Password belum memenuhi: %s.", strings.ToLower(msg)))
				}
			}
		}
		if stored != nil && stored.ID == me.MemberID && !in.Active {
			problems.Add("active", "Anda tidak dapat menonaktifkan akun Anda sendiri.")
		}
		if stored != nil && stored.RoleCode == "admin" && stored.Active && (in.Role != "admin" || !in.Active) {
			if n, err := s.activeAdmins(ctx, me.TenantID); err != nil {
				return err
			} else if n <= 1 {
				problems.Add("role", "Ini satu-satunya Admin aktif; tambahkan Admin lain dulu agar Authentication tidak terkunci.")
			}
		}
		if len(problems) > 0 {
			return apperr.Validation(problems)
		}
		var hash *string
		if in.Password != nil {
			h, err := password.Hash(*in.Password)
			if err != nil {
				return err
			}
			hash = &h
		}
		var empID, empCode *string
		if employee != nil {
			empID, empCode = &employee.ID, &employee.Code
		}
		sc := in.Scope
		if stored == nil {
			if identityID == "" {
				must := "first"
				if hash == nil {
					must = "" // federated only: no password to change
				}
				if err := s.DB.Q(ctx).QueryRow(ctx, `INSERT INTO auth.identity (name, email, password_hash, must_change_password, password_changed_at, created_by)
					VALUES ($1, $2, $3, nullif($4, ''), CASE WHEN $3::text IS NULL THEN NULL ELSE now() END, $5) RETURNING id`,
					in.Name, email, hash, must, me.UserID).Scan(&identityID); err != nil {
					return uniqueEmail(err)
				}
			}
			code, err := codeprefix.NextFree(ctx, s.Codes, "membership", func(ctx context.Context, c string) (bool, error) {
				var taken bool
				err := s.DB.Q(ctx).QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth.membership WHERE tenant_id = $1 AND lower(code) = lower($2))`, me.TenantID, c).Scan(&taken)
				return taken, err
			})
			if err != nil {
				return err
			}
			if err := s.DB.Q(ctx).QueryRow(ctx, `INSERT INTO auth.membership (tenant_id, identity_id, code, name, username, role_id, level_code, ownership_code,
				group_code, region_code, wilayah_code, company_code, operational_unit_code, org_level1_code, org_level2_code, org_level3_code,
				is_active, created_by, employee_id, employee_code)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20) RETURNING id`,
				me.TenantID, identityID, code, in.Name, in.Username, roleID, in.Level, in.Ownership, sc.GroupCode, sc.RegionCode, sc.WilayahCode,
				sc.CompanyCode, sc.OperationalUnitCode, sc.OrgLevel1Code, sc.OrgLevel2Code, sc.OrgLevel3Code, in.Active, me.UserID, empID, empCode).Scan(&id); err != nil {
				return err
			}
		} else {
			if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.membership SET name = $2, username = $3, role_id = $4, level_code = $5, ownership_code = $6,
				owner_code = NULL, gmk_code = NULL, group_code = $7, region_code = $8, wilayah_code = $9, company_code = $10,
				operational_unit_code = $11, org_level1_code = $12, org_level2_code = $13, org_level3_code = $14,
				is_active = $15, employee_id = $17, employee_code = $18, updated_at = now(), updated_by = $16, version = version + 1 WHERE id = $1`,
				id, in.Name, in.Username, roleID, in.Level, in.Ownership, sc.GroupCode, sc.RegionCode, sc.WilayahCode, sc.CompanyCode,
				sc.OperationalUnitCode, sc.OrgLevel1Code, sc.OrgLevel2Code, sc.OrgLevel3Code, in.Active, me.UserID, empID, empCode); err != nil {
				return err
			}
			if !shared {
				// The person belongs to this tenant only: their name, sign-in email and password follow the form.
				if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.identity SET name = $2, email = coalesce($3, email),
					password_hash = coalesce($4, password_hash),
					must_change_password = CASE WHEN $4::text IS NULL THEN must_change_password ELSE 'reset' END,
					password_changed_at = CASE WHEN $4::text IS NULL THEN password_changed_at ELSE now() END,
					updated_at = now(), updated_by = $5, version = version + 1 WHERE id = $1`, identityID, in.Name, email, hash, me.UserID); err != nil {
					return uniqueEmail(err)
				}
			}
			if !in.Active || hash != nil {
				// A deactivated member, or one whose password an administrator set, signs in again.
				if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.session SET revoked_at = now() WHERE identity_id = $1 AND revoked_at IS NULL
					AND ($2 OR membership_id = $3)`, identityID, hash != nil, id); err != nil {
					return err
				}
			}
		}
		if !shared || stored == nil && !reuse {
			if err := s.setLink(ctx, identityID, in.IdentityIssuer, in.ExternalSub, me.UserID); err != nil {
				return err
			}
		}
		if saved, err = s.userByID(ctx, me.TenantID, id, false); err != nil {
			return err
		}
		if stored == nil {
			s.audit(ctx, requestOf(ctx), "user_created", me, saved.Username, "Peran "+saved.RoleName)
			if to := s.emailOf(ctx, saved); to != "" {
				s.mailAccountCreated(ctx, saved, to, reuse)
			}
		} else {
			detail := "Data pengguna diubah"
			if stored.Active != saved.Active {
				detail = map[bool]string{true: "Status diubah menjadi aktif", false: "Status diubah menjadi nonaktif"}[saved.Active]
			}
			s.audit(ctx, requestOf(ctx), "user_updated", me, saved.Username, detail)
		}
		return nil
	})
	if err != nil {
		return ManagedUser{}, err
	}
	return s.managed(saved, t, shared), nil
}

// setLink sets the federated identity of a person (none when issuer is nil).
func (s *Service) setLink(ctx context.Context, identityID string, issuer, subject *string, by string) error {
	if _, err := s.DB.Q(ctx).Exec(ctx, `DELETE FROM auth.identity_link WHERE identity_id = $1`, identityID); err != nil {
		return err
	}
	if issuer == nil {
		return nil
	}
	_, err := s.DB.Q(ctx).Exec(ctx, `INSERT INTO auth.identity_link (identity_id, issuer, subject, created_by) VALUES ($1, $2, $3, $4)`, identityID, *issuer, *subject, by)
	if isUnique(err, "identity_link_subject") {
		return apperr.Validation([]apperr.Problem{{Field: "externalSubject", Message: "Identitas SSO ini sudah dipakai orang lain."}})
	}
	return err
}

func uniqueEmail(err error) error {
	if isUnique(err, "identity_email_live") {
		return apperr.Validation([]apperr.Problem{{Field: "email", Message: "Email ini sudah dipakai identitas lain."}})
	}
	return err
}

func (s *Service) activeAdmins(ctx context.Context, tenantID string) (int, error) {
	var n int
	err := s.DB.Q(ctx).QueryRow(ctx, `SELECT count(*) FROM auth.membership u JOIN auth.role r ON r.id = u.role_id JOIN auth.identity i ON i.id = u.identity_id
		WHERE u.tenant_id = $1 AND r.code = 'admin' AND u.is_active AND NOT u.is_deleted AND i.is_active`, tenantID).Scan(&n)
	return n, err
}

// DeleteUser is a soft delete of the membership; its sessions end. The person keeps their identity (and any
// other company they are a member of).
func (s *Service) DeleteUser(ctx context.Context, id string) error {
	me, err := Require(ctx, "auth.users", "delete")
	if err != nil {
		return err
	}
	return s.DB.InTx(ctx, func(ctx context.Context) error {
		u, err := s.actorUser(ctx, me, id, true)
		if err != nil {
			return notFound(err)
		}
		if u.ID == me.MemberID {
			return apperr.Conflict("SELF", "Anda tidak dapat menghapus akun Anda sendiri.")
		}
		if u.RoleCode == "admin" && u.Active {
			if n, err := s.activeAdmins(ctx, me.TenantID); err != nil {
				return err
			} else if n <= 1 {
				return apperr.Conflict("LAST_ADMIN", "Ini satu-satunya Admin aktif; tidak dapat dihapus.")
			}
		}
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.membership SET is_deleted = true, is_active = false, deleted_at = now(), deleted_by = $2,
			updated_at = now(), updated_by = $2, version = version + 1 WHERE id = $1`, id, me.UserID); err != nil {
			return err
		}
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.session SET revoked_at = now() WHERE membership_id = $1 AND revoked_at IS NULL`, id); err != nil {
			return err
		}
		s.audit(ctx, requestOf(ctx), "user_updated", me, u.Username, "Pengguna dihapus")
		return nil
	})
}

// Unlock clears the lock and the failure count of the person (POST /users/:id/unlock).
func (s *Service) Unlock(ctx context.Context, id string) (ManagedUser, error) {
	me, err := Require(ctx, "auth.users", "update")
	if err != nil {
		return ManagedUser{}, err
	}
	u, err := s.actorUser(ctx, me, id, false)
	if err != nil {
		return ManagedUser{}, notFound(err)
	}
	if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.identity SET locked_until = NULL, failed_logins = 0 WHERE id = $1`, u.IdentityID); err != nil {
		return ManagedUser{}, err
	}
	s.audit(ctx, requestOf(ctx), "user_updated", me, u.Username, "Kunci akun dibuka")
	return s.GetUser(ctx, id)
}

// RevokeSessions ends every session of a member in this tenant (POST /users/:id/revoke-sessions).
func (s *Service) RevokeSessions(ctx context.Context, id string) (int64, error) {
	me, err := Require(ctx, "auth.users", "update")
	if err != nil {
		return 0, err
	}
	u, err := s.actorUser(ctx, me, id, false)
	if err != nil {
		return 0, notFound(err)
	}
	tag, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.session SET revoked_at = now() WHERE membership_id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return 0, err
	}
	s.audit(ctx, requestOf(ctx), "session_revoked", me, u.Username, fmt.Sprintf("%d sesi dicabut oleh administrator", tag.RowsAffected()))
	return tag.RowsAffected(), nil
}

// employeeOK says whether the member may act: no employee, or an active one (Portal Master of its tenant). When
// Portal Master has never been read the member is not blocked (the last copy is used otherwise).
func (s *Service) employeeOK(ctx context.Context, u *userRow) bool {
	if u.EmployeeID == nil {
		return true
	}
	t, err := s.Org.Tree(ctx, u.TenantID, false)
	if err != nil {
		return true
	}
	e, ok := t.empByID[*u.EmployeeID]
	return ok && e.Active
}

// EmployeeOption is an employee the users form can link a member to.
type EmployeeOption struct {
	Code     string  `json:"code"`
	Nik      string  `json:"nik"`
	Name     string  `json:"name"`
	Email    *string `json:"email"`
	Active   bool    `json:"active"`
	UserID   *string `json:"userId"` // the member already linked to the employee
	Username *string `json:"username"`
}

// EmployeeOptions lists the employees of the tenant's Portal Master with the member each one has
// (GET /users/employee-options).
func (s *Service) EmployeeOptions(ctx context.Context) ([]EmployeeOption, error) {
	me, err := Require(ctx, "auth.users", "read")
	if err != nil {
		return nil, err
	}
	t, err := s.Org.Tree(ctx, me.TenantID, false)
	if err != nil {
		return nil, &apperr.Error{Status: 503, Code: "ORG_UNAVAILABLE", Message: "Master Karyawan (Portal Master) tidak dapat dibaca; coba lagi sebentar lagi."}
	}
	linked := map[string][2]string{}
	rows, err := s.DB.Q(ctx).Query(ctx, `SELECT employee_id::text, id::text, username FROM auth.membership WHERE tenant_id = $1 AND employee_id IS NOT NULL AND NOT is_deleted`, me.TenantID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var e, id, u string
		if err := rows.Scan(&e, &id, &u); err != nil {
			rows.Close()
			return nil, err
		}
		linked[e] = [2]string{id, u}
	}
	rows.Close()
	out := make([]EmployeeOption, 0, len(t.employees))
	for _, e := range t.employees {
		o := EmployeeOption{Code: e.Code, Nik: e.Nik, Name: e.Name, Email: e.Email, Active: e.Active}
		if l, ok := linked[e.ID]; ok {
			o.UserID, o.Username = &l[0], &l[1]
		}
		out = append(out, o)
	}
	return out, nil
}

// nameOf is the member's name: its employee's current name when it has one (Master Karyawan), else its own.
func (s *Service) nameOf(ctx context.Context, u *userRow) string {
	if u.EmployeeID != nil {
		if t, err := s.Org.Tree(ctx, u.TenantID, false); err == nil {
			if e, ok := t.empByID[*u.EmployeeID]; ok {
				return e.Name
			}
		}
	}
	return u.Name
}
