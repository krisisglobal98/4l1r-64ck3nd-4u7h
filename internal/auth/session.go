package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"alir.local/auth-service/internal/mail"
	"alir.local/auth-service/internal/password"
	"alir.local/auth-service/internal/platform/apperr"
	"alir.local/auth-service/internal/platform/record"
	"alir.local/auth-service/internal/token"
)

// refreshGrace: a refresh token shown again this soon after it was rotated is a second tab refreshing at the same
// moment (it gets 409 and retries with the new cookie), not a stolen token.
const refreshGrace = 20 * time.Second

// SessionUser is the user part of a sign-in answer (types/contracts.ts User). ID is the membership (what the users
// page lists); IdentityID is the person.
type SessionUser struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	Name       string `json:"name"`
	Role       string `json:"role"`
	IdentityID string `json:"identityId"`
}

// TenantRef is a company as the sign-in answers name it.
type TenantRef struct {
	ID   string `json:"id"`
	Code string `json:"code"`
	Name string `json:"name"`
}

// LoginResult is the answer of a sign-in, a refresh or a switch of company (types/session.ts LoginResult). The
// refresh token travels only in the httpOnly cookie.
type LoginResult struct {
	Token              string      `json:"token"`
	ExpiresAt          time.Time   `json:"expiresAt"`
	User               SessionUser `json:"user"`
	Access             Access      `json:"access"`
	MustChangePassword *string     `json:"mustChangePassword"`
	Tenant             TenantRef   `json:"tenant"`
	Tenants            []TenantRef `json:"tenants"` // every company the person may switch to
	PlatformAdmin      bool        `json:"platformAdmin"`
	// The company requires MFA and the person has none: the token grants nothing until they enrol.
	MustEnrollMfa  bool `json:"mustEnrollMfa"`
	refresh        string
	sso            string // the single sign-on cookie of a new sign-in
	refreshExpires time.Time
}

func newSecret() (raw string, hash []byte) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	raw = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	return raw, h[:]
}

func hashOf(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

func invalidLogin() error {
	return unauthorized("INVALID", "Username/email atau password salah.")
}

/* ---------------- Tenants ---------------- */

// tenantRef finds an active company by code or id ("" = none given).
func (s *Service) tenantRef(ctx context.Context, key string) (*TenantRef, error) {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" {
		return nil, nil
	}
	if len(key) > 40 && !uuidLike.MatchString(key) {
		return nil, unknownTenant()
	}
	var t TenantRef
	err := s.DB.Q(ctx).QueryRow(ctx, `SELECT id, code, name FROM auth.tenant WHERE (lower(code) = $1 OR id::text = $1) AND is_active AND NOT is_deleted`, key).Scan(&t.ID, &t.Code, &t.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, unknownTenant()
	}
	return &t, err
}

func unknownTenant() error {
	return apperr.Validation([]apperr.Problem{{Field: "tenant", Message: "Perusahaan tidak dikenal atau tidak aktif."}})
}

// tenantsOf are the companies a person may work in: live, active memberships of active companies (by name).
func (s *Service) tenantsOf(ctx context.Context, identityID string) ([]TenantRef, error) {
	rows, err := s.DB.Q(ctx).Query(ctx, `SELECT t.id, t.code, t.name FROM auth.membership m JOIN auth.tenant t ON t.id = m.tenant_id
		WHERE m.identity_id = $1 AND NOT m.is_deleted AND m.is_active AND t.is_active AND NOT t.is_deleted ORDER BY t.name, t.code`, identityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TenantRef{}
	for rows.Next() {
		var t TenantRef
		if err := rows.Scan(&t.ID, &t.Code, &t.Name); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// LookupTenant answers whether a company code exists (the sign-in page of a company's address shows its name).
func (s *Service) LookupTenant(ctx context.Context, code string) (TenantRef, error) {
	t, err := s.tenantRef(ctx, code)
	if err != nil {
		return TenantRef{}, err
	}
	if t == nil {
		return TenantRef{}, unknownTenant()
	}
	return *t, nil
}

/* ---------------- Sign-in ---------------- */

// identityRow is the sign-in state of a person.
type identityRow struct {
	ID, Name                  string
	PasswordHash, MustChange  *string
	Active, Locked            bool
	LockedUntil               *time.Time
	FailedLogins, LockMinutes int
}

func (s *Service) lockIdentity(ctx context.Context, id string) (*identityRow, error) {
	var x identityRow
	err := s.DB.Q(ctx).QueryRow(ctx, `SELECT id, name, password_hash, must_change_password, is_active, coalesce(locked_until > now(), false), locked_until,
		failed_logins, greatest(0, ceil(extract(epoch FROM (locked_until - now())) / 60))::int
		FROM auth.identity WHERE id = $1 AND NOT is_deleted FOR UPDATE`, id).Scan(&x.ID, &x.Name, &x.PasswordHash, &x.MustChange, &x.Active, &x.Locked,
		&x.LockedUntil, &x.FailedLogins, &x.LockMinutes)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNoUser
	}
	return &x, err
}

// findIdentity is the person an identifier names: an email (any company), or a username (in the company when
// one is given; a username used by different people in different companies needs the company).
func (s *Service) findIdentity(ctx context.Context, ident string, tenant *TenantRef) (id string, byUsername bool, err error) {
	ident = strings.ToLower(strings.TrimSpace(ident))
	if strings.Contains(ident, "@") {
		id, err = s.identityByEmail(ctx, ident)
		return id, false, err
	}
	tid := ""
	if tenant != nil {
		tid = tenant.ID
	}
	rows, err := s.DB.Q(ctx).Query(ctx, `SELECT DISTINCT identity_id::text FROM auth.membership WHERE username = $1 AND NOT is_deleted
		AND ($2 = '' OR tenant_id::text = $2) LIMIT 2`, ident, tid)
	if err != nil {
		return "", true, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var x string
		if err := rows.Scan(&x); err != nil {
			return "", true, err
		}
		ids = append(ids, x)
	}
	if len(ids) > 1 {
		return "", true, &apperr.Error{Status: http.StatusConflict, Code: "TENANT_REQUIRED",
			Message: "Username ini dipakai di lebih dari satu perusahaan. Masuk dengan email, atau buka alamat perusahaan Anda."}
	}
	if len(ids) == 1 {
		return ids[0], true, rows.Err()
	}
	return "", true, rows.Err()
}

// Login signs in with a username or an email and the password. A person who is a member of more than one company
// chooses one: without "tenant" the answer is 409 TENANT_CHOICE with the companies (after a correct password
// only), and the page signs in again with the chosen one.
func (s *Service) Login(ctx context.Context, r *http.Request, body record.Values) (LoginResult, error) {
	ident, _ := body["username"].(string)
	if e, _ := body["email"].(string); strings.TrimSpace(ident) == "" {
		ident = e
	}
	pw, _ := body["password"].(string)
	if strings.TrimSpace(ident) == "" || pw == "" || len(ident) > 254 {
		return LoginResult{}, apperr.Validation([]apperr.Problem{{Field: "username", Message: "Username/email dan password wajib diisi."}})
	}
	tkey, _ := body["tenant"].(string)
	if tkey == "" && r != nil {
		tkey = r.Header.Get("X-Tenant")
	}
	tenant, err := s.tenantRef(ctx, tkey)
	if err != nil {
		return LoginResult{}, err
	}
	tenantID := ""
	if tenant != nil {
		tenantID = tenant.ID
	}
	// Password spraying from one address is slowed before any account is looked at (the lockout is per person).
	if err := s.limit(ctx, "login:ip:"+clientIP(r), s.limits().LoginPerIP); err != nil {
		return LoginResult{}, err
	}
	var out LoginResult
	var refusal error
	err = s.DB.InTx(ctx, func(ctx context.Context) error {
		refusal = nil
		now := s.now()
		target := strings.ToLower(strings.TrimSpace(ident))
		iid, byUsername, err := s.findIdentity(ctx, target, tenant)
		if err != nil {
			var e *apperr.Error
			if errors.As(err, &e) {
				password.Burn(pw)
				refusal = err
				return nil
			}
			return err
		}
		var id *identityRow
		if iid != "" {
			if id, err = s.lockIdentity(ctx, iid); err != nil && !errors.Is(err, errNoUser) {
				return err
			}
		}
		if id == nil {
			password.Burn(pw)
			s.auditIn(ctx, r, tenantID, "login_failed", nil, target, "Username/email tidak dikenal")
			refusal = invalidLogin()
			return nil
		}
		ipol, err := s.identityPolicy(ctx, id.ID)
		if err != nil {
			return err
		}
		if id.Locked {
			password.Burn(pw)
			refusal = locked(*id.LockedUntil, id.LockMinutes)
			return nil
		}
		ok := false
		if id.PasswordHash != nil {
			if ok, err = password.Verify(pw, *id.PasswordHash); err != nil {
				return err
			}
		} else {
			password.Burn(pw)
		}
		// A failure of a known person is recorded in each company they are a member of (the one chosen, when one is):
		// every company's administrator sees the attempts on their members.
		where := []string{tenantID}
		if tenantID == "" {
			if where, err = s.memberTenants(ctx, id.ID); err != nil {
				return err
			}
		}
		auditAll := func(typ, detail string) {
			for _, t := range where {
				s.auditIn(ctx, r, t, typ, nil, target, detail)
			}
		}
		if !ok {
			n := id.FailedLogins + 1
			auditAll("login_failed", fmt.Sprintf("Password salah (percobaan ke-%d)", n))
			if ipol.MaxFailedAttempts > 0 && n >= ipol.MaxFailedAttempts {
				var until time.Time
				if err := s.DB.Q(ctx).QueryRow(ctx, `UPDATE auth.identity SET failed_logins = 0, locked_until = now() + make_interval(mins => $2)
					WHERE id = $1 RETURNING locked_until`, id.ID, ipol.LockoutMinutes).Scan(&until); err != nil {
					return err
				}
				auditAll("locked", fmt.Sprintf("Terkunci %d menit setelah %d percobaan gagal", ipol.LockoutMinutes, n))
				refusal = locked(until, ipol.LockoutMinutes)
				return nil
			}
			if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.identity SET failed_logins = $2 WHERE id = $1`, id.ID, n); err != nil {
				return err
			}
			refusal = invalidLogin()
			return nil
		}
		// From here the password is right: what follows may tell the person about their own account. The failure
		// count is cleared only when the whole sign-in succeeds (startSession): a second factor still to come must
		// not get fresh tries with every correct password.
		var err2 error
		out, refusal, err2 = s.enter(ctx, r, id, tenantID, byUsername, target, "local", now)
		return err2
	})
	if err != nil {
		return LoginResult{}, err
	}
	return out, refusal
}

// memberTenants are the companies a person is a live member of ("" when none: an event of the installation).
func (s *Service) memberTenants(ctx context.Context, identityID string) ([]string, error) {
	rows, err := s.DB.Q(ctx).Query(ctx, `SELECT DISTINCT tenant_id::text FROM auth.membership WHERE identity_id = $1 AND NOT is_deleted`, identityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		out = []string{""}
	}
	return out, rows.Err()
}

// enter signs an authenticated person (password or email code) in to one company: the company given, the only
// one, or a choice (409 TENANT_CHOICE); with the company's rules (inactive, unverified email of an external member,
// the employee, the sign-in method the policy allows, password expiry, concurrent sessions). method: local | otp.
func (s *Service) enter(ctx context.Context, r *http.Request, id *identityRow, tenantID string, byUsername bool, target, method string, now time.Time) (LoginResult, error, error) {
	if !id.Active {
		return LoginResult{}, &apperr.Error{Status: 403, Code: "INACTIVE", Message: "Akun ini nonaktif. Hubungi administrator."}, nil
	}
	// The companies this sign-in may enter: the one given, and with a username only where it is that username.
	// An external member (signed up) enters only once the email is verified.
	rows, err := s.DB.Q(ctx).Query(ctx, `SELECT m.id, m.tenant_id, m.is_active AND t.is_active AND NOT t.is_deleted,
		m.kind = 'external' AND i.email_verified_at IS NULL
		FROM auth.membership m JOIN auth.tenant t ON t.id = m.tenant_id JOIN auth.identity i ON i.id = m.identity_id
		WHERE m.identity_id = $1 AND NOT m.is_deleted AND ($2 = '' OR m.tenant_id::text = $2)
		AND (NOT $3 OR m.username = $4) ORDER BY t.name`, id.ID, tenantID, byUsername, target)
	if err != nil {
		return LoginResult{}, nil, err
	}
	type cand struct{ mid, tid string }
	var live []cand
	inactive, unverified := 0, 0
	for rows.Next() {
		var c cand
		var active, unconfirmed bool
		if err := rows.Scan(&c.mid, &c.tid, &active, &unconfirmed); err != nil {
			rows.Close()
			return LoginResult{}, nil, err
		}
		switch {
		case active && unconfirmed:
			unverified++
		case active:
			live = append(live, c)
		default:
			inactive++
		}
	}
	rows.Close()
	switch {
	case len(live) == 0 && unverified > 0:
		return LoginResult{}, &apperr.Error{Status: 403, Code: "EMAIL_UNVERIFIED", Message: "Verifikasi email Anda dulu: buka tautan yang kami kirim, atau minta kirim ulang."}, nil
	case len(live) == 0 && inactive > 0:
		return LoginResult{}, &apperr.Error{Status: 403, Code: "INACTIVE", Message: "Akun Anda di perusahaan ini nonaktif. Hubungi administrator."}, nil
	case len(live) == 0:
		return LoginResult{}, &apperr.Error{Status: 403, Code: "NOT_MEMBER", Message: "Akun Anda belum terdaftar di perusahaan ini."}, nil
	case len(live) > 1:
		all, err := s.tenantsOf(ctx, id.ID)
		if err != nil {
			return LoginResult{}, nil, err
		}
		choice := []TenantRef{}
		for _, t := range all {
			for _, c := range live {
				if c.tid == t.ID {
					choice = append(choice, t)
				}
			}
		}
		return LoginResult{}, &apperr.Error{Status: http.StatusConflict, Code: "TENANT_CHOICE", Message: "Pilih perusahaan yang akan Anda masuki.",
			Details: map[string]any{"tenants": choice}}, nil
	}
	u, err := s.userByID(ctx, live[0].tid, live[0].mid, true)
	if err != nil {
		return LoginResult{}, nil, err
	}
	pol, err := s.policy(ctx, u.TenantID)
	if err != nil {
		return LoginResult{}, nil, err
	}
	if method == "local" && !pol.AllowLocalLogin {
		return LoginResult{}, &apperr.Error{Status: 403, Code: "LOCAL_DISABLED", Message: "Login dengan password dinonaktifkan di perusahaan ini. Gunakan SSO."}, nil
	}
	if method == "otp" && !pol.AllowEmailOtp {
		return LoginResult{}, &apperr.Error{Status: 403, Code: "OTP_DISABLED", Message: "Login dengan kode email dinonaktifkan di perusahaan ini."}, nil
	}
	if !s.employeeOK(ctx, u) {
		return LoginResult{}, &apperr.Error{Status: 403, Code: "EMPLOYEE_INACTIVE", Message: "Karyawan pemilik akun ini nonaktif. Hubungi administrator."}, nil
	}
	must := u.MustChange
	if must == nil && pol.PasswordExpiryDays > 0 {
		tag, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.identity SET must_change_password = 'expired'
			WHERE id = $1 AND password_changed_at < now() - make_interval(days => $2)`, u.IdentityID, pol.PasswordExpiryDays)
		if err != nil {
			return LoginResult{}, nil, err
		}
		if tag.RowsAffected() == 1 {
			e := "expired"
			must = &e
		}
	}
	u.MustChange = must
	return s.secondFactorOrSession(ctx, r, u, pol, method, now)
}

// secondFactorOrSession opens the session of a member whose first factor is proven, or answers MFA_REQUIRED when the
// person has an authenticator (password, email code and identity provider sign-ins alike).
func (s *Service) secondFactorOrSession(ctx context.Context, r *http.Request, u *userRow, pol Policy, method string, now time.Time) (LoginResult, error, error) {
	if u.MfaEnrolled {
		raw, hash := newSecret()
		var exp time.Time
		if err := s.DB.Q(ctx).QueryRow(ctx, `INSERT INTO auth.mfa_challenge (token_hash, identity_id, membership_id, tenant_id, method, expires_at)
			VALUES ($1, $2, $3, $4, $5, now() + interval '5 minutes') RETURNING expires_at`, hash, u.IdentityID, u.ID, u.TenantID, method).Scan(&exp); err != nil {
			return LoginResult{}, nil, err
		}
		return LoginResult{}, &apperr.Error{Status: http.StatusUnauthorized, Code: "MFA_REQUIRED", Message: "Masukkan kode dari aplikasi authenticator Anda.",
			Details: map[string]any{"mfaToken": raw, "expiresAt": exp.UTC()}}, nil
	}
	return s.startSession(ctx, r, u, pol, method, now)
}

// startSession opens the session of a member whose sign-in is complete (every factor proven).
func (s *Service) startSession(ctx context.Context, r *http.Request, u *userRow, pol Policy, method string, now time.Time) (LoginResult, error, error) {
	if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.identity SET last_login_at = now(), failed_logins = 0, locked_until = NULL WHERE id = $1`, u.IdentityID); err != nil {
		return LoginResult{}, nil, err
	}
	if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.membership SET last_login_at = now() WHERE id = $1`, u.ID); err != nil {
		return LoginResult{}, nil, err
	}
	if !pol.AllowConcurrentSessions {
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.session SET revoked_at = now() WHERE identity_id = $1 AND tenant_id = $2 AND revoked_at IS NULL`, u.IdentityID, u.TenantID); err != nil {
			return LoginResult{}, nil, err
		}
	}
	raw, hash := newSecret()
	sso, ssoHash := newSecret()
	var sid string
	var expires time.Time
	if err := s.DB.Q(ctx).QueryRow(ctx, `INSERT INTO auth.session (identity_id, membership_id, tenant_id, refresh_hash, sso_hash, method, ip, user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $8, $9, nullif($5, ''), nullif($6, ''), now() + make_interval(hours => $7)) RETURNING id, expires_at`,
		u.IdentityID, u.ID, u.TenantID, hash, clientIP(r), truncate(userAgent(r), 300), pol.SessionHours, ssoHash, method).Scan(&sid, &expires); err != nil {
		return LoginResult{}, nil, err
	}
	out, err := s.issue(ctx, u, sid, now)
	if err != nil {
		return LoginResult{}, nil, err
	}
	out.refresh, out.refreshExpires, out.sso = raw, expires, sso
	s.audit(ctx, r, "login", s.actorOf(u, sid, Access{}), u.Username, map[string]string{"local": "Masuk dengan password", "otp": "Masuk dengan kode email"}[method])
	return out, nil, nil
}

func userAgent(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.UserAgent()
}

func locked(until time.Time, minutes int) error {
	return &apperr.Error{Status: http.StatusLocked, Code: "LOCKED",
		Message: fmt.Sprintf("Akun terkunci karena terlalu banyak login gagal. Coba lagi dalam %d menit atau hubungi administrator.", minutes),
		Details: map[string]any{"lockedUntil": until.UTC()}}
}

// issue makes the access token of a session: sub = the person, mid = the membership, tid = the company.
func (s *Service) issue(ctx context.Context, u *userRow, sid string, now time.Time) (LoginResult, error) {
	u.Name = s.nameOf(ctx, u)
	acc, err := s.access(ctx, u)
	if err != nil {
		return LoginResult{}, err
	}
	exp := now.Add(s.Cfg.AccessTTL)
	jti, _ := newSecret()
	c := token.Claims{ID: jti[:16], Issuer: s.Cfg.Issuer, Audience: token.Audience, Subject: u.IdentityID, SessionID: sid, MemberID: u.ID, TenantID: u.TenantID,
		IssuedAt: now.Unix(), Expires: exp.Unix(), Username: u.Username, Name: u.Name, Role: u.RoleCode, Full: acc.Full}
	if !acc.Full {
		c.Grants = acc.Grants
	}
	// Until the password is changed the session may do nothing else, in this service or any other: the token
	// grants nothing (the answer still tells the page why).
	if u.MustChange != nil || u.mustEnroll() {
		c.Full, c.Grants = false, nil
	}
	tok, err := s.Keys.Sign(c)
	if err != nil {
		return LoginResult{}, err
	}
	tenants, err := s.tenantsOf(ctx, u.IdentityID)
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Token: tok, ExpiresAt: time.Unix(exp.Unix(), 0).UTC(), User: SessionUser{u.ID, u.Username, u.Name, u.RoleCode, u.IdentityID},
		Access: acc, MustChangePassword: u.MustChange, Tenant: TenantRef{u.TenantID, u.TenantCode, u.TenantName}, Tenants: tenants,
		PlatformAdmin: u.PlatformAdmin, MustEnrollMfa: u.mustEnroll()}, nil
}

// Refresh trades the refresh cookie for a new access token, and rotates the refresh token.
func (s *Service) Refresh(ctx context.Context, r *http.Request, raw string) (LoginResult, error) {
	ended := unauthorized("SESSION_ENDED", "Sesi sudah berakhir. Silakan masuk kembali.")
	if raw == "" || len(raw) > 100 {
		return LoginResult{}, ended
	}
	var out LoginResult
	var refusal error
	err := s.DB.InTx(ctx, func(ctx context.Context) error {
		refusal = nil
		now := s.now()
		h := hashOf(raw)
		var sid, mid, tid, iid string
		var expires time.Time
		var usable bool
		// Every clock check uses the database's now(): one clock for every instance of the service. Idle time
		// follows the policy of the company the session works in.
		err := s.DB.Q(ctx).QueryRow(ctx, `SELECT x.id, x.membership_id, x.tenant_id, x.identity_id, x.expires_at,
			x.revoked_at IS NULL AND x.expires_at > now() AND (p.idle_minutes = 0 OR x.last_seen_at > now() - make_interval(mins => p.idle_minutes))
			FROM auth.session x JOIN auth.security_policy p ON p.tenant_id = x.tenant_id WHERE x.refresh_hash = $1 FOR UPDATE OF x`, h).Scan(&sid, &mid, &tid, &iid, &expires, &usable)
		if errors.Is(err, pgx.ErrNoRows) {
			// A rotated token shown again: a second tab right now, or a stolen token (end that session).
			var recent bool
			err = s.DB.Q(ctx).QueryRow(ctx, `SELECT id, tenant_id, identity_id, last_seen_at > now() - make_interval(secs => $2)
				FROM auth.session WHERE previous_hash = $1 AND revoked_at IS NULL FOR UPDATE`, h, refreshGrace.Seconds()).Scan(&sid, &tid, &iid, &recent)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				refusal = ended
			case err != nil:
				return err
			case recent:
				refusal = apperr.Conflict("REFRESH_RACE", "Sesi baru saja diperbarui; ulangi.")
			default:
				if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.session SET revoked_at = now() WHERE id = $1`, sid); err != nil {
					return err
				}
				s.auditIn(ctx, r, tid, "session_revoked", nil, iid, "Token pembaruan lama dipakai lagi; sesi diakhiri")
				refusal = ended
			}
			return nil
		}
		if err != nil {
			return err
		}
		if !usable {
			_, _ = s.DB.Q(ctx).Exec(ctx, `UPDATE auth.session SET revoked_at = coalesce(revoked_at, now()) WHERE id = $1`, sid)
			refusal = ended
			return nil
		}
		u, err := s.userByID(ctx, tid, mid, false)
		if errors.Is(err, errNoUser) || err == nil && (!u.usable() || !s.employeeOK(ctx, u)) {
			refusal = unauthorized("ACCOUNT_INACTIVE", "Akun tidak aktif. Hubungi administrator.")
			return nil
		}
		if err != nil {
			return err
		}
		next, nh := newSecret()
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.session SET previous_hash = refresh_hash, refresh_hash = $2, last_seen_at = now() WHERE id = $1`, sid, nh); err != nil {
			return err
		}
		if out, err = s.issue(ctx, u, sid, now); err != nil {
			return err
		}
		out.refresh, out.refreshExpires = next, expires
		return nil
	})
	if err != nil {
		return LoginResult{}, err
	}
	return out, refusal
}

// SwitchTenant moves the caller's session to another company they are a member of (POST /auth/switch-tenant
// {tenant}): a new access token there and a rotated refresh token; tokens of the company left stop working.
func (s *Service) SwitchTenant(ctx context.Context, r *http.Request, body record.Values) (LoginResult, error) {
	a := ActorFrom(ctx)
	if a == nil {
		return LoginResult{}, unauthorized("SIGNED_OUT", "Sesi tidak ditemukan. Silakan masuk kembali.")
	}
	if a.MustChange != nil {
		return LoginResult{}, &apperr.Error{Status: http.StatusForbidden, Code: "MUST_CHANGE_PASSWORD", Message: "Ganti password Anda terlebih dahulu."}
	}
	key, _ := body["tenant"].(string)
	t, err := s.tenantRef(ctx, key)
	if err != nil {
		return LoginResult{}, err
	}
	if t == nil {
		return LoginResult{}, apperr.Validation([]apperr.Problem{{Field: "tenant", Message: "Pilih perusahaan."}})
	}
	var out LoginResult
	err = s.DB.InTx(ctx, func(ctx context.Context) error {
		var mid string
		err := s.DB.Q(ctx).QueryRow(ctx, `SELECT id FROM auth.membership WHERE identity_id = $1 AND tenant_id = $2 AND NOT is_deleted`, a.UserID, t.ID).Scan(&mid)
		if errors.Is(err, pgx.ErrNoRows) {
			return &apperr.Error{Status: 403, Code: "NOT_MEMBER", Message: "Anda bukan anggota perusahaan ini."}
		}
		if err != nil {
			return err
		}
		u, err := s.userByID(ctx, t.ID, mid, false)
		if err != nil {
			return err
		}
		if !u.usable() {
			return &apperr.Error{Status: 403, Code: "INACTIVE", Message: "Akun Anda di perusahaan ini nonaktif. Hubungi administrator."}
		}
		if !s.employeeOK(ctx, u) {
			return &apperr.Error{Status: 403, Code: "EMPLOYEE_INACTIVE", Message: "Karyawan pemilik akun ini nonaktif di perusahaan tersebut."}
		}
		raw, hash := newSecret()
		var expires time.Time
		if err := s.DB.Q(ctx).QueryRow(ctx, `UPDATE auth.session SET membership_id = $2, tenant_id = $3, previous_hash = NULL, refresh_hash = $4,
			last_seen_at = now() WHERE id = $1 AND revoked_at IS NULL RETURNING expires_at`, a.SessionID, u.ID, u.TenantID, hash).Scan(&expires); err != nil {
			return err
		}
		if out, err = s.issue(ctx, u, a.SessionID, s.now()); err != nil {
			return err
		}
		out.refresh, out.refreshExpires = raw, expires
		s.audit(ctx, r, "tenant_switched", s.actorOf(u, a.SessionID, Access{}), u.Username, "Pindah perusahaan dari sesi yang sama")
		return nil
	})
	return out, err
}

// Logout ends the session of the caller (or of the refresh cookie).
func (s *Service) Logout(ctx context.Context, r *http.Request, raw string) error {
	a := ActorFrom(ctx)
	switch {
	case a != nil:
		_, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.session SET revoked_at = now() WHERE id::text = $1 AND revoked_at IS NULL`, a.SessionID)
		s.audit(ctx, r, "logout", a, a.Username, "Keluar")
		return err
	case raw != "":
		_, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.session SET revoked_at = now() WHERE refresh_hash = $1 AND revoked_at IS NULL`, hashOf(raw))
		return err
	}
	return nil
}

// ChangePassword sets the caller's own password (one for every company); current may be left out only while a
// new one is required.
func (s *Service) ChangePassword(ctx context.Context, r *http.Request, body record.Values) error {
	a := ActorFrom(ctx)
	if a == nil {
		return unauthorized("SIGNED_OUT", "Sesi tidak ditemukan. Silakan masuk kembali.")
	}
	current, _ := body["current"].(string)
	next, _ := body["next"].(string)
	return s.DB.InTx(ctx, func(ctx context.Context) error {
		u, err := s.userByID(ctx, a.TenantID, a.MemberID, true)
		if err != nil {
			return notFound(err)
		}
		if u.MustChange == nil || current != "" {
			ok := false
			if u.PasswordHash != nil {
				ok, _ = password.Verify(current, *u.PasswordHash)
			}
			if !ok {
				return apperr.Validation([]apperr.Problem{{Field: "current", Message: "Password saat ini salah."}})
			}
		}
		if err := s.setPassword(ctx, u.IdentityID, u.PasswordHash, next); err != nil {
			return err
		}
		// Every other session of the person, in every company, signs in again with the new password.
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.session SET revoked_at = now() WHERE identity_id = $1 AND id::text <> $2 AND revoked_at IS NULL`, u.IdentityID, a.SessionID); err != nil {
			return err
		}
		s.audit(ctx, r, "user_updated", a, u.Username, "Password diganti oleh pengguna")
		s.mailPasswordChanged(ctx, u, s.emailOf(ctx, u))
		return nil
	})
}

// setPassword checks next against the person's policy (the strictest of their companies) and their last passwords,
// and stores it on the identity.
func (s *Service) setPassword(ctx context.Context, identityID string, current *string, next string) error {
	pol, err := s.identityPolicy(ctx, identityID)
	if err != nil {
		return err
	}
	if msg := pol.Rules().Problem(next); msg != "" {
		return apperr.Validation([]apperr.Problem{{Field: "next", Message: fmt.Sprintf("Password belum memenuhi: %s.", strings.ToLower(msg))}})
	}
	if current != nil {
		if same, _ := password.Verify(next, *current); same {
			return apperr.Validation([]apperr.Problem{{Field: "next", Message: "Password baru harus berbeda dari yang lama."}})
		}
	}
	if pol.PasswordHistory > 0 {
		rows, err := s.DB.Q(ctx).Query(ctx, `SELECT password_hash FROM auth.password_history WHERE identity_id = $1 ORDER BY created_at DESC LIMIT $2`, identityID, pol.PasswordHistory)
		if err != nil {
			return err
		}
		var old []string
		for rows.Next() {
			var h string
			_ = rows.Scan(&h)
			old = append(old, h)
		}
		rows.Close()
		for _, h := range old {
			if same, _ := password.Verify(next, h); same {
				return apperr.Validation([]apperr.Problem{{Field: "next", Message: fmt.Sprintf("Password ini sudah dipakai dalam %d password terakhir.", pol.PasswordHistory)}})
			}
		}
	}
	hash, err := password.Hash(next)
	if err != nil {
		return err
	}
	if current != nil {
		if _, err := s.DB.Q(ctx).Exec(ctx, `INSERT INTO auth.password_history (identity_id, password_hash) VALUES ($1, $2)`, identityID, *current); err != nil {
			return err
		}
	}
	_, err = s.DB.Q(ctx).Exec(ctx, `UPDATE auth.identity SET password_hash = $2, password_changed_at = now(), must_change_password = NULL,
		failed_logins = 0, locked_until = NULL WHERE id = $1`, identityID, hash)
	return err
}

// resetLink makes a single-use reset link for a person, made in a company (administrator, 24 h; forgot, 1 h).
func (s *Service) resetLink(ctx context.Context, u *userRow, ttl time.Duration) (string, time.Time, error) {
	raw, hash := newSecret()
	var exp time.Time
	err := s.DB.Q(ctx).QueryRow(ctx, `INSERT INTO auth.password_reset (token_hash, identity_id, tenant_id, expires_at) VALUES ($1, $2, $3, now() + make_interval(secs => $4))
		RETURNING expires_at`, hash, u.IdentityID, u.TenantID, ttl.Seconds()).Scan(&exp)
	return "/reset-password?token=" + raw, exp.UTC(), err
}

// AdminResetLink answers {link, expiresAt} (POST /users/:id/reset-link). Mailed when the member has an email;
// otherwise handed to the administrator, who sends it to the user.
func (s *Service) AdminResetLink(ctx context.Context, r *http.Request, id string) (map[string]any, error) {
	me, err := Require(ctx, "auth.users", "update")
	if err != nil {
		return nil, err
	}
	u, err := s.actorUser(ctx, me, id, false)
	if err != nil {
		return nil, notFound(err)
	}
	if u.IdentityIssuer != nil {
		return nil, apperr.Conflict("SSO_USER", "Pengguna SSO masuk lewat penyedia identitas; password tidak dipakai.")
	}
	to := s.emailOf(ctx, u)
	if to == "" {
		// A person who is a member of other companies too gets the link only by mail (the password is theirs).
		if shared, err := s.sharedElsewhere(ctx, u); err != nil {
			return nil, err
		} else if shared {
			return nil, apperr.Conflict("NO_EMAIL", "Orang ini juga anggota perusahaan lain dan tidak punya email; tautan reset tidak dapat dibuat di sini.")
		}
	}
	link, exp, err := s.resetLink(ctx, u, 24*time.Hour)
	if err != nil {
		return nil, err
	}
	if to != "" {
		s.mailResetLink(ctx, u, to, link, 24, true)
		s.audit(ctx, r, "user_updated", me, u.Username, "Tautan reset password dikirim ke email")
		return map[string]any{"link": nil, "expiresAt": exp, "sentTo": mail.Mask(to)}, nil
	}
	s.audit(ctx, r, "user_updated", me, u.Username, "Tautan reset password dibuat (tanpa email)")
	return map[string]any{"link": link, "expiresAt": exp, "sentTo": nil}, nil
}

// Forgot always answers the same, whether the account exists or not; the link goes to the person's email.
func (s *Service) Forgot(ctx context.Context, r *http.Request, body record.Values) (map[string]any, error) {
	ident, _ := body["username"].(string)
	if e, _ := body["email"].(string); strings.TrimSpace(ident) == "" {
		ident = e
	}
	tkey, _ := body["tenant"].(string)
	if tkey == "" && r != nil {
		tkey = r.Header.Get("X-Tenant")
	}
	same := map[string]any{"demoLink": nil}
	tenant, err := s.tenantRef(ctx, tkey)
	if err != nil || len(ident) > 254 {
		return same, nil
	}
	iid, _, err := s.findIdentity(ctx, ident, tenant)
	if err != nil || iid == "" {
		return same, nil
	}
	tid := ""
	if tenant != nil {
		tid = tenant.ID
	}
	// The membership the mail speaks for: the company given, else the first active one.
	var mid, mtid string
	err = s.DB.Q(ctx).QueryRow(ctx, `SELECT m.id, m.tenant_id FROM auth.membership m JOIN auth.tenant t ON t.id = m.tenant_id JOIN auth.identity i ON i.id = m.identity_id
		WHERE m.identity_id = $1 AND NOT m.is_deleted AND m.is_active AND t.is_active AND i.is_active AND ($2 = '' OR m.tenant_id::text = $2)
		ORDER BY t.name LIMIT 1`, iid, tid).Scan(&mid, &mtid)
	if err != nil {
		return same, nil
	}
	u, err := s.userByID(ctx, mtid, mid, false)
	if err != nil || u.IdentityIssuer != nil {
		return same, nil
	}
	if to := s.emailOf(ctx, u); to != "" {
		link, _, err := s.resetLink(ctx, u, time.Hour)
		if err != nil {
			return nil, err
		}
		s.mailResetLink(ctx, u, to, link, 1, false)
		s.auditIn(ctx, r, u.TenantID, "user_updated", nil, u.Username, "Tautan lupa password dikirim ke email")
	} else {
		s.auditIn(ctx, r, u.TenantID, "user_updated", nil, u.Username, "Lupa password diminta, tetapi akun tidak punya email")
	}
	return same, nil
}

// Reset sets a password with a reset token: single use, before it expires; every session of the person ends.
func (s *Service) Reset(ctx context.Context, r *http.Request, body record.Values) error {
	raw, _ := body["token"].(string)
	next, _ := body["password"].(string)
	return s.DB.InTx(ctx, func(ctx context.Context) error {
		var iid string
		var tid *string
		err := s.DB.Q(ctx).QueryRow(ctx, `SELECT identity_id, tenant_id FROM auth.password_reset WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() FOR UPDATE`, hashOf(raw)).Scan(&iid, &tid)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.Conflict("RESET_INVALID", "Tautan reset tidak berlaku atau sudah dipakai. Minta tautan baru.")
		}
		if err != nil {
			return err
		}
		id, err := s.lockIdentity(ctx, iid)
		if err != nil {
			return apperr.Conflict("RESET_INVALID", "Tautan reset tidak berlaku atau sudah dipakai. Minta tautan baru.")
		}
		if err := s.setPassword(ctx, id.ID, id.PasswordHash, next); err != nil {
			var e *apperr.Error
			if errors.As(err, &e) && e.Status == 422 { // the form names the field "password"
				return apperr.Validation([]apperr.Problem{{Field: "password", Message: e.Details.(map[string]any)["problems"].([]apperr.Problem)[0].Message}})
			}
			return err
		}
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.password_reset SET used_at = now() WHERE token_hash = $1`, hashOf(raw)); err != nil {
			return err
		}
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.session SET revoked_at = now() WHERE identity_id = $1 AND revoked_at IS NULL`, id.ID); err != nil {
			return err
		}
		// The member the link was made for (for the audit and the mail), when it still exists.
		var mid string
		if tid != nil && s.DB.Q(ctx).QueryRow(ctx, `SELECT id FROM auth.membership WHERE identity_id = $1 AND tenant_id = $2 AND NOT is_deleted`, id.ID, *tid).Scan(&mid) == nil {
			if u, err := s.userByID(ctx, *tid, mid, false); err == nil {
				s.auditIn(ctx, r, u.TenantID, "user_updated", nil, u.Username, "Password diatur ulang dengan tautan")
				s.mailPasswordChanged(ctx, u, s.emailOf(ctx, u))
			}
		}
		return nil
	})
}
