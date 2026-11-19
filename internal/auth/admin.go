package auth

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"alir.local/auth-service/internal/catalog"
	"alir.local/auth-service/internal/platform/apperr"
	"alir.local/auth-service/internal/platform/record"
)

/* ---------------- Public sign-in settings ---------------- */

// LoginOptions are the sign-in settings of a company (?tenant=code, or the X-Tenant header of its address); without
// a company: password sign-in with the default rules (the company is chosen after the password).
func (s *Service) LoginOptions(ctx context.Context, tenantKey string) (map[string]any, error) {
	t, err := s.tenantRef(ctx, tenantKey)
	if err != nil {
		return nil, err
	}
	p := Policy{PasswordMinLength: 8, RequireNumber: true, AllowLocalLogin: true}
	if t != nil {
		if p, err = s.policy(ctx, t.ID); err != nil {
			return nil, err
		}
	}
	var captcha any
	if s.Captcha != nil {
		captcha = map[string]string{"provider": s.Cfg.CaptchaProvider, "siteKey": s.Cfg.CaptchaSiteKey}
	}
	otp := t == nil || p.AllowEmailOtp
	idps := []IdpButton{}
	if t != nil {
		if idps, err = s.idpButtons(ctx, t.ID); err != nil {
			return nil, err
		}
	}
	return map[string]any{"localEnabled": p.AllowLocalLogin, "ssoEnabled": p.SsoEnabled, "ssoLabel": nil, "demoHint": nil, "tenant": t, "emailLogin": true,
		"emailOtp": otp, "selfSignup": t != nil && p.SelfSignupEnabled, "captcha": captcha, "identityProviders": idps,
		"terms":    map[string]any{"version": s.Cfg.TermsVersion, "url": nilIfEmpty(s.Cfg.TermsURL)},
		"password": map[string]any{"passwordMinLength": p.PasswordMinLength, "requireUppercase": p.RequireUppercase, "requireNumber": p.RequireNumber, "requireSymbol": p.RequireSymbol}}, nil
}

/* ---------------- Own account ---------------- */

func (s *Service) Me(ctx context.Context) (map[string]any, error) {
	a := ActorFrom(ctx)
	if a == nil {
		return nil, unauthorized("SIGNED_OUT", "Sesi tidak ditemukan. Silakan masuk kembali.")
	}
	u := a.user
	u.Name = s.nameOf(ctx, u)
	scope := "Belum ditentukan"
	if u.Level != nil {
		if i := levelIndex(*u.Level); i >= 0 {
			if code := *fields[i].get(&u.Scope); code != nil {
				name := *code
				if t, err := s.Org.Tree(ctx, u.TenantID, false); err == nil {
					if n := t.names(u.Scope)[fields[i].key]; n != nil {
						name = *n
					}
				}
				scope = fmt.Sprintf("%s (%s)", name, *code)
			}
		}
	}
	method := "local"
	if u.IdentityIssuer != nil {
		method = "sso"
	}
	tenants, err := s.tenantsOf(ctx, u.IdentityID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": u.ID, "identityId": u.IdentityID, "username": u.Username, "name": u.Name, "role": u.RoleCode, "roleName": u.RoleName, "scope": scope,
		"method": method, "lastLoginAt": utc(u.LastLogin), "passwordChangedAt": utc(u.PasswordChangedAt), "email": s.emailOf(ctx, u),
		"tenant": TenantRef{u.TenantID, u.TenantCode, u.TenantName}, "tenants": tenants, "platformAdmin": u.PlatformAdmin}, nil
}

/* ---------------- Sessions ---------------- */

type sessionRow struct {
	ID        string      `json:"id"`
	User      SessionUser `json:"user"`
	Tenant    TenantRef   `json:"tenant"`
	IP        *string     `json:"ip"`
	UserAgent *string     `json:"userAgent"`
	Method    string      `json:"method"`
	CreatedAt time.Time   `json:"createdAt"`
	LastSeen  time.Time   `json:"lastSeenAt"`
	ExpiresAt time.Time   `json:"expiresAt"`
	Current   bool        `json:"current"`
}

// sessions are the live sessions of a person (identityID, every company) or of a company (tenantID).
func (s *Service) sessions(ctx context.Context, identityID, tenantID string) ([]sessionRow, error) {
	a := ActorFrom(ctx)
	q := `SELECT x.id, u.id, u.username, u.name, r.code, u.identity_id, t.id, t.code, t.name, x.ip, x.user_agent, x.method, x.created_at, x.last_seen_at, x.expires_at
		FROM auth.session x JOIN auth.membership u ON u.id = x.membership_id JOIN auth.role r ON r.id = u.role_id JOIN auth.tenant t ON t.id = x.tenant_id
		WHERE x.revoked_at IS NULL AND x.expires_at > now() AND ($1 = '' OR x.identity_id::text = $1) AND ($2 = '' OR x.tenant_id::text = $2)
		ORDER BY x.last_seen_at DESC LIMIT 1000`
	rows, err := s.DB.Q(ctx).Query(ctx, q, identityID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []sessionRow{}
	for rows.Next() {
		var x sessionRow
		if err := rows.Scan(&x.ID, &x.User.ID, &x.User.Username, &x.User.Name, &x.User.Role, &x.User.IdentityID, &x.Tenant.ID, &x.Tenant.Code, &x.Tenant.Name,
			&x.IP, &x.UserAgent, &x.Method, &x.CreatedAt, &x.LastSeen, &x.ExpiresAt); err != nil {
			return nil, err
		}
		x.CreatedAt, x.LastSeen, x.ExpiresAt = x.CreatedAt.UTC(), x.LastSeen.UTC(), x.ExpiresAt.UTC()
		x.Current = a != nil && x.ID == a.SessionID
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Service) MySessions(ctx context.Context) ([]sessionRow, error) {
	a := ActorFrom(ctx)
	if a == nil {
		return nil, unauthorized("SIGNED_OUT", "Sesi tidak ditemukan. Silakan masuk kembali.")
	}
	return s.sessions(ctx, a.UserID, "")
}

func (s *Service) AllSessions(ctx context.Context) ([]sessionRow, error) {
	me, err := Require(ctx, "auth.sessions", "read")
	if err != nil {
		return nil, err
	}
	return s.sessions(ctx, "", me.TenantID)
}

// RevokeSession ends one session: an administrator's (any) or the caller's own (mine, never the current one).
func (s *Service) RevokeSession(ctx context.Context, id string, mine bool) error {
	a := ActorFrom(ctx)
	if !mine {
		var err error
		if a, err = Require(ctx, "auth.sessions", "delete"); err != nil {
			return err
		}
	} else if a == nil {
		return unauthorized("SIGNED_OUT", "Sesi tidak ditemukan. Silakan masuk kembali.")
	}
	if !uuidLike.MatchString(id) {
		return apperr.NotFound()
	}
	if mine && id == a.SessionID {
		return apperr.Conflict("CURRENT", "Sesi ini sedang dipakai; gunakan Keluar.")
	}
	// Mine: any session of the person. An administrator's: a session working in their company.
	var username string
	err := s.DB.Q(ctx).QueryRow(ctx, `UPDATE auth.session x SET revoked_at = now() FROM auth.membership u
		WHERE x.id = $1 AND u.id = x.membership_id AND x.revoked_at IS NULL
		AND (($3 AND x.identity_id::text = $2) OR (NOT $3 AND x.tenant_id::text = $2)) RETURNING u.username`,
		id, map[bool]string{true: a.UserID, false: a.TenantID}[mine], mine).Scan(&username)
	if err != nil {
		return apperr.NotFound()
	}
	detail := "Sesi dicabut oleh administrator"
	if mine {
		detail = "Sesi diakhiri oleh pengguna"
	}
	s.audit(ctx, requestOf(ctx), "session_revoked", a, username, detail)
	return nil
}

func (s *Service) RevokeOtherSessions(ctx context.Context) (int64, error) {
	a := ActorFrom(ctx)
	if a == nil {
		return 0, unauthorized("SIGNED_OUT", "Sesi tidak ditemukan. Silakan masuk kembali.")
	}
	tag, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.session SET revoked_at = now() WHERE identity_id = $1 AND id::text <> $2 AND revoked_at IS NULL`, a.UserID, a.SessionID)
	if err != nil {
		return 0, err
	}
	s.audit(ctx, requestOf(ctx), "session_revoked", a, a.Username, fmt.Sprintf("%d sesi lain diakhiri oleh pengguna", tag.RowsAffected()))
	return tag.RowsAffected(), nil
}

/* ---------------- Security policy ---------------- */

func (s *Service) GetPolicy(ctx context.Context) (Policy, error) {
	me, err := Require(ctx, "auth.security", "read")
	if err != nil {
		return Policy{}, err
	}
	return s.policy(ctx, me.TenantID)
}

func (s *Service) SetPolicy(ctx context.Context, body record.Values) (Policy, error) {
	me, err := Require(ctx, "auth.security", "update")
	if err != nil {
		return Policy{}, err
	}
	var p record.Problems
	n := func(key, label string, min, max int) int {
		v := record.RequiredInt(body, key, label, min, &p)
		if !p.Has(key) && v > max {
			p.Add(key, fmt.Sprintf("%s paling besar %d.", label, max))
		}
		return v
	}
	b := func(key, label string) bool { return record.Bool(body, key, label, false, &p) }
	x := Policy{
		PasswordMinLength: n("passwordMinLength", "Panjang minimal password", 6, 128), RequireUppercase: b("requireUppercase", "Huruf besar"),
		RequireNumber: b("requireNumber", "Angka"), RequireSymbol: b("requireSymbol", "Simbol"),
		PasswordExpiryDays: n("passwordExpiryDays", "Masa berlaku password", 0, 3650), PasswordHistory: n("passwordHistory", "Riwayat password", 0, 24),
		MaxFailedAttempts: n("maxFailedAttempts", "Batas login gagal", 0, 100), LockoutMinutes: n("lockoutMinutes", "Lama terkunci", 1, 1440),
		SessionHours: n("sessionHours", "Lama sesi", 1, 720), IdleMinutes: n("idleMinutes", "Batas diam", 0, 1440),
		AllowConcurrentSessions: b("allowConcurrentSessions", "Sesi bersamaan"), AllowLocalLogin: b("allowLocalLogin", "Login password"),
		SsoEnabled: b("ssoEnabled", "SSO"),
		SsoIssuer:  record.OptionalText(body, "ssoIssuer", "SSO issuer", 200, &p), SsoClientID: record.OptionalText(body, "ssoClientId", "SSO client id", 200, &p),
	}
	if !x.AllowLocalLogin && !x.SsoEnabled {
		p.Add("allowLocalLogin", "Aktifkan login password atau SSO; tanpa keduanya tidak ada yang bisa masuk.")
	}
	if x.SsoEnabled && (x.SsoIssuer == nil || x.SsoClientID == nil) {
		p.Add("ssoIssuer", "SSO aktif butuh issuer dan client id.")
	}
	// Self sign-up and email codes: fields left out keep their value (older forms do not send them).
	cur, err := s.policy(ctx, me.TenantID)
	if err != nil {
		return Policy{}, err
	}
	x.SelfSignupEnabled, x.SelfSignupRole, x.AllowEmailOtp = cur.SelfSignupEnabled, cur.SelfSignupRole, cur.AllowEmailOtp
	if _, sent := body["selfSignupEnabled"]; sent {
		x.SelfSignupEnabled = b("selfSignupEnabled", "Pendaftaran mandiri")
	}
	if _, sent := body["selfSignupRole"]; sent {
		x.SelfSignupRole = record.OptionalText(body, "selfSignupRole", "Peran pendaftar", record.MaxCode, &p)
	}
	if _, sent := body["allowEmailOtp"]; sent {
		x.AllowEmailOtp = b("allowEmailOtp", "Login dengan kode email")
	}
	x.MfaMode = cur.MfaMode
	if _, sent := body["mfaMode"]; sent {
		m, _ := body["mfaMode"].(string)
		if m != "off" && m != "optional" && m != "required" {
			p.Add("mfaMode", "MFA: pilih nonaktif, opsional, atau wajib.")
		} else {
			x.MfaMode = m
		}
	}
	// Requiring MFA while one's own account has none would lock this very session out at once.
	if x.MfaMode == "required" && cur.MfaMode != "required" && (me.user == nil || !me.user.MfaEnrolled) {
		p.Add("mfaMode", "Pasang MFA (aplikasi authenticator) untuk akun Anda dulu sebelum mewajibkannya.")
	}
	var signupRoleID *string
	if x.SelfSignupRole != nil && !p.Has("selfSignupRole") {
		var id string
		err := s.DB.Q(ctx).QueryRow(ctx, `SELECT id FROM auth.role WHERE tenant_id = $1 AND code = $2 AND is_active AND NOT is_deleted`, me.TenantID, *x.SelfSignupRole).Scan(&id)
		switch {
		case *x.SelfSignupRole == "admin":
			p.Add("selfSignupRole", "Pendaftar mandiri tidak boleh langsung menjadi Admin.")
		case err != nil:
			p.Add("selfSignupRole", "Peran tidak tersedia.")
		default:
			signupRoleID = &id
		}
	}
	if x.SelfSignupEnabled && x.SelfSignupRole == nil && !p.Has("selfSignupRole") {
		p.Add("selfSignupRole", "Pendaftaran mandiri butuh peran untuk anggota yang mendaftar.")
	}
	if len(p) > 0 {
		return Policy{}, apperr.Validation(p)
	}
	if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.security_policy SET password_min_length = $1, require_uppercase = $2, require_number = $3,
		require_symbol = $4, password_expiry_days = $5, password_history = $6, max_failed_attempts = $7, lockout_minutes = $8,
		session_hours = $9, idle_minutes = $10, allow_concurrent_sessions = $11, allow_local_login = $12, sso_enabled = $13,
		sso_issuer = $14, sso_client_id = $15, updated_at = now(), updated_by = $16, self_signup_enabled = $18, self_signup_role_id = $19,
		allow_email_otp = $20, mfa_mode = $21 WHERE tenant_id = $17`,
		x.PasswordMinLength, x.RequireUppercase, x.RequireNumber, x.RequireSymbol, x.PasswordExpiryDays, x.PasswordHistory, x.MaxFailedAttempts,
		x.LockoutMinutes, x.SessionHours, x.IdleMinutes, x.AllowConcurrentSessions, x.AllowLocalLogin, x.SsoEnabled, x.SsoIssuer, x.SsoClientID, me.UserID, me.TenantID, x.SelfSignupEnabled, signupRoleID, x.AllowEmailOtp, x.MfaMode); err != nil {
		return Policy{}, err
	}
	s.audit(ctx, requestOf(ctx), "policy_changed", me, "", "Kebijakan keamanan diperbarui")
	return s.policy(ctx, me.TenantID)
}

/* ---------------- Unit module access ---------------- */

type unitAccess struct {
	All       bool       `json:"all"`
	Modules   []string   `json:"modules"`
	UpdatedAt *time.Time `json:"updatedAt"`
	UpdatedBy *string    `json:"updatedBy"`
}

func (s *Service) UnitAccess(ctx context.Context) (map[string]unitAccess, error) {
	me, err := Require(ctx, "auth.unitAccess", "read")
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.Q(ctx).Query(ctx, `SELECT a.unit_code, a.all_modules, a.modules, a.updated_at, u.name FROM auth.unit_access a
		LEFT JOIN auth.identity u ON u.id = a.updated_by WHERE a.tenant_id = $1`, me.TenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]unitAccess{}
	for rows.Next() {
		var code string
		var x unitAccess
		if err := rows.Scan(&code, &x.All, &x.Modules, &x.UpdatedAt, &x.UpdatedBy); err != nil {
			return nil, err
		}
		x.UpdatedAt = utc(x.UpdatedAt)
		out[code] = x
	}
	// Units without a row may use every module.
	if t, err := s.Org.Tree(ctx, me.TenantID, false); err == nil {
		for _, u := range t.options.Units {
			if _, ok := out[u.Code]; !ok {
				out[u.Code] = unitAccess{All: true, Modules: []string{}}
			}
		}
	}
	return out, rows.Err()
}

func (s *Service) SetUnitAccess(ctx context.Context, unit string, body record.Values) (unitAccess, error) {
	me, err := Require(ctx, "auth.unitAccess", "update")
	if err != nil {
		return unitAccess{}, err
	}
	t, err := s.Org.Tree(ctx, me.TenantID, false)
	if err != nil {
		return unitAccess{}, &apperr.Error{Status: 503, Code: "ORG_UNAVAILABLE", Message: "Master organisasi (Portal Master) tidak dapat dibaca; coba lagi sebentar lagi."}
	}
	u, ok := t.units[unit]
	if !ok || u.LevelCode != "unit" {
		return unitAccess{}, &apperr.Error{Status: 404, Code: "NOT_FOUND", Message: "Unit operasional tidak ditemukan."}
	}
	var p record.Problems
	all := record.Bool(body, "all", "Semua modul", false, &p)
	modules := record.Codes(body, "modules", "Modul", &p)
	for _, m := range modules {
		if !catalog.Known(m) {
			p.Add("modules", fmt.Sprintf("Modul %s tidak dikenal.", m))
		}
	}
	if !all && len(modules) == 0 && !p.Has("modules") {
		p.Add("modules", "Pilih minimal satu modul, atau izinkan semua modul.")
	}
	if len(p) > 0 {
		return unitAccess{}, apperr.Validation(p)
	}
	if all {
		modules = []string{}
	}
	slices.Sort(modules)
	if _, err := s.DB.Q(ctx).Exec(ctx, `INSERT INTO auth.unit_access (tenant_id, unit_code, all_modules, modules, updated_at, updated_by) VALUES ($5, $1, $2, $3, now(), $4)
		ON CONFLICT (tenant_id, unit_code) DO UPDATE SET all_modules = $2, modules = $3, updated_at = now(), updated_by = $4`, unit, all, modules, me.UserID, me.TenantID); err != nil {
		return unitAccess{}, err
	}
	detail := "Unit boleh mengakses semua modul"
	if !all {
		detail = fmt.Sprintf("Akses modul unit: %d modul", len(modules))
	}
	s.audit(ctx, requestOf(ctx), "access_changed", me, u.Name, detail)
	now := s.now()
	return unitAccess{All: all, Modules: modules, UpdatedAt: &now, UpdatedBy: &me.Name}, nil
}

/* ---------------- Audit log ---------------- */

type auditEvent struct {
	ID    string    `json:"id"`
	At    time.Time `json:"at"`
	Type  string    `json:"type"`
	Actor *struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Name     string `json:"name"`
	} `json:"actor"`
	Target *string `json:"target"`
	IP     *string `json:"ip"`
	Detail *string `json:"detail"`
}

// Audit is one page of the log (GET /auth/audit?q&type&from&to&page&size). from/to are dates, read in UTC.
func (s *Service) Audit(ctx context.Context, q map[string]string) (map[string]any, error) {
	me, err := Require(ctx, "auth.audit", "read")
	if err != nil {
		return nil, err
	}
	size, _ := strconv.Atoi(q["size"])
	if size < 1 || size > 200 {
		size = 25
	}
	page, _ := strconv.Atoi(q["page"])
	if page < 1 {
		page = 1
	}
	var from, to *time.Time
	if t, err := time.Parse(time.DateOnly, q["from"]); err == nil {
		from = &t
	}
	if t, err := time.Parse(time.DateOnly, q["to"]); err == nil {
		end := t.Add(24 * time.Hour)
		to = &end
	}
	typ := q["type"]
	if typ == "all" {
		typ = ""
	}
	term := "%" + strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(q["q"]), "%", `\%`), "_", `\_`) + "%"
	where := ` WHERE tenant_id = $7 AND ($1 = '' OR type = $1) AND ($2::timestamptz IS NULL OR at >= $2) AND ($3::timestamptz IS NULL OR at < $3)
		AND lower(concat_ws(' ', actor_name, actor_username, target, ip, detail)) LIKE $4`
	var total int
	if err := s.DB.Q(ctx).QueryRow(ctx, `SELECT count(*) FROM auth.audit_event`+strings.Replace(where, "$7", "$5", 1), typ, from, to, term, me.TenantID).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := s.DB.Q(ctx).Query(ctx, `SELECT id, at, type, actor_id, actor_username, actor_name, target, ip, detail FROM auth.audit_event`+where+
		` ORDER BY at DESC, id DESC LIMIT $5 OFFSET $6`, typ, from, to, term, size, (page-1)*size, me.TenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []auditEvent{}
	for rows.Next() {
		var e auditEvent
		var aid, aun, ana *string
		if err := rows.Scan(&e.ID, &e.At, &e.Type, &aid, &aun, &ana, &e.Target, &e.IP, &e.Detail); err != nil {
			return nil, err
		}
		e.At = e.At.UTC()
		if aid != nil {
			e.Actor = &struct {
				ID       string `json:"id"`
				Username string `json:"username"`
				Name     string `json:"name"`
			}{*aid, deref(aun), deref(ana)}
		}
		items = append(items, e)
	}
	return map[string]any{"items": items, "total": total}, rows.Err()
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

/* ---------------- Organisation copy ---------------- */

func (s *Service) OrgOptions(ctx context.Context) (Options, error) {
	a := ActorFrom(ctx)
	if a == nil || a.MustChange != nil || !a.Access.May("auth.users", "read") && !a.Access.May("auth.organization", "read") && !a.Access.May("auth.unitAccess", "read") {
		_, err := Require(ctx, "auth.organization", "read")
		return Options{}, err
	}
	t, err := s.Org.Tree(ctx, a.TenantID, false)
	if err != nil {
		return Options{}, &apperr.Error{Status: 503, Code: "ORG_UNAVAILABLE", Message: "Master organisasi (Portal Master) tidak dapat dibaca; coba lagi sebentar lagi."}
	}
	return t.options, nil
}

func (s *Service) orgStatus(t *tree) map[string]any {
	o := t.options
	c := func(n int) map[string]int { return map[string]int{"total": n, "active": n, "deactivated": 0} }
	tables := map[string]any{"group": c(len(o.Groups)), "region": c(len(o.Regions)), "wilayah": c(len(o.Wilayahs)), "company": c(len(o.Companies)),
		"unit": c(len(o.Units)), "gmk": c(0), "gmkUnit": c(0), "orgLevel1": c(len(o.OrgLevel1s)), "orgLevel2": c(len(o.OrgLevel2s)), "orgLevel3": c(len(o.OrgLevel3s))}
	active := map[string]int{}
	for k, v := range tables {
		active[k] = v.(map[string]int)["active"]
	}
	return map[string]any{"configured": true, "database": "Portal Master", "lastSync": map[string]any{"at": t.at, "userId": nil, "tables": tables}, "active": active}
}

func (s *Service) OrgStatus(ctx context.Context) (map[string]any, error) {
	me, err := Require(ctx, "auth.organization", "read")
	if err != nil {
		return nil, err
	}
	t, err := s.Org.Tree(ctx, me.TenantID, false)
	if err != nil {
		return map[string]any{"configured": true, "database": "Portal Master", "lastSync": nil, "active": map[string]int{}}, nil
	}
	return s.orgStatus(t), nil
}

func (s *Service) OrgSync(ctx context.Context) (map[string]any, error) {
	me, err := Require(ctx, "auth.organization", "update")
	if err != nil {
		return nil, err
	}
	start := time.Now()
	t, err := s.Org.Tree(ctx, me.TenantID, true)
	if err != nil {
		return nil, &apperr.Error{Status: 503, Code: "ORG_UNAVAILABLE", Message: "Portal Master tidak dapat dihubungi: " + err.Error()}
	}
	s.audit(ctx, requestOf(ctx), "org_synced", me, "", "Master organisasi disalin ulang dari Portal Master")
	st := s.orgStatus(t)
	return map[string]any{"at": t.at, "database": "Portal Master", "durationMs": time.Since(start).Milliseconds(), "tables": st["lastSync"].(map[string]any)["tables"]}, nil
}
