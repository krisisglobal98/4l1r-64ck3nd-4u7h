// Package auth is the Authentication service of ALIR: sign-in with rotating sessions, accounts (Pengguna), roles
// and their grants (Peran & Hak Akses), unit module access, the security policy, sessions and the audit log.
// It answers the contract the ALIR frontend reads (docs/auth-api.md, src/services/api/demoApi.ts behaves the same).
package auth

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"alir.local/auth-service/internal/catalog"
	"alir.local/auth-service/internal/oidcrp"
	"alir.local/auth-service/internal/password"
	"alir.local/auth-service/internal/platform/apperr"
	"alir.local/auth-service/internal/platform/codeprefix"
	"alir.local/auth-service/internal/platform/config"
	"alir.local/auth-service/internal/platform/database"
	"alir.local/auth-service/internal/platform/httpx/reqid"
	"alir.local/auth-service/internal/secretbox"
	"alir.local/auth-service/internal/token"
)

type Service struct {
	DB    *database.DB
	Keys  *token.Keys
	Org   *Org
	Cfg   config.Config
	Codes codeprefix.Postgres
	Now   func() time.Time // the clock (tests set it)
	// Captcha of the public forms (nil: none); Limits of them (nil: DefaultLimits).
	Captcha Captcha
	Limits  *Limits
	// Box seals TOTP and identity provider secrets.
	Box *secretbox.Box
	// RP signs people in through the companies' identity providers.
	RP *oidcrp.Client
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

/* ---------------- Security policy ---------------- */

// Policy is the security policy (GET/PUT /auth/policy), the shape of types/auth.ts SecurityPolicy.
type Policy struct {
	PasswordMinLength       int     `json:"passwordMinLength"`
	RequireUppercase        bool    `json:"requireUppercase"`
	RequireNumber           bool    `json:"requireNumber"`
	RequireSymbol           bool    `json:"requireSymbol"`
	PasswordExpiryDays      int     `json:"passwordExpiryDays"`
	PasswordHistory         int     `json:"passwordHistory"`
	MaxFailedAttempts       int     `json:"maxFailedAttempts"`
	LockoutMinutes          int     `json:"lockoutMinutes"`
	SessionHours            int     `json:"sessionHours"`
	IdleMinutes             int     `json:"idleMinutes"`
	AllowConcurrentSessions bool    `json:"allowConcurrentSessions"`
	AllowLocalLogin         bool    `json:"allowLocalLogin"`
	SsoEnabled              bool    `json:"ssoEnabled"`
	SsoIssuer               *string `json:"ssoIssuer"`
	SsoClientID             *string `json:"ssoClientId"`
	// Self sign-up of people who are not employees (vendors, applicants): open or not, and the role they get.
	SelfSignupEnabled bool    `json:"selfSignupEnabled"`
	SelfSignupRole    *string `json:"selfSignupRole"`
	// Sign-in with a one-time code sent to the person's email.
	AllowEmailOtp bool `json:"allowEmailOtp"`
	// Multi-factor authentication: off (not offered) | optional | required (members must enrol).
	MfaMode   string     `json:"mfaMode"`
	UpdatedAt *time.Time `json:"updatedAt"`
	UpdatedBy *string    `json:"updatedBy"`
}

func (p Policy) Rules() password.Rules {
	return password.Rules{MinLength: p.PasswordMinLength, RequireUppercase: p.RequireUppercase, RequireNumber: p.RequireNumber, RequireSymbol: p.RequireSymbol}
}

// policy is the security policy of a tenant.
func (s *Service) policy(ctx context.Context, tenantID string) (Policy, error) {
	var p Policy
	err := s.DB.Q(ctx).QueryRow(ctx, `SELECT p.password_min_length, p.require_uppercase, p.require_number, p.require_symbol, p.password_expiry_days,
		p.password_history, p.max_failed_attempts, p.lockout_minutes, p.session_hours, p.idle_minutes, p.allow_concurrent_sessions,
		p.allow_local_login, p.sso_enabled, p.sso_issuer, p.sso_client_id, p.updated_at, u.name, p.self_signup_enabled, sr.code, p.allow_email_otp, p.mfa_mode
		FROM auth.security_policy p LEFT JOIN auth.identity u ON u.id = p.updated_by LEFT JOIN auth.role sr ON sr.id = p.self_signup_role_id
		WHERE p.tenant_id = $1`, tenantID).Scan(
		&p.PasswordMinLength, &p.RequireUppercase, &p.RequireNumber, &p.RequireSymbol, &p.PasswordExpiryDays, &p.PasswordHistory,
		&p.MaxFailedAttempts, &p.LockoutMinutes, &p.SessionHours, &p.IdleMinutes, &p.AllowConcurrentSessions, &p.AllowLocalLogin,
		&p.SsoEnabled, &p.SsoIssuer, &p.SsoClientID, &p.UpdatedAt, &p.UpdatedBy, &p.SelfSignupEnabled, &p.SelfSignupRole, &p.AllowEmailOtp, &p.MfaMode)
	if p.UpdatedAt != nil {
		t := p.UpdatedAt.UTC()
		p.UpdatedAt = &t
	}
	return p, err
}

// identityPolicy is what holds for a person's password and lockout, which are one for every company they are a
// member of: the strictest rule of those companies (the defaults when they are a member of none).
func (s *Service) identityPolicy(ctx context.Context, identityID string) (Policy, error) {
	p := Policy{PasswordMinLength: 8, RequireNumber: true, MaxFailedAttempts: 5, LockoutMinutes: 15}
	var n int
	err := s.DB.Q(ctx).QueryRow(ctx, `SELECT count(*), coalesce(max(p.password_min_length), 8), coalesce(bool_or(p.require_uppercase), false),
		coalesce(bool_or(p.require_number), true), coalesce(bool_or(p.require_symbol), false), coalesce(max(p.password_history), 0),
		coalesce(min(p.max_failed_attempts) FILTER (WHERE p.max_failed_attempts > 0), 0), coalesce(max(p.lockout_minutes), 15)
		FROM auth.membership m JOIN auth.security_policy p ON p.tenant_id = m.tenant_id
		WHERE m.identity_id = $1 AND NOT m.is_deleted`, identityID).Scan(&n, &p.PasswordMinLength, &p.RequireUppercase, &p.RequireNumber,
		&p.RequireSymbol, &p.PasswordHistory, &p.MaxFailedAttempts, &p.LockoutMinutes)
	if err == nil && n == 0 {
		p.MaxFailedAttempts = 5
	}
	return p, err
}

/* ---------------- Effective access ---------------- */

// Access is what the signed-in user may do (types/session.ts EffectiveAccess): role grants limited to the modules
// of their operational unit. Not limited: the built-in Admin, and accounts scoped above unit level.
type Access struct {
	Role        string         `json:"role"`
	Modules     []string       `json:"modules"`
	Grants      catalog.Grants `json:"grants"`
	Unit        *string        `json:"unit"`
	UnitModules []string       `json:"unitModules"`
	Full        bool           `json:"full"`
}

// May says whether the access allows action on menu.
func (a Access) May(menu, action string) bool {
	return a.Full || slices.Contains(a.Grants[menu], action)
}

func (s *Service) access(ctx context.Context, u *userRow) (Access, error) {
	if u.RoleCode == "admin" {
		return Access{Role: "admin", Modules: catalog.ModuleIDs(), Grants: catalog.Full(), Full: true}, nil
	}
	granted := catalog.Grants{}
	if u.RoleActive {
		rows, err := s.DB.Q(ctx).Query(ctx, `SELECT menu, actions FROM auth.role_grant WHERE role_id = $1`, u.RoleID)
		if err != nil {
			return Access{}, err
		}
		for rows.Next() {
			var menu string
			var actions []string
			if err := rows.Scan(&menu, &actions); err != nil {
				rows.Close()
				return Access{}, err
			}
			granted[menu] = actions
		}
		rows.Close()
	}
	var unit *string
	var all = true
	var unitModules []string
	if u.Level != nil && unitLevels[*u.Level] && u.Scope.OperationalUnitCode != nil {
		err := s.DB.Q(ctx).QueryRow(ctx, `SELECT all_modules, modules FROM auth.unit_access WHERE tenant_id = $1 AND unit_code = $2`, u.TenantID, *u.Scope.OperationalUnitCode).Scan(&all, &unitModules)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			all = true
		case err != nil:
			return Access{}, err
		default:
			if !all {
				unit = u.Scope.OperationalUnitCode
			}
		}
	}
	out := Access{Role: u.RoleCode, Modules: []string{}, Grants: catalog.Grants{}, Unit: unit}
	if !all {
		out.UnitModules = unitModules
	}
	for _, m := range catalog.Modules() {
		if !all && !slices.Contains(unitModules, m.ID) {
			continue
		}
		reads := false
		for _, menu := range m.Menus {
			if a := granted[menu.ID]; len(a) > 0 {
				out.Grants[menu.ID] = slices.Clone(a)
				reads = reads || slices.Contains(a, "read")
			}
		}
		if reads {
			out.Modules = append(out.Modules, m.ID)
		}
	}
	return out, nil
}

/* ---------------- Audit ---------------- */

// audit records an event in the actor's tenant.
func (s *Service) audit(ctx context.Context, r *http.Request, typ string, actor *Actor, target, detail string) {
	tid := ""
	if actor != nil {
		tid = actor.TenantID
	}
	s.auditIn(ctx, r, tid, typ, actor, target, detail)
}

// auditIn records an event in a tenant ("" = an event of the installation, e.g. a failed sign-in of no company).
func (s *Service) auditIn(ctx context.Context, r *http.Request, tenantID, typ string, actor *Actor, target, detail string) {
	var id, username, name *string
	if actor != nil {
		id, username, name = &actor.UserID, &actor.Username, &actor.Name
	}
	rid := ""
	if r != nil {
		rid = reqid.From(r.Context())
	}
	_, _ = s.DB.Q(ctx).Exec(ctx, `INSERT INTO auth.audit_event (tenant_id, type, actor_id, actor_username, actor_name, target, ip, detail, request_id)
		VALUES (nullif($9, '')::uuid, $1, $2, $3, $4, nullif($5, ''), nullif($6, ''), nullif($7, ''), nullif($8, ''))`,
		typ, id, username, name, truncate(target, 200), clientIP(r), truncate(detail, 500), rid, tenantID)
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// TrustForwarded makes clientIP read X-Forwarded-For (set once at start, behind a proxy that sets the header).
var trustForwarded bool

func TrustForwarded(on bool) { trustForwarded = on }

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if trustForwarded {
		if f := r.Header.Get("X-Forwarded-For"); f != "" {
			first, _, _ := strings.Cut(f, ",")
			return truncate(strings.TrimSpace(first), 64)
		}
	}
	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i > 0 {
		ip = ip[:i]
	}
	return truncate(strings.Trim(ip, "[]"), 64)
}

/* ---------------- The caller ---------------- */

// Actor is the signed-in caller of a request, read again from the database on every request: the person
// (UserID, the identity: what created_by/updated_by and the audit record), their membership in the tenant the
// session works in, and that tenant.
type Actor struct {
	UserID, Username, Name, Role, SessionID string
	MemberID, TenantID                      string
	PlatformAdmin                           bool
	Access                                  Access
	MustChange                              *string
	MustEnroll                              bool // the company requires MFA and the person has none yet
	user                                    *userRow
}

// ctx is ctx with the actor's tenant for generated codes.
func (a *Actor) ctx(ctx context.Context) context.Context {
	return codeprefix.WithTenant(ctx, a.TenantID)
}

type actorKey struct{}

func ActorFrom(ctx context.Context) *Actor {
	a, _ := ctx.Value(actorKey{}).(*Actor)
	return a
}

// Require is the caller when they may do action on menu.
func Require(ctx context.Context, menu, action string) (*Actor, error) {
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
	if !a.Access.May(menu, action) {
		return nil, apperr.Forbidden()
	}
	return a, nil
}

func unauthorized(code, msg string) *apperr.Error {
	return &apperr.Error{Status: http.StatusUnauthorized, Code: code, Message: msg}
}

// public are the endpoints that need no caller.
var public = map[string]bool{"/auth/idp/discover": true, "/auth/idp/start": true, "/auth/idp/callback": true, "/auth/mfa/verify": true, "/auth/signup": true, "/auth/email/verify": true, "/auth/email/resend": true, "/auth/otp/request": true, "/auth/otp/verify": true,
	"/auth/login": true, "/auth/refresh": true, "/auth/logout": true, "/auth/login-options": true, "/auth/tenants/lookup": true,
	"/auth/password/forgot": true, "/auth/password/reset": true, "/.well-known/jwks.json": true, "/healthz": true, "/readyz": true}

// Authenticate reads the Bearer token: signature and expiry, then the session and the account as they are now
// (a revoked session, a deactivated account or a changed role takes effect at once). Without a token the request
// goes on anonymous; the handlers that need a caller refuse it.
func (s *Service) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The OIDC endpoints authenticate their callers themselves (client secrets, codes, refresh and access tokens of
		// applications); only the login page's completion of a challenge is a call of a signed-in person.
		if (strings.HasPrefix(r.URL.Path, "/oauth2/") && r.URL.Path != "/oauth2/authorize/complete") || strings.HasPrefix(r.URL.Path, "/.well-known/") {
			next.ServeHTTP(w, r)
			return
		}
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			next.ServeHTTP(w, r)
			return
		}
		c, err := s.Keys.Verify(strings.TrimPrefix(h, "Bearer "), s.Cfg.Issuer, s.now())
		// The endpoints that need no caller are never blocked by a stale token: refresh is how it gets renewed.
		if err != nil && public[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		switch {
		case errors.Is(err, token.ErrExpired):
			writeErr(w, r, unauthorized("TOKEN_EXPIRED", "Sesi perlu diperbarui."))
			return
		case err != nil:
			writeErr(w, r, unauthorized("TOKEN_INVALID", "Sesi tidak sah. Silakan masuk kembali."))
			return
		}
		a, err := s.actor(r.Context(), c)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorKey{}, a)))
	})
}

func (s *Service) actor(ctx context.Context, c token.Claims) (*Actor, error) {
	if c.SessionID == "service" && c.ClientID != "" {
		return s.serviceActor(ctx, c)
	}
	ended := unauthorized("SESSION_ENDED", "Sesi sudah berakhir. Silakan masuk kembali.")
	if !uuidLike.MatchString(c.SessionID) || !uuidLike.MatchString(c.MemberID) || !uuidLike.MatchString(c.TenantID) {
		return nil, ended
	}
	// The session must still be alive and still work in the membership and tenant the token names (a switch of
	// company moves the session: tokens of the company it left stop working).
	var alive bool
	err := s.DB.Q(ctx).QueryRow(ctx, `SELECT revoked_at IS NULL AND expires_at > now() FROM auth.session
		WHERE id = $1 AND identity_id::text = $2 AND membership_id = $3 AND tenant_id = $4`, c.SessionID, c.Subject, c.MemberID, c.TenantID).Scan(&alive)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !alive {
		return nil, ended
	}
	if err != nil {
		return nil, err
	}
	u, err := s.userByID(ctx, c.TenantID, c.MemberID, false)
	if errors.Is(err, errNoUser) || err == nil && (!u.usable() || !s.employeeOK(ctx, u)) {
		return nil, unauthorized("ACCOUNT_INACTIVE", "Akun tidak aktif. Hubungi administrator.")
	}
	if err != nil {
		return nil, err
	}
	acc, err := s.access(ctx, u)
	if err != nil {
		return nil, err
	}
	return s.actorOf(u, c.SessionID, acc), nil
}

func (s *Service) actorOf(u *userRow, sid string, acc Access) *Actor {
	return &Actor{UserID: u.IdentityID, Username: u.Username, Name: u.Name, Role: u.RoleCode, SessionID: sid, MemberID: u.ID, TenantID: u.TenantID,
		PlatformAdmin: u.PlatformAdmin, Access: acc, MustChange: u.MustChange, MustEnroll: u.mustEnroll(), user: u}
}

func statusOf(err error) int {
	var e *apperr.Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 500
}
