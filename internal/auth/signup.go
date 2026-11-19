package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"alir.local/auth-service/internal/catalog"
	"alir.local/auth-service/internal/password"
	"alir.local/auth-service/internal/platform/apperr"
	"alir.local/auth-service/internal/platform/codeprefix"
	"alir.local/auth-service/internal/platform/record"
	"alir.local/auth-service/internal/token"
)

// Self sign-up (people who are not employees: vendors, applicants of a public application), email verification,
// sign-in with a one-time code sent by email, and the API applications use to activate, verify or upgrade members.
// Every public answer here is the same whether the email is known or not.

const (
	verifyTTL   = 24 * time.Hour
	otpTTL      = 10 * time.Minute
	otpTries    = 5
	signupGrace = 7 * 24 * time.Hour // unverified sign-ups are removed after this
)

// checkEmail is the answer of every public form that mails: it never tells whether the email has an account.
var checkEmail = map[string]any{"status": "check_email"}

/* ---------------- Sign-up ---------------- */

// signupTenant is the company of a sign-up form, when it accepts sign-ups (its policy and the role new members get).
func (s *Service) signupTenant(ctx context.Context, key string) (*TenantRef, string, Policy, error) {
	t, err := s.tenantRef(ctx, key)
	if err != nil {
		return nil, "", Policy{}, err
	}
	if t == nil {
		return nil, "", Policy{}, apperr.Validation([]apperr.Problem{{Field: "tenant", Message: "Pilih perusahaan tujuan pendaftaran."}})
	}
	pol, err := s.policy(ctx, t.ID)
	if err != nil {
		return nil, "", Policy{}, err
	}
	var roleID string
	if pol.SelfSignupEnabled && pol.SelfSignupRole != nil {
		_ = s.DB.Q(ctx).QueryRow(ctx, `SELECT id FROM auth.role WHERE tenant_id = $1 AND code = $2 AND is_active AND NOT is_deleted`, t.ID, *pol.SelfSignupRole).Scan(&roleID)
	}
	if roleID == "" {
		return nil, "", Policy{}, &apperr.Error{Status: 403, Code: "SIGNUP_CLOSED", Message: fmt.Sprintf("%s tidak menerima pendaftaran mandiri.", t.Name)}
	}
	return t, roleID, pol, nil
}

func tenantKeyOf(r *http.Request, body record.Values) string {
	if t, _ := body["tenant"].(string); t != "" {
		return t
	}
	if r != nil {
		return r.Header.Get("X-Tenant")
	}
	return ""
}

var usernameJunk = regexp.MustCompile(`[^a-z0-9._-]+`)

// freeUsername is a username for a new member of a tenant, made from the email's local part.
func (s *Service) freeUsername(ctx context.Context, tenantID, email string) (string, error) {
	base := strings.Trim(usernameJunk.ReplaceAllString(strings.ToLower(strings.SplitN(email, "@", 2)[0]), "."), "._-")
	if base == "" || !usernamePattern.MatchString(base) {
		base = "pengguna"
	}
	if len(base) > 50 {
		base = base[:50]
	}
	for i := 0; i < 100; i++ {
		u := base
		if i > 0 {
			u = fmt.Sprintf("%s%d", base, i+1)
		}
		var taken bool
		if err := s.DB.Q(ctx).QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth.membership WHERE tenant_id = $1 AND username = $2 AND NOT is_deleted)`, tenantID, u).Scan(&taken); err != nil {
			return "", err
		}
		if !taken {
			return u, nil
		}
	}
	return "", apperr.Conflict("USERNAME_EXHAUSTED", "Username otomatis tidak dapat dibuat; hubungi administrator.")
}

// addExternal makes a person an external member of a tenant with the sign-up role.
func (s *Service) addExternal(ctx context.Context, tenantID, identityID, roleID, name, email string) (string, error) {
	username, err := s.freeUsername(ctx, tenantID, email)
	if err != nil {
		return "", err
	}
	ctx = codeprefix.WithTenant(ctx, tenantID)
	code, err := codeprefix.NextFree(ctx, s.Codes, "membership", func(ctx context.Context, c string) (bool, error) {
		var taken bool
		err := s.DB.Q(ctx).QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth.membership WHERE tenant_id = $1 AND lower(code) = lower($2))`, tenantID, c).Scan(&taken)
		return taken, err
	})
	if err != nil {
		return "", err
	}
	var id string
	err = s.DB.Q(ctx).QueryRow(ctx, `INSERT INTO auth.membership (tenant_id, identity_id, code, name, username, role_id, kind, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, 'external', $2) RETURNING id`, tenantID, identityID, code, truncate(name, record.MaxName), username, roleID).Scan(&id)
	return id, err
}

// Signup registers a person with their email in a company that accepts sign-ups (POST /auth/signup {tenant, email,
// name, password, acceptTerms, captcha}). Answer 202 check_email in every case: a new email gets a verification link;
// an email waiting for verification gets the link again; an email that already has an account gets a notice to sign
// in (and join the company from there). Nothing here tells whether the email is known.
func (s *Service) Signup(ctx context.Context, r *http.Request, body record.Values) (map[string]any, error) {
	t, roleID, pol, err := s.signupTenant(ctx, tenantKeyOf(r, body))
	if err != nil {
		return nil, err
	}
	var p record.Problems
	email := parseEmail(body, "email", &p)
	if email == nil && !p.Has("email") {
		p.Add("email", "Email wajib diisi.")
	}
	name := record.RequiredText(body, "name", "Nama lengkap", record.MaxName, &p)
	if name != "" && len([]rune(name)) < 2 && !p.Has("name") {
		p.Add("name", "Nama lengkap minimal 2 karakter.")
	}
	pw, _ := body["password"].(string)
	if msg := pol.Rules().Problem(pw); msg != "" {
		p.Add("password", fmt.Sprintf("Password belum memenuhi: %s.", strings.ToLower(msg)))
	}
	if accepted, _ := body["acceptTerms"].(bool); !accepted {
		p.Add("acceptTerms", "Setujui syarat dan ketentuan untuk mendaftar.")
	}
	if len(p) > 0 {
		return nil, apperr.Validation(p)
	}
	captcha, _ := body["captcha"].(string)
	if err := s.captchaOK(ctx, r, captcha); err != nil {
		return nil, err
	}
	if err := s.limitBoth(ctx, r, "signup", *email, s.limits().SignupPerEmail, s.limits().SignupPerIP); err != nil {
		return nil, err
	}
	hash, err := password.Hash(pw)
	if err != nil {
		return nil, err
	}
	err = s.DB.InTx(ctx, func(ctx context.Context) error {
		if _, err := s.DB.Q(ctx).Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('auth.signup.' || $1::text))`, *email); err != nil {
			return err
		}
		var iid, origin string
		var verified bool
		err := s.DB.Q(ctx).QueryRow(ctx, `SELECT id, origin, email_verified_at IS NOT NULL FROM auth.identity WHERE email = $1 AND NOT is_deleted`, *email).Scan(&iid, &origin, &verified)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if err := s.DB.Q(ctx).QueryRow(ctx, `INSERT INTO auth.identity (name, email, password_hash, password_changed_at, origin, terms_version, terms_accepted_at, created_by)
				VALUES ($1, $2, $3, now(), 'signup', $4, now(), $5) RETURNING id`, name, *email, hash, s.Cfg.TermsVersion, SystemUserID).Scan(&iid); err != nil {
				return uniqueEmail(err)
			}
			if _, err := s.addExternal(ctx, t.ID, iid, roleID, name, *email); err != nil {
				return err
			}
			s.auditIn(ctx, r, t.ID, "user_created", nil, *email, "Pendaftaran mandiri (menunggu verifikasi email)")
			return s.mailVerify(ctx, iid, t, name, *email)
		case err != nil:
			return err
		case !verified && origin == "signup":
			// Waiting for verification: the link again (and this company too); the password typed now is not used.
			var member bool
			if err := s.DB.Q(ctx).QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth.membership WHERE tenant_id = $1 AND identity_id = $2 AND NOT is_deleted)`, t.ID, iid).Scan(&member); err != nil {
				return err
			}
			if !member {
				if _, err := s.addExternal(ctx, t.ID, iid, roleID, name, *email); err != nil {
					return err
				}
			}
			return s.mailVerify(ctx, iid, t, name, *email)
		default:
			s.mailSignupExists(ctx, iid, t, *email)
			return nil
		}
	})
	if err != nil {
		return nil, err
	}
	return checkEmail, nil
}

func (s *Service) mailVerify(ctx context.Context, identityID string, t *TenantRef, name, email string) error {
	raw, hash := newSecret()
	if _, err := s.DB.Q(ctx).Exec(ctx, `INSERT INTO auth.email_token (token_hash, identity_id, tenant_id, expires_at) VALUES ($1, $2, $3, now() + make_interval(secs => $4))`,
		hash, identityID, t.ID, verifyTTL.Seconds()); err != nil {
		return err
	}
	s.queueTo(ctx, "email_verify", identityID, t.ID, email, "Verifikasi email ALIR Anda",
		fmt.Sprintf("Halo %s,\n\nTerima kasih telah mendaftar di %s melalui ALIR.\nBuka tautan berikut dalam 24 jam untuk memverifikasi email Anda:\n%s/verify-email?token=%s\n\nBila Anda tidak mendaftar, abaikan email ini; akun yang tidak diverifikasi dihapus setelah 7 hari.",
			name, t.Name, s.Cfg.AppBaseURL, raw))
	return nil
}

func (s *Service) mailSignupExists(ctx context.Context, identityID string, t *TenantRef, email string) {
	s.queueTo(ctx, "signup_exists", identityID, t.ID, email, "Anda sudah punya akun ALIR",
		fmt.Sprintf("Halo,\n\nAda permintaan pendaftaran ke %s dengan email ini, tetapi email ini sudah punya akun ALIR.\nMasuk di %s/login dengan email dan password Anda, lalu pilih bergabung dengan %s.\nLupa password? %s/forgot-password\n\nBila bukan Anda yang mendaftar, abaikan email ini.",
			t.Name, s.Cfg.AppBaseURL, t.Name, s.Cfg.AppBaseURL))
}

// VerifyEmail confirms an email with the mailed token (POST /auth/email/verify {token}).
func (s *Service) VerifyEmail(ctx context.Context, r *http.Request, body record.Values) (map[string]any, error) {
	raw, _ := body["token"].(string)
	bad := apperr.Conflict("VERIFY_INVALID", "Tautan verifikasi tidak berlaku atau sudah dipakai. Minta kirim ulang.")
	if raw == "" || len(raw) > 100 {
		return nil, bad
	}
	var out map[string]any
	err := s.DB.InTx(ctx, func(ctx context.Context) error {
		var iid string
		var tid *string
		err := s.DB.Q(ctx).QueryRow(ctx, `SELECT identity_id, tenant_id FROM auth.email_token WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() FOR UPDATE`,
			hashOf(raw)).Scan(&iid, &tid)
		if errors.Is(err, pgx.ErrNoRows) {
			return bad
		}
		if err != nil {
			return err
		}
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.email_token SET used_at = now() WHERE token_hash = $1`, hashOf(raw)); err != nil {
			return err
		}
		var email string
		if err := s.DB.Q(ctx).QueryRow(ctx, `UPDATE auth.identity SET email_verified_at = coalesce(email_verified_at, now()) WHERE id = $1 AND NOT is_deleted RETURNING email`, iid).Scan(&email); err != nil {
			return bad
		}
		out = map[string]any{"verified": true, "email": email}
		if tid != nil {
			var t TenantRef
			if s.DB.Q(ctx).QueryRow(ctx, `SELECT id, code, name FROM auth.tenant WHERE id = $1`, *tid).Scan(&t.ID, &t.Code, &t.Name) == nil {
				out["tenant"] = t
				s.auditIn(ctx, r, t.ID, "user_updated", nil, email, "Email diverifikasi")
			}
		}
		return nil
	})
	return out, err
}

// ResendVerification mails a new verification link to an email waiting for one (POST /auth/email/resend
// {email, tenant?, captcha}). The same answer for every email.
func (s *Service) ResendVerification(ctx context.Context, r *http.Request, body record.Values) (map[string]any, error) {
	var p record.Problems
	email := parseEmail(body, "email", &p)
	if email == nil {
		if len(p) == 0 {
			p.Add("email", "Email wajib diisi.")
		}
		return nil, apperr.Validation(p)
	}
	captcha, _ := body["captcha"].(string)
	if err := s.captchaOK(ctx, r, captcha); err != nil {
		return nil, err
	}
	if err := s.limitBoth(ctx, r, "resend", *email, s.limits().ResendPerEmail, s.limits().ResendPerIP); err != nil {
		return nil, err
	}
	var iid, name string
	if s.DB.Q(ctx).QueryRow(ctx, `SELECT id, name FROM auth.identity WHERE email = $1 AND email_verified_at IS NULL AND is_active AND NOT is_deleted`, *email).Scan(&iid, &name) != nil {
		return checkEmail, nil
	}
	// The company of the sign-up: the one named, else the person's first membership.
	tkey := tenantKeyOf(r, body)
	var t TenantRef
	if s.DB.Q(ctx).QueryRow(ctx, `SELECT t.id, t.code, t.name FROM auth.membership m JOIN auth.tenant t ON t.id = m.tenant_id
		WHERE m.identity_id = $1 AND NOT m.is_deleted AND ($2 = '' OR lower(t.code) = lower($2)) ORDER BY m.created_at LIMIT 1`, iid, tkey).Scan(&t.ID, &t.Code, &t.Name) != nil {
		return checkEmail, nil
	}
	if err := s.mailVerify(ctx, iid, &t, name, *email); err != nil {
		return nil, err
	}
	return checkEmail, nil
}

// Join makes the signed-in person an external member of another company that accepts sign-ups (POST /auth/join
// {tenant}); they switch to it afterwards.
func (s *Service) Join(ctx context.Context, r *http.Request, body record.Values) (TenantRef, error) {
	a := ActorFrom(ctx)
	if a == nil || a.MemberID == "" {
		return TenantRef{}, unauthorized("SIGNED_OUT", "Sesi tidak ditemukan. Silakan masuk kembali.")
	}
	t, roleID, _, err := s.signupTenant(ctx, tenantKeyOf(r, body))
	if err != nil {
		return TenantRef{}, err
	}
	err = s.DB.InTx(ctx, func(ctx context.Context) error {
		var member bool
		if err := s.DB.Q(ctx).QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth.membership WHERE tenant_id = $1 AND identity_id = $2 AND NOT is_deleted)`, t.ID, a.UserID).Scan(&member); err != nil {
			return err
		}
		if member {
			return apperr.Conflict("ALREADY_MEMBER", fmt.Sprintf("Anda sudah anggota %s.", t.Name))
		}
		var name, email string
		if err := s.DB.Q(ctx).QueryRow(ctx, `SELECT name, coalesce(email, '') FROM auth.identity WHERE id = $1`, a.UserID).Scan(&name, &email); err != nil {
			return err
		}
		if email == "" {
			email = a.Username // only names the new username
		}
		if _, err := s.addExternal(ctx, t.ID, a.UserID, roleID, name, email); err != nil {
			return err
		}
		s.auditIn(ctx, r, t.ID, "user_created", nil, email, "Bergabung sebagai anggota eksternal")
		return nil
	})
	return *t, err
}

/* ---------------- Sign-in with a code sent by email ---------------- */

func otpHash(identityID, code string) []byte { return hashOf(identityID + ":" + code) }

func newOTP() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1_000_000))
	return fmt.Sprintf("%06d", n.Int64())
}

// RequestOTP mails a one-time sign-in code (POST /auth/otp/request {email, captcha}). The same answer for every email.
func (s *Service) RequestOTP(ctx context.Context, r *http.Request, body record.Values) (map[string]any, error) {
	var p record.Problems
	email := parseEmail(body, "email", &p)
	if email == nil {
		if len(p) == 0 {
			p.Add("email", "Email wajib diisi.")
		}
		return nil, apperr.Validation(p)
	}
	captcha, _ := body["captcha"].(string)
	if err := s.captchaOK(ctx, r, captcha); err != nil {
		return nil, err
	}
	if err := s.limitBoth(ctx, r, "otp", *email, s.limits().OTPPerEmail, s.limits().OTPPerIP); err != nil {
		return nil, err
	}
	err := s.DB.InTx(ctx, func(ctx context.Context) error {
		var iid, name string
		if s.DB.Q(ctx).QueryRow(ctx, `SELECT id, name FROM auth.identity WHERE email = $1 AND is_active AND NOT is_deleted FOR UPDATE`, *email).Scan(&iid, &name) != nil {
			return nil
		}
		code := newOTP()
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.login_otp SET used_at = now() WHERE identity_id = $1 AND used_at IS NULL`, iid); err != nil {
			return err
		}
		if _, err := s.DB.Q(ctx).Exec(ctx, `INSERT INTO auth.login_otp (identity_id, code_hash, expires_at) VALUES ($1, $2, now() + make_interval(secs => $3))`,
			iid, otpHash(iid, code), otpTTL.Seconds()); err != nil {
			return err
		}
		s.queueTo(ctx, "login_otp", iid, "", *email, "Kode masuk ALIR: "+code,
			fmt.Sprintf("Halo %s,\n\nKode masuk ALIR Anda: %s\nBerlaku 10 menit dan hanya sekali pakai. Jangan berikan kode ini kepada siapa pun, termasuk petugas ALIR.\n\nBila Anda tidak meminta kode, abaikan email ini.", name, code))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return checkEmail, nil
}

func invalidCode() error {
	return unauthorized("INVALID_CODE", "Kode salah atau kedaluwarsa. Minta kode baru bila perlu.")
}

// VerifyOTP signs in with the mailed code (POST /auth/otp/verify {email, code, tenant?}); like a password sign-in it
// may answer TENANT_CHOICE. A correct code also confirms the email (the person reads that mailbox).
func (s *Service) VerifyOTP(ctx context.Context, r *http.Request, body record.Values) (LoginResult, error) {
	var p record.Problems
	email := parseEmail(body, "email", &p)
	code, _ := body["code"].(string)
	code = strings.TrimSpace(code)
	if email == nil || len(code) != 6 {
		return LoginResult{}, apperr.Validation([]apperr.Problem{{Field: "code", Message: "Isi email dan 6 digit kode."}})
	}
	if err := s.limit(ctx, "otpverify:email:"+*email, s.limits().OTPVerifyPerEmail); err != nil {
		return LoginResult{}, err
	}
	tenant, err := s.tenantRef(ctx, tenantKeyOf(r, body))
	if err != nil {
		return LoginResult{}, err
	}
	tenantID := ""
	if tenant != nil {
		tenantID = tenant.ID
	}
	var out LoginResult
	var refusal error
	err = s.DB.InTx(ctx, func(ctx context.Context) error {
		refusal = nil
		iid, err := s.identityByEmail(ctx, *email)
		if err != nil {
			return err
		}
		if iid == "" {
			refusal = invalidCode()
			return nil
		}
		id, err := s.lockIdentity(ctx, iid)
		if err != nil {
			refusal = invalidCode()
			return nil
		}
		if id.Locked {
			refusal = locked(*id.LockedUntil, id.LockMinutes)
			return nil
		}
		var oid string
		var stored []byte
		var tries int
		err = s.DB.Q(ctx).QueryRow(ctx, `SELECT id, code_hash, attempts FROM auth.login_otp WHERE identity_id = $1 AND used_at IS NULL AND expires_at > now()
			ORDER BY created_at DESC LIMIT 1 FOR UPDATE`, iid).Scan(&oid, &stored, &tries)
		if errors.Is(err, pgx.ErrNoRows) {
			refusal = invalidCode()
			return nil
		}
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(otpHash(iid, code), stored) != 1 {
			// A wrong code counts; the last try burns it.
			if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.login_otp SET attempts = attempts + 1, used_at = CASE WHEN attempts + 1 >= $2 THEN now() END WHERE id = $1`, oid, otpTries); err != nil {
				return err
			}
			s.auditIn(ctx, r, tenantID, "login_failed", nil, *email, "Kode email salah")
			refusal = invalidCode()
			return nil
		}
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.login_otp SET used_at = now() WHERE id = $1`, oid); err != nil {
			return err
		}
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.identity SET email_verified_at = coalesce(email_verified_at, now()) WHERE id = $1`, iid); err != nil {
			return err
		}
		var err2 error
		out, refusal, err2 = s.enter(ctx, r, id, tenantID, false, *email, "otp", s.now())
		return err2
	})
	if err != nil {
		return LoginResult{}, err
	}
	return out, refusal
}

/* ---------------- Applications: activate, verify, upgrade a member ---------------- */

// SetMemberAccess changes what a member may do (POST /users/{id}/access {role?, active?, verified?}): an
// administrator, or an application with a service role allowed to update users (e.g. a tender application that
// verified a vendor's documents). Only a person with the Admin role makes another Admin.
func (s *Service) SetMemberAccess(ctx context.Context, id string, body record.Values) (ManagedUser, error) {
	me, err := Require(ctx, "auth.users", "update")
	if err != nil {
		return ManagedUser{}, err
	}
	var p record.Problems
	role := record.OptionalText(body, "role", "Peran", record.MaxCode, &p)
	_, setActive := body["active"]
	active := record.Bool(body, "active", "Status aktif", true, &p)
	_, setVerified := body["verified"]
	verified := record.Bool(body, "verified", "Terverifikasi", false, &p)
	if len(p) > 0 {
		return ManagedUser{}, apperr.Validation(p)
	}
	err = s.DB.InTx(ctx, func(ctx context.Context) error {
		u, err := s.actorUser(ctx, me, id, true)
		if err != nil {
			return notFound(err)
		}
		var detail []string
		if role != nil && *role != u.RoleCode {
			if *role == "admin" && (me.Role != "admin" || me.MemberID == "") {
				return apperr.Validation([]apperr.Problem{{Field: "role", Message: "Hanya Admin yang dapat menjadikan anggota lain Admin."}})
			}
			if u.RoleCode == "admin" && u.Active {
				if n, err := s.activeAdmins(ctx, me.TenantID); err != nil {
					return err
				} else if n <= 1 {
					return apperr.Validation([]apperr.Problem{{Field: "role", Message: "Ini satu-satunya Admin aktif."}})
				}
			}
			var rid string
			if s.DB.Q(ctx).QueryRow(ctx, `SELECT id FROM auth.role WHERE tenant_id = $1 AND code = $2 AND is_active AND NOT is_deleted`, me.TenantID, *role).Scan(&rid) != nil {
				return apperr.Validation([]apperr.Problem{{Field: "role", Message: "Peran tidak tersedia."}})
			}
			if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.membership SET role_id = $2, updated_at = now(), updated_by = $3, version = version + 1 WHERE id = $1`, id, rid, me.UserID); err != nil {
				return err
			}
			detail = append(detail, "peran "+*role)
		}
		if setActive && active != u.Active {
			if !active && (u.ID == me.MemberID || u.RoleCode == "admin") {
				if u.ID == me.MemberID {
					return apperr.Validation([]apperr.Problem{{Field: "active", Message: "Anda tidak dapat menonaktifkan akun Anda sendiri."}})
				}
				if n, err := s.activeAdmins(ctx, me.TenantID); err != nil {
					return err
				} else if n <= 1 {
					return apperr.Validation([]apperr.Problem{{Field: "active", Message: "Ini satu-satunya Admin aktif."}})
				}
			}
			if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.membership SET is_active = $2, updated_at = now(), updated_by = $3, version = version + 1 WHERE id = $1`, id, active, me.UserID); err != nil {
				return err
			}
			if !active {
				if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.session SET revoked_at = now() WHERE membership_id = $1 AND revoked_at IS NULL`, id); err != nil {
					return err
				}
			}
			detail = append(detail, map[bool]string{true: "diaktifkan", false: "dinonaktifkan"}[active])
		}
		if setVerified && verified != (u.VerifiedAt != nil) {
			if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.membership SET verified_at = CASE WHEN $2 THEN now() END, verified_by = CASE WHEN $2 THEN $3::uuid END,
				updated_at = now(), updated_by = $3, version = version + 1 WHERE id = $1`, id, verified, me.UserID); err != nil {
				return err
			}
			detail = append(detail, map[bool]string{true: "diverifikasi", false: "verifikasi dicabut"}[verified])
		}
		if len(detail) > 0 {
			s.audit(ctx, requestOf(ctx), "user_updated", me, u.Username, "Akses anggota: "+strings.Join(detail, ", "))
		}
		return nil
	})
	if err != nil {
		return ManagedUser{}, err
	}
	return s.GetUser(ctx, id)
}

// serviceActor is an application acting with client_credentials: its service role's grants as they are now
// (limited to its module), in its company.
func (s *Service) serviceActor(ctx context.Context, c token.Claims) (*Actor, error) {
	invalid := unauthorized("TOKEN_INVALID", "Token layanan tidak berlaku.")
	cl, err := s.clientByID(ctx, c.ClientID)
	if err != nil || !cl.Active || cl.uuid != c.Subject || cl.tenantID == nil || *cl.tenantID != c.TenantID || cl.serviceRoleID == nil {
		return nil, invalid
	}
	g := catalog.Grants{}
	rows, err := s.DB.Q(ctx).Query(ctx, `SELECT g.menu, g.actions FROM auth.role_grant g JOIN auth.role r ON r.id = g.role_id
		JOIN auth.tenant t ON t.id = r.tenant_id WHERE g.role_id = $1 AND r.is_active AND NOT r.is_deleted AND t.is_active AND NOT t.is_deleted`, *cl.serviceRoleID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var menu string
		var actions []string
		if err := rows.Scan(&menu, &actions); err != nil {
			rows.Close()
			return nil, err
		}
		g[menu] = actions
	}
	rows.Close()
	if cl.Module != nil {
		g = moduleGrants(g, *cl.Module)
	}
	return &Actor{UserID: cl.uuid, Username: cl.ID, Name: cl.Name, Role: "service", SessionID: "service", TenantID: c.TenantID,
		Access: Access{Role: "service", Modules: []string{}, Grants: g}}, nil
}

/* ---------------- Housekeeping ---------------- */

// Cleanup removes what is no longer needed: sign-ups never verified within 7 days (the person and their external
// memberships), and old rate counters, codes, tokens and authorization requests.
func (s *Service) Cleanup(ctx context.Context) (int64, error) {
	var removed int64
	err := s.DB.InTx(ctx, func(ctx context.Context) error {
		q := s.DB.Q(ctx)
		stale := `SELECT id FROM auth.identity i WHERE i.origin = 'signup' AND i.email_verified_at IS NULL AND i.created_at < now() - make_interval(secs => $1)
			AND NOT EXISTS (SELECT 1 FROM auth.membership m WHERE m.identity_id = i.id AND m.kind = 'workforce')`
		if _, err := q.Exec(ctx, `DELETE FROM auth.membership WHERE identity_id IN (`+stale+`)`, signupGrace.Seconds()); err != nil {
			return err
		}
		tag, err := q.Exec(ctx, `DELETE FROM auth.identity WHERE id IN (`+stale+`)`, signupGrace.Seconds())
		if err != nil {
			return err
		}
		removed = tag.RowsAffected()
		for _, x := range []string{
			`DELETE FROM auth.rate_event WHERE at < now() - interval '1 day'`,
			`DELETE FROM auth.login_otp WHERE created_at < now() - interval '1 day'`,
			`DELETE FROM auth.email_token WHERE expires_at < now() - interval '1 day'`,
			`DELETE FROM auth.authz_request WHERE expires_at < now() - interval '1 day'`,
			`DELETE FROM auth.idp_login WHERE expires_at < now() - interval '1 day'`,
			`DELETE FROM auth.mfa_challenge WHERE expires_at < now() - interval '1 day'`,
			`DELETE FROM auth.auth_code WHERE expires_at < now() - interval '1 day' AND grant_id IS NULL`,
		} {
			if _, err := q.Exec(ctx, x); err != nil {
				return err
			}
		}
		return nil
	})
	return removed, err
}
