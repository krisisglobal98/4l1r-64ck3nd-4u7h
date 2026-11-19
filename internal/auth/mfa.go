package auth

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"alir.local/auth-service/internal/platform/apperr"
	"alir.local/auth-service/internal/platform/record"
	"alir.local/auth-service/internal/totp"
)

// Multi-factor authentication with an authenticator app (TOTP) and single-use recovery codes. It belongs to the
// person (identity): one authenticator for every company. A sign-in of a person with an authenticator stops after
// the password (or email code) with 401 MFA_REQUIRED and an mfaToken; POST /auth/mfa/verify finishes it.

const recoveryCount = 10

func mustEnrollErr() error {
	return &apperr.Error{Status: http.StatusForbidden, Code: "MFA_ENROLL_REQUIRED", Message: "Perusahaan Anda mewajibkan MFA. Pasang aplikasi authenticator dulu."}
}

// mfaActor is the caller of the MFA endpoints: signed in, password already changed (enrolment is allowed while
// the company still waits for it).
func mfaActor(ctx context.Context) (*Actor, error) {
	a := ActorFrom(ctx)
	if a == nil || a.MemberID == "" {
		return nil, unauthorized("SIGNED_OUT", "Sesi tidak ditemukan. Silakan masuk kembali.")
	}
	if a.MustChange != nil {
		return nil, &apperr.Error{Status: http.StatusForbidden, Code: "MUST_CHANGE_PASSWORD", Message: "Ganti password Anda terlebih dahulu."}
	}
	return a, nil
}

type factor struct {
	id        string
	secret    []byte
	lastStep  int64
	confirmed bool
}

// factorOf is the person's TOTP factor (confirmed or not), locked when forUpdate.
func (s *Service) factorOf(ctx context.Context, identityID string, forUpdate bool) (*factor, error) {
	q := `SELECT id, secret_sealed, last_step, confirmed_at IS NOT NULL FROM auth.mfa_factor WHERE identity_id = $1 AND kind = 'totp'`
	if forUpdate {
		q += ` FOR UPDATE`
	}
	var f factor
	var sealed string
	err := s.DB.Q(ctx).QueryRow(ctx, q, identityID).Scan(&f.id, &sealed, &f.lastStep, &f.confirmed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if f.secret, err = s.Box.Open(sealed, identityID); err != nil {
		return nil, fmt.Errorf("mfa secret of %s: %w", identityID, err)
	}
	return &f, nil
}

func normRecovery(code string) string {
	return strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
}

func recoveryHash(identityID, code string) []byte {
	return hashOf(identityID + ":" + normRecovery(code))
}

// newRecoveryCodes replaces the person's recovery codes with fresh ones (answered once).
func (s *Service) newRecoveryCodes(ctx context.Context, identityID string) ([]string, error) {
	if _, err := s.DB.Q(ctx).Exec(ctx, `DELETE FROM auth.recovery_code WHERE identity_id = $1`, identityID); err != nil {
		return nil, err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	out := make([]string, 0, recoveryCount)
	for range recoveryCount {
		b := make([]byte, 7)
		_, _ = rand.Read(b)
		c := strings.ToLower(enc.EncodeToString(b))[:10]
		c = c[:5] + "-" + c[5:]
		if _, err := s.DB.Q(ctx).Exec(ctx, `INSERT INTO auth.recovery_code (identity_id, code_hash) VALUES ($1, $2)`, identityID, recoveryHash(identityID, c)); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// proveFactor checks an authenticator code (never the same time step twice) or a recovery code (single use).
func (s *Service) proveFactor(ctx context.Context, identityID, code, recovery string) (bool, error) {
	if recovery != "" {
		tag, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.recovery_code SET used_at = now() WHERE identity_id = $1 AND code_hash = $2 AND used_at IS NULL`,
			identityID, recoveryHash(identityID, recovery))
		return err == nil && tag.RowsAffected() == 1, err
	}
	f, err := s.factorOf(ctx, identityID, true)
	if err != nil || f == nil || !f.confirmed {
		return false, err
	}
	step, ok := totp.Verify(f.secret, code, s.now(), f.lastStep)
	if !ok {
		return false, nil
	}
	_, err = s.DB.Q(ctx).Exec(ctx, `UPDATE auth.mfa_factor SET last_step = $2, last_used_at = now() WHERE id = $1`, f.id, step)
	return err == nil, err
}

/* ---------------- The second step of a sign-in ---------------- */

// VerifyMFA finishes a sign-in with the authenticator code or a recovery code (POST /auth/mfa/verify {mfaToken,
// code | recoveryCode}). Wrong codes count toward the person's lockout like wrong passwords.
func (s *Service) VerifyMFA(ctx context.Context, r *http.Request, body record.Values) (LoginResult, error) {
	raw, _ := body["mfaToken"].(string)
	code, _ := body["code"].(string)
	recovery, _ := body["recoveryCode"].(string)
	expired := unauthorized("MFA_EXPIRED", "Langkah verifikasi sudah kedaluwarsa. Masuk lagi.")
	if raw == "" || len(raw) > 100 || (code == "" && recovery == "") || len(code) > 10 || len(recovery) > 20 {
		return LoginResult{}, apperr.Validation([]apperr.Problem{{Field: "code", Message: "Isi kode dari aplikasi authenticator atau kode cadangan."}})
	}
	var out LoginResult
	var refusal error
	err := s.DB.InTx(ctx, func(ctx context.Context) error {
		refusal = nil
		var iid, mid, tid, method string
		var attempts int
		err := s.DB.Q(ctx).QueryRow(ctx, `SELECT identity_id, membership_id, tenant_id, method, attempts FROM auth.mfa_challenge
			WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() FOR UPDATE`, hashOf(raw)).Scan(&iid, &mid, &tid, &method, &attempts)
		if errors.Is(err, pgx.ErrNoRows) {
			refusal = expired
			return nil
		}
		if err != nil {
			return err
		}
		id, err := s.lockIdentity(ctx, iid)
		if err != nil {
			refusal = expired
			return nil
		}
		if id.Locked {
			refusal = locked(*id.LockedUntil, id.LockMinutes)
			return nil
		}
		ok, err := s.proveFactor(ctx, iid, code, recovery)
		if err != nil {
			return err
		}
		if !ok {
			n := id.FailedLogins + 1
			ipol, err := s.identityPolicy(ctx, iid)
			if err != nil {
				return err
			}
			burn := attempts+1 >= otpTries
			if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.mfa_challenge SET attempts = attempts + 1, used_at = CASE WHEN $2 THEN now() END WHERE token_hash = $1`, hashOf(raw), burn); err != nil {
				return err
			}
			s.auditIn(ctx, r, tid, "login_failed", nil, id.Name, fmt.Sprintf("Kode MFA salah (percobaan ke-%d)", n))
			if ipol.MaxFailedAttempts > 0 && n >= ipol.MaxFailedAttempts {
				var until time.Time
				if err := s.DB.Q(ctx).QueryRow(ctx, `UPDATE auth.identity SET failed_logins = 0, locked_until = now() + make_interval(mins => $2) WHERE id = $1 RETURNING locked_until`,
					iid, ipol.LockoutMinutes).Scan(&until); err != nil {
					return err
				}
				refusal = locked(until, ipol.LockoutMinutes)
				return nil
			}
			if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.identity SET failed_logins = $2 WHERE id = $1`, iid, n); err != nil {
				return err
			}
			refusal = unauthorized("INVALID_CODE", "Kode salah. Coba lagi dengan kode terbaru.")
			return nil
		}
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.mfa_challenge SET used_at = now() WHERE token_hash = $1`, hashOf(raw)); err != nil {
			return err
		}
		u, err := s.userByID(ctx, tid, mid, true)
		if err != nil || !u.usable() || !s.employeeOK(ctx, u) {
			refusal = &apperr.Error{Status: 403, Code: "INACTIVE", Message: "Akun Anda di perusahaan ini nonaktif. Hubungi administrator."}
			return nil
		}
		pol, err := s.policy(ctx, tid)
		if err != nil {
			return err
		}
		if recovery != "" {
			s.auditIn(ctx, r, tid, "user_updated", nil, u.Username, "Masuk dengan kode cadangan MFA")
		}
		var err2 error
		out, refusal, err2 = s.startSession(ctx, r, u, pol, method, s.now())
		return err2
	})
	if err != nil {
		return LoginResult{}, err
	}
	return out, refusal
}

/* ---------------- Enrolment ---------------- */

// MfaStatus is the caller's MFA (GET /auth/mfa).
func (s *Service) MfaStatus(ctx context.Context) (map[string]any, error) {
	a, err := mfaActor(ctx)
	if err != nil {
		return nil, err
	}
	var confirmedAt, lastUsed *time.Time
	_ = s.DB.Q(ctx).QueryRow(ctx, `SELECT confirmed_at, last_used_at FROM auth.mfa_factor WHERE identity_id = $1 AND kind = 'totp'`, a.UserID).Scan(&confirmedAt, &lastUsed)
	var left int
	if err := s.DB.Q(ctx).QueryRow(ctx, `SELECT count(*) FROM auth.recovery_code WHERE identity_id = $1 AND used_at IS NULL`, a.UserID).Scan(&left); err != nil {
		return nil, err
	}
	return map[string]any{"enrolled": confirmedAt != nil, "confirmedAt": utc(confirmedAt), "lastUsedAt": utc(lastUsed), "recoveryCodesLeft": left,
		"mode": a.user.MfaMode, "required": a.user.MfaMode == "required"}, nil
}

// StartTotp begins enrolment (POST /auth/mfa/totp/start): a new secret for the app (shown once, as text and as an
// otpauth:// address for a QR code); it counts only after ConfirmTotp.
func (s *Service) StartTotp(ctx context.Context) (map[string]any, error) {
	a, err := mfaActor(ctx)
	if err != nil {
		return nil, err
	}
	if a.user.MfaMode == "off" && !a.user.MfaEnrolled {
		return nil, apperr.Conflict("MFA_OFF", "MFA tidak diaktifkan di perusahaan ini.")
	}
	var out map[string]any
	err = s.DB.InTx(ctx, func(ctx context.Context) error {
		f, err := s.factorOf(ctx, a.UserID, true)
		if err != nil {
			return err
		}
		if f != nil && f.confirmed {
			return apperr.Conflict("MFA_ENROLLED", "Authenticator sudah terpasang. Nonaktifkan dulu untuk memasang yang baru.")
		}
		secret := totp.NewSecret()
		if _, err := s.DB.Q(ctx).Exec(ctx, `INSERT INTO auth.mfa_factor (identity_id, kind, secret_sealed) VALUES ($1, 'totp', $2)
			ON CONFLICT (identity_id, kind) DO UPDATE SET secret_sealed = $2, created_at = now(), confirmed_at = NULL, last_step = 0, last_used_at = NULL`,
			a.UserID, s.Box.Seal(secret, a.UserID)); err != nil {
			return err
		}
		account := a.Username + "@" + a.user.TenantCode
		if a.user.Email != nil {
			account = *a.user.Email
		}
		out = map[string]any{"secret": totp.Encode(secret), "otpauthUrl": totp.URL("ALIR", account, secret), "digits": totp.Digits, "period": totp.Period}
		return nil
	})
	return out, err
}

// ConfirmTotp finishes enrolment with a code from the app (POST /auth/mfa/totp/confirm {code}); the answer has the
// recovery codes, shown once.
func (s *Service) ConfirmTotp(ctx context.Context, r *http.Request, body record.Values) (map[string]any, error) {
	a, err := mfaActor(ctx)
	if err != nil {
		return nil, err
	}
	code, _ := body["code"].(string)
	var codes []string
	err = s.DB.InTx(ctx, func(ctx context.Context) error {
		f, err := s.factorOf(ctx, a.UserID, true)
		if err != nil {
			return err
		}
		if f == nil || f.confirmed {
			return apperr.Conflict("MFA_NOT_STARTED", "Mulai pemasangan authenticator dulu.")
		}
		step, ok := totp.Verify(f.secret, code, s.now(), 0)
		if !ok {
			return apperr.Validation([]apperr.Problem{{Field: "code", Message: "Kode tidak cocok. Periksa jam ponsel dan coba kode terbaru."}})
		}
		if _, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.mfa_factor SET confirmed_at = now(), last_step = $2, last_used_at = now() WHERE id = $1`, f.id, step); err != nil {
			return err
		}
		if codes, err = s.newRecoveryCodes(ctx, a.UserID); err != nil {
			return err
		}
		s.audit(ctx, r, "user_updated", a, a.Username, "MFA (authenticator) dipasang")
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"recoveryCodes": codes}, nil
}

// RegenerateRecoveryCodes replaces the recovery codes (POST /auth/mfa/recovery-codes {code}); the old ones stop.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, r *http.Request, body record.Values) (map[string]any, error) {
	a, err := mfaActor(ctx)
	if err != nil {
		return nil, err
	}
	code, _ := body["code"].(string)
	var codes []string
	err = s.DB.InTx(ctx, func(ctx context.Context) error {
		ok, err := s.proveFactor(ctx, a.UserID, code, "")
		if err != nil {
			return err
		}
		if !ok {
			return apperr.Validation([]apperr.Problem{{Field: "code", Message: "Kode authenticator salah."}})
		}
		if codes, err = s.newRecoveryCodes(ctx, a.UserID); err != nil {
			return err
		}
		s.audit(ctx, r, "user_updated", a, a.Username, "Kode cadangan MFA dibuat ulang")
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"recoveryCodes": codes}, nil
}

// requiredBy is the name of a company of the person that requires MFA ("" when none does).
func (s *Service) requiredBy(ctx context.Context, identityID string) (string, error) {
	var name string
	err := s.DB.Q(ctx).QueryRow(ctx, `SELECT t.name FROM auth.membership m JOIN auth.tenant t ON t.id = m.tenant_id JOIN auth.security_policy p ON p.tenant_id = m.tenant_id
		WHERE m.identity_id = $1 AND NOT m.is_deleted AND p.mfa_mode = 'required' ORDER BY t.name LIMIT 1`, identityID).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return name, err
}

// DisableMfa removes the caller's authenticator (DELETE /auth/mfa {code | recoveryCode}), unless a company of theirs
// requires MFA. Every other session signs in again.
func (s *Service) DisableMfa(ctx context.Context, r *http.Request, body record.Values) error {
	a, err := mfaActor(ctx)
	if err != nil {
		return err
	}
	code, _ := body["code"].(string)
	recovery, _ := body["recoveryCode"].(string)
	return s.DB.InTx(ctx, func(ctx context.Context) error {
		if by, err := s.requiredBy(ctx, a.UserID); err != nil {
			return err
		} else if by != "" {
			return apperr.Conflict("MFA_REQUIRED_BY_TENANT", fmt.Sprintf("%s mewajibkan MFA; authenticator tidak dapat dinonaktifkan.", by))
		}
		ok, err := s.proveFactor(ctx, a.UserID, code, recovery)
		if err != nil {
			return err
		}
		if !ok {
			return apperr.Validation([]apperr.Problem{{Field: "code", Message: "Kode authenticator atau kode cadangan salah."}})
		}
		if err := s.dropFactors(ctx, a.UserID, a.SessionID); err != nil {
			return err
		}
		s.audit(ctx, r, "user_updated", a, a.Username, "MFA dinonaktifkan oleh pengguna")
		return nil
	})
}

// dropFactors removes the authenticator and the recovery codes; every session but keep ends.
func (s *Service) dropFactors(ctx context.Context, identityID, keep string) error {
	for _, q := range []string{`DELETE FROM auth.mfa_factor WHERE identity_id = $1`, `DELETE FROM auth.recovery_code WHERE identity_id = $1`} {
		if _, err := s.DB.Q(ctx).Exec(ctx, q, identityID); err != nil {
			return err
		}
	}
	_, err := s.DB.Q(ctx).Exec(ctx, `UPDATE auth.session SET revoked_at = now() WHERE identity_id = $1 AND id::text <> $2 AND revoked_at IS NULL`, identityID, keep)
	return err
}

// ResetMfa removes a member's authenticator (a lost phone; POST /users/{id}/mfa/reset): they sign in with the
// password and enrol again. Refused for a person who is a member of another company too (MFA is theirs).
func (s *Service) ResetMfa(ctx context.Context, id string) (ManagedUser, error) {
	me, err := Require(ctx, "auth.users", "update")
	if err != nil {
		return ManagedUser{}, err
	}
	err = s.DB.InTx(ctx, func(ctx context.Context) error {
		u, err := s.actorUser(ctx, me, id, true)
		if err != nil {
			return notFound(err)
		}
		if shared, err := s.sharedElsewhere(ctx, u); err != nil {
			return err
		} else if shared {
			return apperr.Conflict("SHARED_IDENTITY", "Orang ini juga anggota perusahaan lain; MFA-nya tidak dapat direset di sini. Ia bisa masuk dengan kode cadangan.")
		}
		if err := s.dropFactors(ctx, u.IdentityID, ""); err != nil {
			return err
		}
		s.audit(ctx, requestOf(ctx), "user_updated", me, u.Username, "MFA direset oleh administrator")
		return nil
	})
	if err != nil {
		return ManagedUser{}, err
	}
	return s.GetUser(ctx, id)
}
