package auth

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"alir.local/auth-service/internal/mail"
)

// The mail of the service: to the email of the member's employee in that company (Portal Master → Karyawan), else
// the person's own sign-in email. A member with neither gets none (an administrator hands them the reset link).

// emailOf is where the member's mail goes, "" when nowhere.
func (s *Service) emailOf(ctx context.Context, u *userRow) string {
	if u.EmployeeID != nil {
		if t, err := s.Org.Tree(ctx, u.TenantID, false); err == nil {
			if e, ok := t.empByID[*u.EmployeeID]; ok && e.Email != nil {
				return *e.Email
			}
		}
	}
	if u.Email != nil {
		return *u.Email
	}
	return ""
}

func (s *Service) queue(ctx context.Context, kind string, u *userRow, to, subject, body string) {
	if to == "" {
		return
	}
	if err := mail.Queue(ctx, s.DB, kind, &u.IdentityID, &u.TenantID, mail.Message{To: to, Subject: subject, Body: body + signature}); err != nil {
		slog.Error("mail not queued", "kind", kind, "err", err)
	}
}

// queueTo queues a mail to an address of a person (tenantID "" = none).
func (s *Service) queueTo(ctx context.Context, kind, identityID, tenantID, to, subject, body string) {
	var tid *string
	if tenantID != "" {
		tid = &tenantID
	}
	if err := mail.Queue(ctx, s.DB, kind, &identityID, tid, mail.Message{To: to, Subject: subject, Body: body + signature}); err != nil {
		slog.Error("mail not queued", "kind", kind, "err", err)
	}
}

const signature = "\n\n—\nEmail ini dikirim otomatis oleh ALIR. Jangan membalas email ini."

func (s *Service) mailResetLink(ctx context.Context, u *userRow, to, link string, hours int, byAdmin bool) {
	why := "Ada permintaan untuk mengatur ulang password akun ALIR Anda"
	if byAdmin {
		why = "Administrator membuat tautan untuk mengatur ulang password akun ALIR Anda"
	}
	s.queue(ctx, map[bool]string{true: "password_reset_link", false: "password_forgot"}[byAdmin], u, to, "Atur ulang password ALIR",
		fmt.Sprintf("Halo %s,\n\n%s (username: %s, perusahaan: %s).\n\nBuka tautan berikut dalam %d jam; tautan hanya bisa dipakai sekali:\n%s%s\n\nBila Anda tidak memintanya, abaikan email ini; password Anda tidak berubah.",
			u.Name, why, u.Username, u.TenantName, hours, s.Cfg.AppBaseURL, link))
}

func (s *Service) mailAccountCreated(ctx context.Context, u *userRow, to string, existing bool) {
	if existing {
		// The person already has an ALIR identity: they sign in as before and now also see this company.
		s.queue(ctx, "account_created", u, to, "Anda ditambahkan ke "+u.TenantName+" di ALIR",
			fmt.Sprintf("Halo %s,\n\nAnda ditambahkan sebagai anggota %s di ALIR (username di sana: %s).\nMasuk dengan email dan password ALIR Anda seperti biasa, lalu pilih perusahaan %s.\nMasuk di %s/login", u.Name, u.TenantName, u.Username, u.TenantName, s.Cfg.AppBaseURL))
		return
	}
	s.queue(ctx, "account_created", u, to, "Akun ALIR Anda sudah dibuat",
		fmt.Sprintf("Halo %s,\n\nAkun ALIR Anda di %s sudah dibuat.\nUsername: %s\n\nPassword awal diberikan langsung oleh administrator (tidak pernah lewat email) dan wajib diganti saat pertama masuk.\nMasuk di %s/login", u.Name, u.TenantName, u.Username, s.Cfg.AppBaseURL))
}

func (s *Service) mailPasswordChanged(ctx context.Context, u *userRow, to string) {
	s.queue(ctx, "password_changed", u, to, "Password ALIR Anda diganti",
		fmt.Sprintf("Halo %s,\n\nPassword akun ALIR Anda (username: %s) baru saja diganti pada %s UTC.\n\nBila bukan Anda yang menggantinya, segera hubungi administrator.", u.Name, u.Username, time.Now().UTC().Format("2006-01-02 15:04")))
}
