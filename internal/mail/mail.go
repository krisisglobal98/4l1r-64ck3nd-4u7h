// Package mail sends the service's mail: messages are written to auth.mail_outbox in the transaction of what causes
// them, and a worker sends them over SMTP, retrying with growing waits. Plain UTF-8 text; never a password.
package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"alir.local/auth-service/internal/platform/database"
)

type Message struct {
	To, Subject, Body string
}

// Sender delivers one message.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// SMTP sends through a mail server. TLS: "starttls" (port 587), "tls" (implicit, port 465) or "none" (a local
// catcher such as Mailpit only).
type SMTP struct {
	Host, Port, Username, Password, From, TLS string
}

func (s SMTP) Send(ctx context.Context, m Message) error {
	from, err := mail.ParseAddress(s.From)
	if err != nil {
		return fmt.Errorf("SMTP_FROM: %w", err)
	}
	to, err := mail.ParseAddress(m.To)
	if err != nil {
		return fmt.Errorf("recipient: %w", err)
	}
	addr := net.JoinHostPort(s.Host, s.Port)
	d := net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	if s.TLS == "tls" {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if s.TLS == "starttls" {
		if err := c.StartTLS(&tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if s.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(to.Address); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(Build(from, to, m.Subject, m.Body, time.Now())); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// Build is the RFC 5322 message: UTF-8 subject (encoded word) and quoted-printable body.
func Build(from, to *mail.Address, subject, body string, at time.Time) []byte {
	var b bytes.Buffer
	id := make([]byte, 12)
	_, _ = rand.Read(id)
	domain := from.Address[strings.LastIndex(from.Address, "@")+1:]
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\nMIME-Version: 1.0\r\n",
		from.String(), to.String(), mime.QEncoding.Encode("utf-8", subject), at.UTC().Format(time.RFC1123Z), hex.EncodeToString(id), domain)
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
	q := quotedprintable.NewWriter(&b)
	_, _ = q.Write([]byte(strings.ReplaceAll(body, "\n", "\r\n")))
	_ = q.Close()
	return b.Bytes()
}

// Queue writes a message to the outbox (in the transaction of ctx, when there is one).
func Queue(ctx context.Context, db *database.DB, kind string, identityID, tenantID *string, m Message) error {
	_, err := db.Q(ctx).Exec(ctx, `INSERT INTO auth.mail_outbox (kind, identity_id, tenant_id, to_address, subject, body_text) VALUES ($1, $2, $3, $4, $5, $6)`,
		kind, identityID, tenantID, m.To, truncate(m.Subject, 200), m.Body)
	return err
}

// backoff is the wait after attempt n (1-based); after the last one the message is failed.
var backoff = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 3 * time.Hour}

// Worker sends due messages every Every; Sender nil means no SMTP yet: messages wait in the outbox. Allow, when set,
// is the only addresses mail may go to (development and tests: never mail a stranger); others are held, not sent.
type Worker struct {
	DB     *database.DB
	Sender Sender
	Every  time.Duration
	Allow  func(to string) bool
}

// AllowList is the allow rule of SMTP_ALLOW_ONLY: exact addresses ("a@b.co") and whole domains ("@b.co"); nil
// (every address) when the list is empty.
func AllowList(entries []string) func(string) bool {
	var exact, domains []string
	for _, e := range entries {
		e = strings.ToLower(strings.TrimSpace(e))
		switch {
		case e == "":
		case strings.HasPrefix(e, "@"):
			domains = append(domains, e)
		default:
			exact = append(exact, e)
		}
	}
	if len(exact) == 0 && len(domains) == 0 {
		return nil
	}
	return func(to string) bool {
		to = strings.ToLower(strings.TrimSpace(to))
		for _, x := range exact {
			if to == x {
				return true
			}
		}
		for _, d := range domains {
			if strings.HasSuffix(to, d) {
				return true
			}
		}
		return false
	}
}

// Held is the error of a message to an address outside the allow list.
const Held = "Ditahan: alamat di luar SMTP_ALLOW_ONLY, tidak dikirim."

func (w Worker) Run(ctx context.Context) {
	if w.Sender == nil {
		slog.Warn("SMTP not configured: mail waits in auth.mail_outbox until SMTP_HOST is set")
		return
	}
	t := time.NewTicker(w.Every)
	defer t.Stop()
	for {
		if n, err := w.Once(ctx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("mail worker", "err", err)
		} else if n > 0 {
			slog.Info("mail sent", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Once sends the due messages (at most 20), each in its own claim: several instances never send one twice.
func (w Worker) Once(ctx context.Context) (int, error) {
	sent := 0
	for range 20 {
		done, err := w.one(ctx)
		if err != nil || !done {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

func (w Worker) one(ctx context.Context) (bool, error) {
	var claimed bool
	err := w.DB.InTx(ctx, func(ctx context.Context) error {
		var id, to, subject, body string
		var attempts int
		err := w.DB.Q(ctx).QueryRow(ctx, `SELECT id, to_address, subject, body_text, attempts FROM auth.mail_outbox
			WHERE status = 'pending' AND next_attempt_at <= now() ORDER BY next_attempt_at LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&id, &to, &subject, &body, &attempts)
		if err != nil {
			return nil // nothing due (or busy elsewhere)
		}
		claimed = true
		if w.Allow != nil && !w.Allow(to) {
			slog.Warn("mail held: address outside SMTP_ALLOW_ONLY", "to", Mask(to))
			_, err = w.DB.Q(ctx).Exec(ctx, `UPDATE auth.mail_outbox SET status = 'failed', last_error = $2 WHERE id = $1`, id, Held)
			return err
		}
		sendErr := w.Sender.Send(ctx, Message{To: to, Subject: subject, Body: body})
		if sendErr == nil {
			_, err = w.DB.Q(ctx).Exec(ctx, `UPDATE auth.mail_outbox SET status = 'sent', attempts = attempts + 1, sent_at = now(), last_error = NULL WHERE id = $1`, id)
			return err
		}
		slog.Warn("mail not sent", "to", Mask(to), "attempt", attempts+1, "err", sendErr)
		if attempts+1 > len(backoff) {
			_, err = w.DB.Q(ctx).Exec(ctx, `UPDATE auth.mail_outbox SET status = 'failed', attempts = attempts + 1, last_error = $2 WHERE id = $1`, id, truncate(sendErr.Error(), 500))
			return err
		}
		_, err = w.DB.Q(ctx).Exec(ctx, `UPDATE auth.mail_outbox SET attempts = attempts + 1, last_error = $2, next_attempt_at = now() + make_interval(secs => $3) WHERE id = $1`,
			id, truncate(sendErr.Error(), 500), backoff[attempts].Seconds())
		return err
	})
	return claimed, err
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// Mask hides most of an address for answers to an administrator: b***@contoh.co.id.
func Mask(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 1 {
		return "***"
	}
	return addr[:1] + "***" + addr[at:]
}
