//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"alir.local/auth-service/internal/mail"
)

/* ---------------- A tiny SMTP server that keeps what it receives ---------------- */

type smtpMsg struct{ from, to, data string }

type fakeSMTP struct {
	ln   net.Listener
	mu   sync.Mutex
	msgs []smtpMsg
	fail bool // answer 451 to every message
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	say := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
	say("220 fake ESMTP")
	var m smtpMsg
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			say("250 fake")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			m = smtpMsg{from: strings.TrimSpace(line[10:])}
			say("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			m.to = strings.Trim(strings.TrimSpace(line[8:]), "<>")
			say("250 ok")
		case cmd == "DATA":
			say("354 go on")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			m.data = b.String()
			f.mu.Lock()
			fail := f.fail
			if !fail {
				f.msgs = append(f.msgs, m)
			}
			f.mu.Unlock()
			if fail {
				say("451 try later")
			} else {
				say("250 queued")
			}
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func (f *fakeSMTP) sender() mail.SMTP {
	_, port, _ := net.SplitHostPort(f.ln.Addr().String())
	return mail.SMTP{Host: "127.0.0.1", Port: port, From: "ALIR <no-reply@contoh.co.id>", TLS: "none"}
}

// outbox lists the queued mail of kind to an address.
func outbox(t *testing.T, kind, to string) []map[string]any {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT status, subject, body_text, attempts FROM auth.mail_outbox WHERE kind = $1 AND to_address = $2 ORDER BY created_at`, kind, to)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var status, subject, body string
		var attempts int
		_ = rows.Scan(&status, &subject, &body, &attempts)
		out = append(out, map[string]any{"status": status, "subject": subject, "body": body, "attempts": attempts})
	}
	return out
}

func TestEmployeeLink(t *testing.T) {
	a := admin(t)
	body := func(username string, extra map[string]any) map[string]any {
		b := map[string]any{"username": username, "role": "viewer", "levelCode": "COMPANY", "companyCode": "C11", "password": "Awal2026x"}
		for k, v := range extra {
			b[k] = v
		}
		return b
	}

	t.Run("EL01 an account linked to an employee takes its name; the answer carries the employee and its email", func(t *testing.T) {
		r := must(t, a.do(t, "POST", "/users", body("budi", map[string]any{"employeeCode": "e001"})), 201)
		if r.str("employeeCode") != "E001" || r.str("name") != "Budi Santoso" || r.str("employeeName") != "Budi Santoso" || r.str("email") != "budi.santoso@contoh.co.id" || r.Obj["employeeActive"] != true {
			t.Errorf("got %s", r.Raw)
		}
	})

	t.Run("EL02 one employee, one live account; unknown and inactive employees are refused", func(t *testing.T) {
		for name, c := range map[string]struct {
			code, msg string
		}{
			"taken":    {"E001", "Karyawan Budi Santoso sudah punya akun budi; satu karyawan satu akun."},
			"unknown":  {"E999", `Karyawan "E999" tidak ditemukan di master Karyawan.`},
			"inactive": {"E004", "Karyawan Sudah Keluar nonaktif; pilih karyawan lain."},
		} {
			if x := a.do(t, "POST", "/users", body("lain."+name, map[string]any{"employeeCode": c.code})); x.Status != 422 || x.problem("employeeCode") != c.msg {
				t.Errorf("%s: %d %q", name, x.Status, x.problem("employeeCode"))
			}
		}
		// an account without an employee is allowed (system, vendor); it needs a name
		if x := a.do(t, "POST", "/users", body("tanpa.karyawan", nil)); x.Status != 422 || x.problem("name") == "" {
			t.Errorf("no name, no employee: %d %s", x.Status, x.Raw)
		}
		want(t, a.do(t, "POST", "/users", body("integrasi.erp", map[string]any{"name": "Integrasi ERP"})), 201)
	})

	t.Run("EL06 the name of a linked account is the employee's, whatever the body says", func(t *testing.T) {
		r := must(t, a.do(t, "POST", "/users", body("nama.lain", map[string]any{"employeeCode": "E007", "name": "Nama Karangan"})), 201)
		if r.str("name") != "Nama Asli" {
			t.Errorf("name: %s", r.Raw)
		}
		c := newClient()
		if x := must(t, c.login(t, "nama.lain", "Awal2026x"), 200); x.Obj["user"].(map[string]any)["name"] != "Nama Asli" {
			t.Errorf("sign-in name: %s", x.Raw)
		}
	})

	t.Run("EL03 the employee list for the form shows who already has an account", func(t *testing.T) {
		r := must(t, a.do(t, "GET", "/users/employee-options", nil), 200)
		found := false
		for _, e := range r.List {
			if e["code"] == "E001" {
				found = e["username"] == "budi"
			}
		}
		if len(r.List) != 8 || !found {
			t.Errorf("options %s", trunc(r.Raw))
		}
	})

	t.Run("EL04 a deleted account frees its employee", func(t *testing.T) {
		id := must(t, a.do(t, "POST", "/users", body("sari", map[string]any{"employeeCode": "E002"})), 201).str("id")
		must(t, a.do(t, "DELETE", "/users/"+id, nil), 204)
		want(t, a.do(t, "POST", "/users", body("sari.baru", map[string]any{"employeeCode": "E002"})), 201)
	})

	t.Run("EL05 an inactive employee cannot sign in; its sessions stop; active again, it signs in", func(t *testing.T) {
		must(t, a.do(t, "POST", "/users", body("dewi", map[string]any{"employeeCode": "E005"})), 201)
		c := newClient()
		must(t, c.login(t, "dewi", "Awal2026x"), 200)
		must(t, c.do(t, "POST", "/auth/password/change", map[string]any{"next": "Dewi2026x"}), 204)
		setEmployeeActive(t, a, "E005", false)
		defer setEmployeeActive(t, a, "E005", true)
		if x := c.send(t, "GET", "/auth/me", nil); x.Status != 401 || x.str("code") != "ACCOUNT_INACTIVE" {
			t.Errorf("session: %d %s", x.Status, x.Raw)
		}
		if x := c.send(t, "POST", "/auth/refresh", nil); x.Status != 401 {
			t.Errorf("refresh: %d", x.Status)
		}
		if x := newClient().login(t, "dewi", "Dewi2026x"); x.Status != 403 || x.str("code") != "EMPLOYEE_INACTIVE" {
			t.Errorf("login: %d %s", x.Status, x.Raw)
		}
		if x := newClient().login(t, "dewi", "salah"); x.Status != 401 {
			t.Errorf("a wrong guess does not tell: %d", x.Status)
		}
		setEmployeeActive(t, a, "E005", true)
		want(t, newClient().login(t, "dewi", "Dewi2026x"), 200)
	})
}

func TestMail(t *testing.T) {
	a := admin(t)
	smtp := newFakeSMTP(t)
	worker := mail.Worker{DB: svc.DB, Sender: smtp.sender(), Every: time.Second}

	t.Run("EM01 a new account linked to an employee gets a notice without its password; then it is sent", func(t *testing.T) {
		must(t, a.do(t, "POST", "/users", map[string]any{"username": "mail.budi", "employeeCode": "E006", "role": "viewer", "levelCode": "COMPANY", "companyCode": "C11", "password": "Awal2026x"}), 201)
		q := outbox(t, "account_created", "mail.uji@contoh.co.id")
		if len(q) == 0 {
			t.Fatalf("no notice queued")
		}
		last := q[len(q)-1]
		if strings.Contains(last["body"].(string), "Awal2026x") || !strings.Contains(last["body"].(string), "mail.budi") {
			t.Errorf("body: %s", last["body"])
		}
		if n, err := worker.Once(context.Background()); err != nil || n == 0 {
			t.Fatalf("worker: %d %v", n, err)
		}
		smtp.mu.Lock()
		defer smtp.mu.Unlock()
		got := smtp.msgs[len(smtp.msgs)-1]
		if got.to != "mail.uji@contoh.co.id" || !strings.Contains(got.data, "Subject: Akun ALIR Anda sudah dibuat") || strings.Contains(got.data, "Awal2026x") {
			t.Errorf("sent: %+v", got)
		}
	})

	t.Run("EM02 forgot password mails the link to the employee; the link sets the password; a notice follows", func(t *testing.T) {
		must(t, newClient().do(t, "POST", "/auth/password/forgot", map[string]any{"username": "mail.budi"}), 200)
		q := outbox(t, "password_forgot", "mail.uji@contoh.co.id")
		if len(q) != 1 {
			t.Fatalf("queued %d", len(q))
		}
		b := q[0]["body"].(string)
		i := strings.Index(b, "/reset-password?token=")
		if i < 0 || !strings.Contains(b, "http://") {
			t.Fatalf("link: %s", b)
		}
		tok := strings.Fields(b[i+len("/reset-password?token="):])[0]
		must(t, newClient().do(t, "POST", "/auth/password/reset", map[string]any{"token": tok, "password": "Lupa2026x"}), 204)
		want(t, newClient().login(t, "mail.budi", "Lupa2026x"), 200)
		if len(outbox(t, "password_changed", "mail.uji@contoh.co.id")) == 0 {
			t.Error("no password-changed notice")
		}
	})

	t.Run("EM03 the administrator's reset link goes to the email; without one it is handed to the administrator", func(t *testing.T) {
		id := userID(t, a, "mail.budi")
		r := must(t, a.do(t, "POST", "/users/"+id+"/reset-link", nil), 200)
		if r.Obj["link"] != nil || r.str("sentTo") != "m***@contoh.co.id" {
			t.Errorf("mailed: %s", r.Raw)
		}
		nid := must(t, a.do(t, "POST", "/users", map[string]any{"username": "no.mail", "employeeCode": "E003", "role": "viewer", "levelCode": "COMPANY", "companyCode": "C11", "password": "Awal2026x"}), 201).str("id")
		r = must(t, a.do(t, "POST", "/users/"+nid+"/reset-link", nil), 200)
		if !strings.HasPrefix(r.str("link"), "/reset-password?token=") || r.Obj["sentTo"] != nil {
			t.Errorf("handed: %s", r.Raw)
		}
		var n int
		_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM auth.mail_outbox WHERE identity_id = (SELECT identity_id FROM auth.membership WHERE id = $1)`, nid).Scan(&n)
		if n != 0 {
			t.Errorf("mail queued for an employee without email: %d", n)
		}
	})

	t.Run("EM04 a mail server that refuses: retried later, failed after the last try", func(t *testing.T) {
		smtp.mu.Lock()
		smtp.fail = true
		smtp.mu.Unlock()
		defer func() { smtp.mu.Lock(); smtp.fail = false; smtp.mu.Unlock() }()
		must(t, newClient().do(t, "POST", "/auth/password/forgot", map[string]any{"username": "mail.budi"}), 200)
		_, _ = worker.Once(context.Background())
		var status string
		var attempts int
		var later bool
		_ = pool.QueryRow(context.Background(), `SELECT status, attempts, next_attempt_at > now() FROM auth.mail_outbox WHERE kind = 'password_forgot' ORDER BY created_at DESC LIMIT 1`).Scan(&status, &attempts, &later)
		if status != "pending" || attempts != 1 || !later {
			t.Errorf("retry: %s %d %v", status, attempts, later)
		}
		_, _ = pool.Exec(context.Background(), `UPDATE auth.mail_outbox SET attempts = 5, next_attempt_at = now() WHERE status = 'pending'`)
		_, _ = worker.Once(context.Background())
		_ = pool.QueryRow(context.Background(), `SELECT status FROM auth.mail_outbox WHERE kind = 'password_forgot' ORDER BY created_at DESC LIMIT 1`).Scan(&status)
		if status != "failed" {
			t.Errorf("after the last try: %s", status)
		}
	})

	t.Run("EM05 two workers never send one message twice", func(t *testing.T) {
		before := len(smtp.msgs)
		for range 6 {
			must(t, newClient().do(t, "POST", "/auth/password/forgot", map[string]any{"username": "mail.budi"}), 200)
		}
		var wg sync.WaitGroup
		for range 3 {
			wg.Add(1)
			go func() { defer wg.Done(); _, _ = worker.Once(context.Background()) }()
		}
		wg.Wait()
		smtp.mu.Lock()
		sent := len(smtp.msgs) - before
		smtp.mu.Unlock()
		var pending int
		_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM auth.mail_outbox WHERE status = 'pending'`).Scan(&pending)
		if sent != 6 || pending != 0 {
			t.Errorf("sent %d, pending %d", sent, pending)
		}
	})
}

func userID(t *testing.T, a *client, username string) string {
	t.Helper()
	for _, u := range must(t, a.do(t, "GET", "/users", nil), 200).List {
		if u["username"] == username {
			return u["id"].(string)
		}
	}
	t.Fatalf("no account %s", username)
	return ""
}
