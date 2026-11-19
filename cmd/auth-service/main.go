// Command auth-service is the Authentication service of ALIR: sign-in, accounts, roles and access.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"alir.local/auth-service/internal/auth"
	"alir.local/auth-service/internal/mail"
	"alir.local/auth-service/internal/oidcrp"
	"alir.local/auth-service/internal/platform/codeprefix"
	"alir.local/auth-service/internal/platform/config"
	"alir.local/auth-service/internal/platform/database"
	"alir.local/auth-service/internal/platform/httpx"
	"alir.local/auth-service/internal/platform/httpx/reqid"
	"alir.local/auth-service/internal/secretbox"
	"alir.local/auth-service/internal/token"
)

func main() {
	if err := run(); err != nil {
		slog.Error("auth-service stopped", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	var level slog.Level
	_ = level.UnmarshalText([]byte(cfg.LogLevel))
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	db, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Pool.Close()
	box, err := secretbox.New(cfg.SecretKey)
	if err != nil {
		return err
	}
	keys, err := token.Load(ctx, db, box)
	if err != nil {
		return err
	}
	auth.TrustForwarded(cfg.TrustProxy)
	svc := &auth.Service{DB: db, Keys: keys, Cfg: cfg, Codes: codeprefix.Postgres{DB: db}, Captcha: auth.NewCaptcha(cfg.CaptchaProvider, cfg.CaptchaSecret), Box: box,
		RP:  &oidcrp.Client{HTTP: &http.Client{Timeout: 10 * time.Second}},
		Org: &auth.Org{PMURL: cfg.PMURL, Keys: keys, Issuer: cfg.Issuer, Client: &http.Client{Timeout: 10 * time.Second}}}
	if _, err := svc.Bootstrap(ctx); err != nil {
		return err
	}
	// Mail goes out from the outbox in the background; without SMTP_HOST it waits there.
	var sender mail.Sender
	if cfg.SMTPHost != "" {
		sender = mail.SMTP{Host: cfg.SMTPHost, Port: cfg.SMTPPort, Username: cfg.SMTPUsername, Password: cfg.SMTPPassword, From: cfg.SMTPFrom, TLS: cfg.SMTPTLS}
	}
	allow := mail.AllowList(cfg.SMTPAllowOnly)
	if allow != nil {
		slog.Info("mail limited to SMTP_ALLOW_ONLY", "entries", len(cfg.SMTPAllowOnly))
	}
	go mail.Worker{DB: db, Sender: sender, Every: 5 * time.Second, Allow: allow}.Run(ctx)
	// Housekeeping: unverified sign-ups after 7 days, old counters, codes and tokens.
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			if n, err := svc.Cleanup(ctx); err != nil {
				slog.Error("cleanup", "err", err)
			} else if n > 0 {
				slog.Info("unverified sign-ups removed", "count", n)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_ = httpx.JSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := db.Pool.Ping(r.Context()); err != nil {
			_ = httpx.JSON(w, 503, map[string]string{"status": "database unavailable"})
			return
		}
		_ = httpx.JSON(w, 200, map[string]string{"status": "ready"})
	})
	svc.Routes(mux)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           httpx.Chain(mux, reqid.Middleware, httpx.Recover, httpx.Logging, httpx.JSONErrors, svc.Authenticate),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		slog.Info("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	slog.Info("auth-service listening", "port", cfg.Port, "issuer", cfg.Issuer, "pm", cfg.PMURL)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
