// Package config reads the service settings from the environment, with a .env file for development.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port        string
	DatabaseURL string
	LogLevel    string
	// Issuer is the iss of the tokens; Portal Master and the applications check it.
	Issuer    string
	AccessTTL time.Duration
	// CookieSecure marks the refresh cookie Secure (HTTPS only); off only for local HTTP development.
	CookieSecure bool
	// CookiePath limits the refresh cookie to the sign-in endpoints as the browser sees them (behind a proxy
	// prefix, e.g. /auth-api/auth).
	CookiePath string
	// PMURL is the Portal Master service, where the organisation tree (user scopes) comes from.
	PMURL string
	// The first administrator, made once when there is no account at all (must change the password).
	AdminUsername, AdminPassword string
	// Mail: SMTP server (empty host = mail waits in the outbox) and the address of the ALIR pages for links.
	SMTPHost, SMTPPort, SMTPUsername, SMTPPassword, SMTPFrom, SMTPTLS string
	AppBaseURL                                                        string
	// PublicURL is where browsers and applications reach this service (the OIDC endpoints are under it); in
	// production it is also the issuer. SSOCookiePath limits the single sign-on cookie to the /oauth2 endpoints as
	// the browser sees them (behind a proxy prefix, e.g. /auth-api/oauth2).
	PublicURL, SSOCookiePath string
	// The terms a person accepts at sign-up (version and the page that shows them).
	TermsVersion, TermsURL string
	// Captcha on the public forms (sign-up, resend, email code): none | turnstile | hcaptcha.
	CaptchaProvider, CaptchaSecret, CaptchaSiteKey string
	// TrustProxy reads the client address from X-Forwarded-For (only behind a proxy that sets it).
	TrustProxy bool
	// SecretKey seals secrets kept in the database (TOTP, identity provider secrets): 32 bytes, base64.
	SecretKey string
}

func Load() (Config, error) {
	loadDotEnv(".env")
	c := Config{
		Port:            get("PORT", "8082"),
		DatabaseURL:     os.Getenv("DATABASE_URL"),
		LogLevel:        get("LOG_LEVEL", "info"),
		Issuer:          get("AUTH_ISSUER", "alir-auth"),
		CookieSecure:    get("AUTH_COOKIE_SECURE", "true") != "false",
		CookiePath:      get("AUTH_COOKIE_PATH", "/auth"),
		PMURL:           strings.TrimRight(get("PM_SERVICE_URL", "http://localhost:8081"), "/"),
		AdminUsername:   strings.ToLower(get("AUTH_ADMIN_USERNAME", "admin")),
		AdminPassword:   os.Getenv("AUTH_ADMIN_PASSWORD"),
		SMTPHost:        os.Getenv("SMTP_HOST"),
		SMTPPort:        get("SMTP_PORT", "587"),
		SMTPUsername:    os.Getenv("SMTP_USERNAME"),
		SMTPPassword:    os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:        get("SMTP_FROM", "ALIR <no-reply@localhost>"),
		SMTPTLS:         get("SMTP_TLS", "starttls"),
		AppBaseURL:      strings.TrimRight(get("APP_BASE_URL", "http://localhost:5173"), "/"),
		SSOCookiePath:   get("AUTH_SSO_COOKIE_PATH", "/oauth2"),
		TermsVersion:    get("AUTH_TERMS_VERSION", "2026-11"),
		TermsURL:        os.Getenv("AUTH_TERMS_URL"),
		CaptchaProvider: get("AUTH_CAPTCHA_PROVIDER", "none"),
		CaptchaSecret:   os.Getenv("AUTH_CAPTCHA_SECRET"),
		CaptchaSiteKey:  os.Getenv("AUTH_CAPTCHA_SITE_KEY"),
		TrustProxy:      get("AUTH_TRUST_PROXY", "false") == "true",
		SecretKey:       os.Getenv("AUTH_SECRET_KEY"),
	}
	if c.SecretKey == "" {
		return c, fmt.Errorf("AUTH_SECRET_KEY is required (32 bytes, base64: openssl rand -base64 32)")
	}
	switch c.CaptchaProvider {
	case "none":
	case "turnstile", "hcaptcha":
		if c.CaptchaSecret == "" || c.CaptchaSiteKey == "" {
			return c, fmt.Errorf("AUTH_CAPTCHA_PROVIDER=%s needs AUTH_CAPTCHA_SECRET and AUTH_CAPTCHA_SITE_KEY", c.CaptchaProvider)
		}
	default:
		return c, fmt.Errorf(`AUTH_CAPTCHA_PROVIDER must be "none", "turnstile" or "hcaptcha"`)
	}
	c.PublicURL = strings.TrimRight(os.Getenv("AUTH_PUBLIC_URL"), "/")
	if c.PublicURL == "" && (strings.HasPrefix(c.Issuer, "https://") || strings.HasPrefix(c.Issuer, "http://")) {
		c.PublicURL = strings.TrimRight(c.Issuer, "/")
	}
	if c.PublicURL == "" {
		c.PublicURL = "http://localhost:" + c.Port
	}
	if c.SMTPTLS != "starttls" && c.SMTPTLS != "tls" && c.SMTPTLS != "none" {
		return c, fmt.Errorf(`SMTP_TLS must be "starttls", "tls" or "none"`)
	}
	minutes, err := strconv.Atoi(get("AUTH_ACCESS_TTL_MINUTES", "15"))
	if err != nil || minutes < 1 || minutes > 60 {
		return c, fmt.Errorf("AUTH_ACCESS_TTL_MINUTES must be 1..60")
	}
	c.AccessTTL = time.Duration(minutes) * time.Minute
	if c.DatabaseURL == "" {
		return c, fmt.Errorf("DATABASE_URL is required")
	}
	return c, nil
}

func get(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// loadDotEnv sets the variables of a .env file that the environment does not set already.
func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"`)
		if _, set := os.LookupEnv(k); !set {
			os.Setenv(k, v)
		}
	}
}
