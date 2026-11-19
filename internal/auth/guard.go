package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"alir.local/auth-service/internal/platform/apperr"
)

// Abuse protection of the public forms: rate limits shared by every instance (auth.rate_event) and an optional
// captcha. A refused attempt answers 429 RATE_LIMITED with the seconds to wait.

// Limit is at most Max attempts per Window.
type Limit struct {
	Max    int
	Window time.Duration
}

// Limits of the public forms; a zero Limit is off.
type Limits struct {
	SignupPerEmail, SignupPerIP Limit
	ResendPerEmail, ResendPerIP Limit
	OTPPerEmail, OTPPerIP       Limit
	OTPVerifyPerEmail           Limit
	LoginPerIP                  Limit
}

// DefaultLimits are the production limits.
var DefaultLimits = Limits{
	SignupPerEmail: Limit{3, time.Hour}, SignupPerIP: Limit{20, time.Hour},
	ResendPerEmail: Limit{3, time.Hour}, ResendPerIP: Limit{30, time.Hour},
	OTPPerEmail: Limit{5, 15 * time.Minute}, OTPPerIP: Limit{60, time.Hour},
	OTPVerifyPerEmail: Limit{10, 15 * time.Minute},
	LoginPerIP:        Limit{120, 10 * time.Minute},
}

func (s *Service) limits() Limits {
	if s.Limits == nil {
		return DefaultLimits
	}
	return *s.Limits
}

// limit counts an attempt under key and refuses it beyond l.
func (s *Service) limit(ctx context.Context, key string, l Limit) error {
	if l.Max <= 0 || key == "" {
		return nil
	}
	var n int
	var oldest *time.Time
	if err := s.DB.Q(ctx).QueryRow(ctx, `SELECT count(*), min(at) FROM auth.rate_event WHERE key = $1 AND at > now() - make_interval(secs => $2)`,
		key, l.Window.Seconds()).Scan(&n, &oldest); err != nil {
		return err
	}
	if n >= l.Max {
		wait := int(l.Window.Seconds())
		if oldest != nil {
			wait = max(1, int(time.Until(oldest.Add(l.Window)).Seconds())+1)
		}
		return &apperr.Error{Status: http.StatusTooManyRequests, Code: "RATE_LIMITED",
			Message: fmt.Sprintf("Terlalu banyak percobaan. Coba lagi dalam %d menit.", max(1, (wait+59)/60)), Details: map[string]any{"retryAfterSeconds": wait}}
	}
	_, err := s.DB.Q(ctx).Exec(ctx, `INSERT INTO auth.rate_event (key) VALUES ($1)`, key)
	return err
}

// limitBoth applies a per-email and a per-address limit.
func (s *Service) limitBoth(ctx context.Context, r *http.Request, what, email string, perEmail, perIP Limit) error {
	if err := s.limit(ctx, what+":ip:"+clientIP(r), perIP); err != nil {
		return err
	}
	if email != "" {
		return s.limit(ctx, what+":email:"+strings.ToLower(email), perEmail)
	}
	return nil
}

// Captcha checks the token of a captcha widget.
type Captcha interface {
	Verify(ctx context.Context, token, ip string) (bool, error)
}

// HTTPCaptcha is Cloudflare Turnstile or hCaptcha (the same siteverify form).
type HTTPCaptcha struct {
	VerifyURL, Secret string
	Client            *http.Client
}

// NewCaptcha is the captcha of a provider ("none": nil).
func NewCaptcha(provider, secret string) Captcha {
	switch provider {
	case "turnstile":
		return HTTPCaptcha{VerifyURL: "https://challenges.cloudflare.com/turnstile/v0/siteverify", Secret: secret, Client: &http.Client{Timeout: 5 * time.Second}}
	case "hcaptcha":
		return HTTPCaptcha{VerifyURL: "https://api.hcaptcha.com/siteverify", Secret: secret, Client: &http.Client{Timeout: 5 * time.Second}}
	}
	return nil
}

func (c HTTPCaptcha) Verify(ctx context.Context, token, ip string) (bool, error) {
	form := url.Values{"secret": {c.Secret}, "response": {token}}
	if ip != "" {
		form.Set("remoteip", ip)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.VerifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.Client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	var out struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return false, err
	}
	return out.Success, nil
}

// captchaOK refuses a public form without a valid captcha token (when a captcha is set up).
func (s *Service) captchaOK(ctx context.Context, r *http.Request, token string) error {
	if s.Captcha == nil {
		return nil
	}
	bad := apperr.Validation([]apperr.Problem{{Field: "captcha", Message: "Selesaikan verifikasi captcha."}})
	if token == "" || len(token) > 4096 {
		return bad
	}
	ok, err := s.Captcha.Verify(ctx, token, clientIP(r))
	if err != nil {
		return &apperr.Error{Status: 503, Code: "CAPTCHA_UNAVAILABLE", Message: "Verifikasi captcha tidak dapat dihubungi; coba lagi sebentar lagi."}
	}
	if !ok {
		return bad
	}
	return nil
}
