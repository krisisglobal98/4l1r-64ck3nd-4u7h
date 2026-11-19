// Package totp is RFC 6238 time-based one-time passwords (HMAC-SHA1, 30 s, 6 digits), as authenticator apps
// (Google Authenticator, Microsoft Authenticator, 1Password, …) make them.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	Period = 30
	Digits = 6
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret is 160 random bits (RFC 4226 recommends at least 128).
func NewSecret() []byte {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return b
}

// Encode is the secret as the apps take it by hand (base32, no padding).
func Encode(secret []byte) string { return b32.EncodeToString(secret) }

// URL is the otpauth:// address an app reads from a QR code.
func URL(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{"secret": {Encode(secret)}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {fmt.Sprint(Digits)}, "period": {fmt.Sprint(Period)}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Step is the time step of t.
func Step(t time.Time) int64 { return t.Unix() / Period }

// Code is the code of a step with digits digits.
func Code(secret []byte, step int64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

// Verify accepts a code of the current step or one step around it (clock drift), newer than lastStep (a code is
// never accepted twice); it answers the step it matched.
func Verify(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != Digits {
		return 0, false
	}
	cur := Step(now)
	for _, s := range []int64{cur - 1, cur, cur + 1} {
		if s <= lastStep {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(Code(secret, s, Digits)), []byte(code)) == 1 {
			return s, true
		}
	}
	return 0, false
}
