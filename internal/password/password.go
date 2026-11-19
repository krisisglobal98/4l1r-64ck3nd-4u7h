// Package password hashes passwords with argon2id and checks them against the security policy, with the same
// rules and words as the ALIR forms (src/services/auth/passwordRules.ts).
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Parameters of new hashes (OWASP: argon2id, 19 MiB, 2 passes, 1 lane); old hashes keep theirs.
const (
	memory  = 19 * 1024
	passes  = 2
	lanes   = 1
	keyLen  = 32
	saltLen = 16
	maxLen  = 256 // longer input is refused before hashing (no hashing of megabytes)
)

// Hash is the PHC string of password: $argon2id$v=19$m=…,t=…,p=…$salt$hash.
func Hash(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, passes, memory, lanes, keyLen)
	b64 := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memory, passes, lanes, b64(salt), b64(key)), nil
}

var errFormat = errors.New("unknown password hash")

// Verify says whether password matches the PHC hash (constant time).
func Verify(password, hash string) (bool, error) {
	if len(password) > maxLen {
		return false, nil
	}
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errFormat
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, errFormat
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return false, errFormat
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// dummy is verified when no account matches, so a missing username takes as long as a wrong password.
var dummy, _ = Hash("not-a-password")

// Burn spends the time of one verification.
func Burn(password string) { _, _ = Verify(password, dummy) }

// Rules are the password rules of the security policy.
type Rules struct {
	MinLength                                      int
	RequireUppercase, RequireNumber, RequireSymbol bool
}

var (
	upper  = regexp.MustCompile(`[A-Z]`)
	digit  = regexp.MustCompile(`[0-9]`)
	symbol = regexp.MustCompile(`[^A-Za-z0-9]`)
)

// Problem is the first rule pw breaks (the label the form shows), or "" when it meets them all.
func (r Rules) Problem(pw string) string {
	switch {
	case len([]rune(pw)) < r.MinLength:
		return fmt.Sprintf("Minimal %d karakter", r.MinLength)
	case len(pw) > maxLen:
		return fmt.Sprintf("Maksimal %d karakter", maxLen)
	case r.RequireUppercase && !upper.MatchString(pw):
		return "Huruf besar (A–Z)"
	case r.RequireNumber && !digit.MatchString(pw):
		return "Angka (0–9)"
	case r.RequireSymbol && !symbol.MatchString(pw):
		return "Simbol (!@#…)"
	}
	return ""
}
