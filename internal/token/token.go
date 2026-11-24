// Package token signs and checks the tokens of the service. Access tokens are JWS compact, EdDSA (Ed25519), short
// lived; ID tokens of OpenID Connect are RS256 (the algorithm every provider must offer) or EdDSA, as the application
// chooses. The private keys live in auth.signing_key (made on first start); their public halves are published as one
// JWKS for Portal Master and the applications.
package token

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"alir.local/auth-service/internal/platform/database"
	"alir.local/auth-service/internal/secretbox"
)

// Audience of every access token.
const Audience = "alir"

// Claims of an access token. Grants are the effective access when the token was made (Admin: Full, no list).
type Claims struct {
	ID        string `json:"jti,omitempty"` // unique per token
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Subject   string `json:"sub"` // the person (identity id): the same in every tenant
	SessionID string `json:"sid"`
	MemberID  string `json:"mid,omitempty"` // the person's membership in the tenant
	TenantID  string `json:"tid"`           // the company the token acts in (Portal Master scopes every row by it)
	IssuedAt  int64  `json:"iat"`
	Expires   int64  `json:"exp"`
	Username  string `json:"username"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	Full      bool   `json:"full,omitempty"`
	// Platform: the person administers the installation; services let them change the data all companies share
	// (Portal Master's global reference masters: countries, currencies, Incoterms).
	Platform bool                `json:"pa,omitempty"`
	Grants   map[string][]string `json:"grants,omitempty"`
	ClientID string              `json:"client_id,omitempty"` // the application the token was issued to (OIDC)
	Scope    string              `json:"scope,omitempty"`
}

// Keys are the signing keys: Ed25519 (access tokens, ID tokens on request) and RSA (ID tokens).
type Keys struct {
	kid    string
	priv   ed25519.PrivateKey
	rsaKid string
	rsa    *rsa.PrivateKey
}

func newKid() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "k" + hex.EncodeToString(b)
}

// The private keys are stored sealed (secretbox, bound to their kid): whoever reads the database cannot sign tokens.
// A key stored before sealing existed is sealed in place the first time it is read.
const sealedPrefix = "v1:"

// current is the newest live key of alg, made the first time.
func current(ctx context.Context, db *database.DB, box *secretbox.Box, alg string, make func() ([]byte, error)) (string, []byte, error) {
	var kid string
	var stored []byte
	err := db.Pool.QueryRow(ctx, `SELECT kid, private_key FROM auth.signing_key WHERE alg = $1 AND retired_at IS NULL ORDER BY created_at DESC LIMIT 1`, alg).Scan(&kid, &stored)
	if errors.Is(err, pgx.ErrNoRows) {
		priv, err := make()
		if err != nil {
			return "", nil, err
		}
		kid = newKid()
		_, err = db.Pool.Exec(ctx, `INSERT INTO auth.signing_key (kid, private_key, alg) VALUES ($1, $2, $3)`, kid, []byte(box.Seal(priv, "signing-key:"+kid)), alg)
		return kid, priv, err
	}
	if err != nil {
		return "", nil, err
	}
	if strings.HasPrefix(string(stored), sealedPrefix) {
		priv, err := box.Open(string(stored), "signing-key:"+kid)
		if err != nil {
			return "", nil, fmt.Errorf("signing key %s cannot be opened with AUTH_SECRET_KEY: %w", kid, err)
		}
		return kid, priv, nil
	}
	_, err = db.Pool.Exec(ctx, `UPDATE auth.signing_key SET private_key = $2 WHERE kid = $1`, kid, []byte(box.Seal(stored, "signing-key:"+kid)))
	return kid, stored, err
}

// Load reads the current signing keys (opened with box), making them the first time.
func Load(ctx context.Context, db *database.DB, box *secretbox.Box) (*Keys, error) {
	kid, priv, err := current(ctx, db, box, "EdDSA", func() ([]byte, error) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	})
	if err != nil {
		return nil, err
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing key %s: bad size", kid)
	}
	rkid, rder, err := current(ctx, db, box, "RS256", func() ([]byte, error) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		return x509.MarshalPKCS8PrivateKey(key)
	})
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(rder)
	rkey, ok := parsed.(*rsa.PrivateKey)
	if err != nil || !ok || rkey.N.BitLen() < 2048 {
		return nil, fmt.Errorf("signing key %s: not an RSA key of 2048 bits or more", rkid)
	}
	return &Keys{kid: kid, priv: ed25519.PrivateKey(priv), rsaKid: rkid, rsa: rkey}, nil
}

var b64 = base64.RawURLEncoding

func (k *Keys) sign(alg string, claims any) (string, error) {
	kid := k.kid
	if alg == "RS256" {
		kid = k.rsaKid
	}
	head, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT", "kid": kid})
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(head) + "." + b64.EncodeToString(body)
	var sig []byte
	switch alg {
	case "EdDSA":
		sig = ed25519.Sign(k.priv, []byte(input))
	case "RS256":
		d := sha256.Sum256([]byte(input))
		if sig, err = rsa.SignPKCS1v15(rand.Reader, k.rsa, crypto.SHA256, d[:]); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("algorithm %s", alg)
	}
	return input + "." + b64.EncodeToString(sig), nil
}

// Sign makes the access token of c (EdDSA).
func (k *Keys) Sign(c Claims) (string, error) { return k.sign("EdDSA", c) }

// SignID makes an ID token with alg (RS256 or EdDSA).
func (k *Keys) SignID(claims any, alg string) (string, error) { return k.sign(alg, claims) }

// Errors of Verify; ErrExpired lets a client refresh instead of signing in again.
var (
	ErrInvalid = errors.New("invalid token")
	ErrExpired = errors.New("token expired")
)

// checked verifies the signature of a token of this service (either key) and answers its claims bytes and alg.
func (k *Keys) checked(tok string) ([]byte, string, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || len(tok) > 16<<10 {
		return nil, "", ErrInvalid
	}
	var head struct{ Alg, Kid string }
	hb, err := b64.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &head) != nil {
		return nil, "", ErrInvalid
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, "", ErrInvalid
	}
	input := []byte(parts[0] + "." + parts[1])
	switch {
	case head.Alg == "EdDSA" && head.Kid == k.kid:
		if !ed25519.Verify(k.priv.Public().(ed25519.PublicKey), input, sig) {
			return nil, "", ErrInvalid
		}
	case head.Alg == "RS256" && head.Kid == k.rsaKid:
		d := sha256.Sum256(input)
		if rsa.VerifyPKCS1v15(&k.rsa.PublicKey, crypto.SHA256, d[:], sig) != nil {
			return nil, "", ErrInvalid
		}
	default:
		return nil, "", ErrInvalid
	}
	body, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, "", ErrInvalid
	}
	return body, head.Alg, nil
}

// Verify checks an access token: EdDSA only, issuer, audience and expiry.
func (k *Keys) Verify(tok, issuer string, now time.Time) (Claims, error) {
	var c Claims
	body, alg, err := k.checked(tok)
	if err != nil || alg != "EdDSA" {
		return c, ErrInvalid
	}
	if json.Unmarshal(body, &c) != nil || c.Issuer != issuer || c.Audience != Audience || c.Subject == "" {
		return c, ErrInvalid
	}
	if now.Unix() >= c.Expires {
		return c, ErrExpired
	}
	return c, nil
}

// Inspect checks only the signature (either key) and the issuer of a token this service signed, expired or not, and
// answers its claims (id_token_hint at logout names a sign-in that may be over).
func (k *Keys) Inspect(tok, issuer string) (map[string]any, error) {
	body, _, err := k.checked(tok)
	if err != nil {
		return nil, err
	}
	var c map[string]any
	if json.Unmarshal(body, &c) != nil || c["iss"] != issuer {
		return nil, ErrInvalid
	}
	return c, nil
}

// JWKS is the public key set: Ed25519 (RFC 8037) and RSA.
func (k *Keys) JWKS() map[string]any {
	pub := k.priv.Public().(ed25519.PublicKey)
	return map[string]any{"keys": []map[string]string{
		{"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": k.kid, "x": b64.EncodeToString(pub)},
		{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": k.rsaKid, "n": b64.EncodeToString(k.rsa.N.Bytes()),
			"e": b64.EncodeToString(big.NewInt(int64(k.rsa.E)).Bytes())},
	}}
}
