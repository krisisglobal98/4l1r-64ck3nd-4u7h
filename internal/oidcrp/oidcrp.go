// Package oidcrp is the relying-party side of OpenID Connect: Authentication signing people in through a
// company's identity provider (Microsoft Entra ID, Google, any OIDC provider). Discovery and keys are cached; an ID
// token is accepted only signed RS256 or ES256 by a key of the provider, for this client, from this issuer, not
// expired, with the nonce of the sign-in.
package oidcrp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Discovery is the part of a provider's openid-configuration the sign-in needs.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// Client talks to providers; its caches are shared by every sign-in.
type Client struct {
	HTTP *http.Client
	TTL  time.Duration // how long discovery and keys are kept (default 1 h)

	mu        sync.Mutex
	discovery map[string]cached[Discovery]
	keys      map[string]cached[map[string]crypto.PublicKey]
}

type cached[T any] struct {
	at time.Time
	v  T
}

func (c *Client) ttl() time.Duration {
	if c.TTL <= 0 {
		return time.Hour
	}
	return c.TTL
}

func (c *Client) getJSON(ctx context.Context, u string, into any) error {
	if !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("provider address must be https: %s", u)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", u, res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(into)
}

// Discover reads issuer/.well-known/openid-configuration (cached); its issuer must be the configured one.
func (c *Client) Discover(ctx context.Context, issuer string) (Discovery, error) {
	issuer = strings.TrimRight(issuer, "/")
	c.mu.Lock()
	if d, ok := c.discovery[issuer]; ok && time.Since(d.at) < c.ttl() {
		c.mu.Unlock()
		return d.v, nil
	}
	c.mu.Unlock()
	var d Discovery
	if err := c.getJSON(ctx, issuer+"/.well-known/openid-configuration", &d); err != nil {
		return d, err
	}
	if strings.TrimRight(d.Issuer, "/") != issuer {
		return d, fmt.Errorf("discovery issuer %q is not %q", d.Issuer, issuer)
	}
	for _, u := range []string{d.AuthorizationEndpoint, d.TokenEndpoint, d.JWKSURI} {
		if !strings.HasPrefix(u, "https://") {
			return d, fmt.Errorf("provider endpoint must be https: %q", u)
		}
	}
	c.mu.Lock()
	if c.discovery == nil {
		c.discovery = map[string]cached[Discovery]{}
	}
	c.discovery[issuer] = cached[Discovery]{time.Now(), d}
	c.mu.Unlock()
	return d, nil
}

// AuthURL is the address the browser goes to: code flow with PKCE (S256), state and nonce.
func AuthURL(d Discovery, clientID, redirectURI, state, nonce, verifier string, scopes []string, extra url.Values) string {
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI}, "scope": {strings.Join(scopes, " ")},
		"state": {state}, "nonce": {nonce}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	for k, v := range extra {
		q[k] = v
	}
	sep := "?"
	if strings.Contains(d.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return d.AuthorizationEndpoint + sep + q.Encode()
}

// Exchange trades the code at the token endpoint (client_secret_post) and answers the ID token.
func (c *Client) Exchange(ctx context.Context, d Discovery, clientID, secret, code, redirectURI, verifier string) (string, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier},
		"client_id": {clientID}, "client_secret": {secret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var out struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		Desc    string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("token endpoint: %w", err)
	}
	if res.StatusCode != http.StatusOK || out.IDToken == "" {
		return "", fmt.Errorf("token endpoint: HTTP %d %s %s", res.StatusCode, out.Error, out.Desc)
	}
	return out.IDToken, nil
}

type jwk struct {
	Kty, Kid, Use, Alg, N, E, Crv, X, Y string
}

func (k jwk) key() (crypto.PublicKey, error) {
	b := func(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")) }
	switch k.Kty {
	case "RSA":
		n, err := b(k.N)
		if err != nil {
			return nil, err
		}
		e, err := b(k.E)
		if err != nil || len(e) > 4 {
			return nil, errors.New("rsa exponent")
		}
		ex := 0
		for _, x := range e {
			ex = ex<<8 | int(x)
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: ex}
		if pub.N.BitLen() < 2048 {
			return nil, errors.New("rsa key shorter than 2048 bits")
		}
		return pub, nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, errors.New("only P-256")
		}
		x, err := b(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b(k.Y)
		if err != nil {
			return nil, err
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("point not on curve")
		}
		return pub, nil
	}
	return nil, fmt.Errorf("key type %s", k.Kty)
}

func (c *Client) keySet(ctx context.Context, jwksURI string, fresh bool) (map[string]crypto.PublicKey, error) {
	c.mu.Lock()
	if k, ok := c.keys[jwksURI]; ok && !fresh && time.Since(k.at) < c.ttl() {
		c.mu.Unlock()
		return k.v, nil
	}
	c.mu.Unlock()
	var set struct{ Keys []jwk }
	if err := c.getJSON(ctx, jwksURI, &set); err != nil {
		return nil, err
	}
	out := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if pub, err := k.key(); err == nil {
			out[k.Kid] = pub
		}
	}
	c.mu.Lock()
	if c.keys == nil {
		c.keys = map[string]cached[map[string]crypto.PublicKey]{}
	}
	c.keys[jwksURI] = cached[map[string]crypto.PublicKey]{time.Now(), out}
	c.mu.Unlock()
	return out, nil
}

// ErrToken is any refusal of an ID token (the reason in the message, for the log only).
var ErrToken = errors.New("id token refused")

// Verify checks an ID token of the provider and answers its claims.
func (c *Client) Verify(ctx context.Context, d Discovery, raw, clientID, nonce string, now time.Time) (map[string]any, error) {
	bad := func(why string) error { return fmt.Errorf("%w: %s", ErrToken, why) }
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(raw) > 32<<10 {
		return nil, bad("not a JWS")
	}
	var head struct{ Alg, Kid string }
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &head) != nil {
		return nil, bad("header")
	}
	if head.Alg != "RS256" && head.Alg != "ES256" {
		return nil, bad("algorithm " + head.Alg)
	}
	keys, err := c.keySet(ctx, d.JWKSURI, false)
	if err != nil {
		return nil, err
	}
	pub, ok := keys[head.Kid]
	if !ok { // the provider may have rotated its keys: read them once more
		if keys, err = c.keySet(ctx, d.JWKSURI, true); err != nil {
			return nil, err
		}
		if pub, ok = keys[head.Kid]; !ok {
			return nil, bad("unknown key " + head.Kid)
		}
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, bad("signature encoding")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if head.Alg != "RS256" || rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) != nil {
			return nil, bad("signature")
		}
	case *ecdsa.PublicKey:
		if head.Alg != "ES256" || len(sig) != 64 || !ecdsa.Verify(k, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return nil, bad("signature")
		}
	default:
		return nil, bad("key type")
	}
	var cl map[string]any
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(body, &cl) != nil {
		return nil, bad("claims")
	}
	if iss, _ := cl["iss"].(string); strings.TrimRight(iss, "/") != strings.TrimRight(d.Issuer, "/") {
		return nil, bad("issuer " + iss)
	}
	switch aud := cl["aud"].(type) {
	case string:
		if aud != clientID {
			return nil, bad("audience")
		}
	case []any:
		found := false
		for _, a := range aud {
			found = found || a == clientID
		}
		if !found {
			return nil, bad("audience")
		}
		if azp, ok := cl["azp"].(string); len(aud) > 1 && (!ok || azp != clientID) {
			return nil, bad("azp")
		}
	default:
		return nil, bad("audience")
	}
	exp, _ := cl["exp"].(float64)
	if exp == 0 || now.Unix() >= int64(exp)+60 { // a minute of clock difference
		return nil, bad("expired")
	}
	if iat, ok := cl["iat"].(float64); ok && int64(iat) > now.Unix()+300 {
		return nil, bad("issued in the future")
	}
	if n, _ := cl["nonce"].(string); n == "" || n != nonce {
		return nil, bad("nonce")
	}
	return cl, nil
}
