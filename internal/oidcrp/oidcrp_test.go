package oidcrp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func sign(t *testing.T, key *rsa.PrivateKey, kid, alg string, claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	b, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
	if alg == "none" {
		return in + "."
	}
	d := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestVerify(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "authorization_endpoint": srv.URL + "/a", "token_endpoint": srv.URL + "/t", "jwks_uri": srv.URL + "/k"})
		case "/k":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		}
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client()}
	ctx := context.Background()
	d, err := c.Discover(ctx, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	good := map[string]any{"iss": srv.URL, "aud": "cid", "sub": "u1", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "nonce": "n1"}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for a, b := range good {
			m[a] = b
		}
		m[k] = v
		return m
	}
	if cl, err := c.Verify(ctx, d, sign(t, key, "k1", "RS256", good), "cid", "n1", now); err != nil || cl["sub"] != "u1" {
		t.Fatalf("good token: %v", err)
	}
	for name, tok := range map[string]string{
		"other key": sign(t, other, "k1", "RS256", good), "unknown kid": sign(t, key, "k9", "RS256", good), "alg none": sign(t, key, "k1", "none", good),
		"HS256": sign(t, key, "k1", "HS256", good), "wrong aud": sign(t, key, "k1", "RS256", with("aud", "lain")), "wrong iss": sign(t, key, "k1", "RS256", with("iss", "https://evil.test")),
		"expired": sign(t, key, "k1", "RS256", with("exp", now.Add(-2*time.Minute).Unix())), "wrong nonce": sign(t, key, "k1", "RS256", with("nonce", "n2")),
		"no nonce": sign(t, key, "k1", "RS256", with("nonce", "")), "multi aud without azp": sign(t, key, "k1", "RS256", with("aud", []any{"cid", "lain"})),
	} {
		if _, err := c.Verify(ctx, d, tok, "cid", "n1", now); err == nil {
			t.Errorf("%s accepted", name)
		} else if !errors.Is(err, ErrToken) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := c.Discover(ctx, "http://insecure.test"); err == nil {
		t.Error("http issuer accepted")
	}
}
