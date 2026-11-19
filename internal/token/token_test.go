package token

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testKeys(t *testing.T) *Keys {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &Keys{kid: "ked", priv: ed, rsaKid: "krsa", rsa: rk}
}

func header(t *testing.T, tok string) map[string]string {
	b, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	var h map[string]string
	_ = json.Unmarshal(b, &h)
	return h
}

func TestIDTokensBothAlgorithms(t *testing.T) {
	k := testKeys(t)
	claims := map[string]any{"iss": "https://auth.test", "sub": "u1", "aud": "app"}
	rs, err := k.SignID(claims, "RS256")
	if err != nil || header(t, rs)["alg"] != "RS256" || header(t, rs)["kid"] != "krsa" {
		t.Fatalf("RS256 %v %v", err, header(t, rs))
	}
	// A verifier that knows only the published JWKS (as an application does).
	var set struct{ Keys []map[string]string }
	b, _ := json.Marshal(k.JWKS())
	_ = json.Unmarshal(b, &set)
	var n, e string
	for _, x := range set.Keys {
		if x["kty"] == "RSA" && x["kid"] == "krsa" {
			n, e = x["n"], x["e"]
		}
	}
	nb, _ := base64.RawURLEncoding.DecodeString(n)
	eb, _ := base64.RawURLEncoding.DecodeString(e)
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}
	parts := strings.Split(rs, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], sig) != nil {
		t.Fatal("RS256 ID token does not verify with the published key")
	}
	if len(set.Keys) != 2 {
		t.Fatalf("jwks %v", set.Keys)
	}
	ed, _ := k.SignID(claims, "EdDSA")
	for _, tok := range []string{rs, ed} {
		if c, err := k.Inspect(tok, "https://auth.test"); err != nil || c["sub"] != "u1" {
			t.Errorf("inspect %s: %v", header(t, tok)["alg"], err)
		}
	}
	if _, err := k.SignID(claims, "HS256"); err == nil {
		t.Error("unknown algorithm signed")
	}
}

func TestAccessTokensStayEdDSA(t *testing.T) {
	k := testKeys(t)
	c := Claims{Issuer: "alir", Audience: Audience, Subject: "u1", Expires: time.Now().Add(time.Minute).Unix()}
	at, _ := k.Sign(c)
	if _, err := k.Verify(at, "alir", time.Now()); err != nil || header(t, at)["alg"] != "EdDSA" {
		t.Fatalf("access token %v", err)
	}
	// An RS256 token with access-token claims is not an access token.
	rs, _ := k.SignID(c, "RS256")
	if _, err := k.Verify(rs, "alir", time.Now()); err == nil {
		t.Error("an RS256 token accepted as an access token")
	}
	// A token whose header names the RSA key but is signed by another key.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	forged := &Keys{kid: k.kid, priv: k.priv, rsaKid: k.rsaKid, rsa: other}
	ft, _ := forged.SignID(map[string]any{"iss": "alir"}, "RS256")
	if _, err := k.Inspect(ft, "alir"); err == nil {
		t.Error("forged RS256 accepted")
	}
}
