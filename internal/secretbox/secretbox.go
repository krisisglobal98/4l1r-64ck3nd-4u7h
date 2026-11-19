// Package secretbox seals secrets kept in the database (TOTP secrets, identity provider client secrets) with
// AES-256-GCM under a key from the environment (AUTH_SECRET_KEY, 32 bytes, base64). A sealed value is "v1:" +
// base64(nonce || ciphertext); the version leaves room for key rotation.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
)

type Box struct{ aead cipher.AEAD }

// New reads a base64 key of 32 bytes.
func New(key64 string) (*Box, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(key64))
	if err != nil || len(key) != 32 {
		return nil, errors.New("AUTH_SECRET_KEY must be 32 bytes in base64 (openssl rand -base64 32)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead}, nil
}

// Seal encrypts plain; aad binds the value to its owner (e.g. the row id), so a sealed value moved elsewhere fails.
func (b *Box) Seal(plain []byte, aad string) string {
	nonce := make([]byte, b.aead.NonceSize())
	_, _ = rand.Read(nonce)
	return "v1:" + base64.StdEncoding.EncodeToString(b.aead.Seal(nonce, nonce, plain, []byte(aad)))
}

var ErrSealed = errors.New("sealed value cannot be opened")

func (b *Box) Open(sealed, aad string) ([]byte, error) {
	raw, ok := strings.CutPrefix(sealed, "v1:")
	if !ok {
		return nil, ErrSealed
	}
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(data) < b.aead.NonceSize() {
		return nil, ErrSealed
	}
	out, err := b.aead.Open(nil, data[:b.aead.NonceSize()], data[b.aead.NonceSize():], []byte(aad))
	if err != nil {
		return nil, ErrSealed
	}
	return out, nil
}
