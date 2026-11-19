package secretbox

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func key() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func TestSealOpen(t *testing.T) {
	b, err := New(key())
	if err != nil {
		t.Fatal(err)
	}
	s := b.Seal([]byte("rahasia"), "row-1")
	if got, err := b.Open(s, "row-1"); err != nil || string(got) != "rahasia" {
		t.Fatalf("open: %q %v", got, err)
	}
	if s == b.Seal([]byte("rahasia"), "row-1") {
		t.Fatal("a fresh nonce every time")
	}
	if _, err := b.Open(s, "row-2"); err == nil {
		t.Fatal("a value moved to another row must not open")
	}
	other, _ := New(key())
	if _, err := other.Open(s, "row-1"); err == nil {
		t.Fatal("another key must not open it")
	}
	if _, err := New("pendek"); err == nil {
		t.Fatal("a short key is refused")
	}
}
