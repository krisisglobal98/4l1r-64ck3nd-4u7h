package totp

import (
	"testing"
	"time"
)

// RFC 6238 appendix B (SHA1, secret "12345678901234567890", 8 digits).
func TestRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{59: "94287082", 1111111109: "07081804", 1111111111: "14050471", 1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130"} {
		if got := Code(secret, unix/Period, 8); got != want {
			t.Errorf("t=%d: %s, want %s", unix, got, want)
		}
	}
}

func TestVerifyWindowAndReplay(t *testing.T) {
	secret := NewSecret()
	now := time.Unix(1_800_000_000, 0)
	cur := Step(now)
	if s, ok := Verify(secret, Code(secret, cur, Digits), now, 0); !ok || s != cur {
		t.Fatal("current code")
	}
	if _, ok := Verify(secret, Code(secret, cur-1, Digits), now, 0); !ok {
		t.Fatal("previous step (drift)")
	}
	if _, ok := Verify(secret, Code(secret, cur-2, Digits), now, 0); ok {
		t.Fatal("two steps old must fail")
	}
	if _, ok := Verify(secret, Code(secret, cur, Digits), now, cur); ok {
		t.Fatal("a used step must fail (replay)")
	}
	if _, ok := Verify(secret, "12345", now, 0); ok {
		t.Fatal("short code")
	}
	if u := URL("ALIR", "budi@contoh.co.id", secret); len(u) < 40 || u[:15] != "otpauth://totp/" {
		t.Fatalf("url %s", u)
	}
}
