package password

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	h, err := Hash("Rahasia2026")
	if err != nil || !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("hash %q %v", h, err)
	}
	if h2, _ := Hash("Rahasia2026"); h2 == h {
		t.Fatal("salted: two hashes of one password differ")
	}
	if ok, _ := Verify("Rahasia2026", h); !ok {
		t.Fatal("right password")
	}
	if ok, _ := Verify("rahasia2026", h); ok {
		t.Fatal("wrong password")
	}
	if ok, _ := Verify(strings.Repeat("a", 300), h); ok {
		t.Fatal("over-long input")
	}
	if _, err := Verify("x", "md5$abc"); err == nil {
		t.Fatal("unknown format")
	}
}

func TestRules(t *testing.T) {
	r := Rules{MinLength: 8, RequireUppercase: true, RequireNumber: true, RequireSymbol: true}
	for pw, want := range map[string]string{"Ab1!": "Minimal 8 karakter", "abcdefg1!": "Huruf besar (A–Z)", "Abcdefgh!": "Angka (0–9)", "Abcdefg12": "Simbol (!@#…)", "Abcdefg1!": ""} {
		if got := r.Problem(pw); got != want {
			t.Errorf("%q: %q, want %q", pw, got, want)
		}
	}
}
