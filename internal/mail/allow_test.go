package mail

import "testing"

func TestAllowList(t *testing.T) {
	if AllowList(nil) != nil || AllowList([]string{" ", ""}) != nil {
		t.Fatal("an empty list allows every address (nil)")
	}
	allow := AllowList([]string{"Saya@Gmail.com", "@kantor.co.id"})
	for addr, want := range map[string]bool{
		"saya@gmail.com": true, " SAYA@gmail.com ": true, "orang@kantor.co.id": true,
		"lain@gmail.com": false, "saya@gmail.com.evil.test": false, "x@bukan-kantor.co.id": false, "kantor.co.id@evil.test": false,
	} {
		if allow(addr) != want {
			t.Errorf("%q: %v", addr, !want)
		}
	}
}
