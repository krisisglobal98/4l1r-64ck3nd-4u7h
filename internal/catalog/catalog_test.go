package catalog

import "testing"

func TestCatalog(t *testing.T) {
	if len(Modules()) == 0 || len(Full()) < 50 {
		t.Fatalf("catalog not loaded: %d modules, %d menus", len(Modules()), len(Full()))
	}
	if g := Default("viewer"); len(g) == 0 {
		t.Fatal("viewer has default grants")
	}
	if _, err := Check(Grants{"pm.orgUnit": {"export", "read"}}); err != nil {
		t.Fatal(err)
	}
	if g, _ := Check(Grants{"pm.orgUnit": {"export", "read"}}); g["pm.orgUnit"][0] != "read" {
		t.Fatalf("ordered as the catalog: %v", g)
	}
	for name, g := range map[string]Grants{"menu": {"x": {"read"}}, "action": {"pm.orgUnit": {"read", "fly"}}, "no read": {"pm.orgUnit": {"export"}}} {
		if _, err := Check(g); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if ModuleOf("pm.orgUnit") != "portal-master" || !Known("authentication") || Known("nope") {
		t.Fatal("modules")
	}
}
