// Package catalog is the permission catalog of ALIR (modules → menus → actions) and the default grants of the
// built-in roles, exported from the frontend (src/services/roles/permissions.ts) so both use the same ids.
// Regenerate catalog.json when the frontend catalog changes.
package catalog

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
)

type Menu struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Actions     []string `json:"actions"`
}

type Module struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Menus []Menu `json:"menus"`
}

// Grants are the granted actions per menu id.
type Grants map[string][]string

//go:embed catalog.json
var raw []byte

var data struct {
	Catalog []Module `json:"catalog"`
	Roles   []struct {
		Code   string `json:"code"`
		Grants Grants `json:"grants"`
	} `json:"roles"`
}

var menus = map[string]Menu{}
var moduleOf = map[string]string{}

func init() {
	if err := json.Unmarshal(raw, &data); err != nil {
		panic(fmt.Sprintf("catalog.json: %v", err))
	}
	for _, m := range data.Catalog {
		for _, x := range m.Menus {
			menus[x.ID], moduleOf[x.ID] = x, m.ID
		}
	}
}

func Modules() []Module { return data.Catalog }

// Full is every action of every menu: the built-in Admin.
func Full() Grants {
	g := Grants{}
	for id, m := range menus {
		g[id] = slices.Clone(m.Actions)
	}
	return g
}

// Default are the grants a built-in role starts with (none for the others).
func Default(role string) Grants {
	for _, r := range data.Roles {
		if r.Code == role {
			return r.Grants
		}
	}
	return Grants{}
}

// Check keeps the actions the catalog has and orders them; it refuses an unknown menu or action, and any action
// without read on that menu (read opens the menu).
func Check(g Grants) (Grants, error) {
	out := Grants{}
	for menu, actions := range g {
		m, ok := menus[menu]
		if !ok {
			return nil, fmt.Errorf("Menu %s tidak dikenal.", menu)
		}
		if len(actions) == 0 {
			continue
		}
		set := map[string]bool{}
		for _, a := range actions {
			if !slices.Contains(m.Actions, a) {
				return nil, fmt.Errorf("Aksi %s tidak tersedia di menu %s.", a, m.Name)
			}
			set[a] = true
		}
		if !set["read"] {
			return nil, fmt.Errorf("Menu %s: aksi lain butuh hak Lihat.", m.Name)
		}
		var ordered []string
		for _, a := range m.Actions {
			if set[a] {
				ordered = append(ordered, a)
			}
		}
		out[menu] = ordered
	}
	return out, nil
}

// ModuleOf is the module of a menu.
func ModuleOf(menu string) string { return moduleOf[menu] }

// ModuleIDs are the ids of every module, in catalog order.
func ModuleIDs() []string {
	var ids []string
	for _, m := range data.Catalog {
		ids = append(ids, m.ID)
	}
	return ids
}

// Known says whether a module id exists.
func Known(module string) bool { return slices.Contains(ModuleIDs(), module) }

// Sorted menu ids of g (stable answers).
func (g Grants) Menus() []string {
	ids := make([]string, 0, len(g))
	for id := range g {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
