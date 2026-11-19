package auth

import (
	"fmt"
	"slices"

	"alir.local/auth-service/internal/platform/record"
)

// Scope is the organisation scope of an account: Portal Master unit codes from the top down to its level. The
// JSON names are the fields of the ALIR users page (types/users.ts Scope).
type Scope struct {
	OwnerCode           *string `json:"ownerCode"`
	GroupCode           *string `json:"groupCode"`
	RegionCode          *string `json:"regionCode"`
	WilayahCode         *string `json:"wilayahCode"`
	GmkCode             *string `json:"gmkCode"`
	CompanyCode         *string `json:"companyCode"`
	OperationalUnitCode *string `json:"operationalUnitCode"`
	OrgLevel1Code       *string `json:"orgLevel1Code"`
	OrgLevel2Code       *string `json:"orgLevel2Code"`
	OrgLevel3Code       *string `json:"orgLevel3Code"`
}

// field is one offered level of the form, top to bottom, with its scope field.
type field struct {
	level, key, label string
	get               func(*Scope) **string
}

var fields = []field{
	{"GROUP", "groupCode", "Group", func(s *Scope) **string { return &s.GroupCode }},
	{"REGION", "regionCode", "Region", func(s *Scope) **string { return &s.RegionCode }},
	{"WILAYAH", "wilayahCode", "Wilayah", func(s *Scope) **string { return &s.WilayahCode }},
	{"COMPANY", "companyCode", "Perusahaan", func(s *Scope) **string { return &s.CompanyCode }},
	{"OPERATIONAL_UNIT", "operationalUnitCode", "Unit Operasional", func(s *Scope) **string { return &s.OperationalUnitCode }},
	{"ORG_LEVEL_1", "orgLevel1Code", "Organisasi Level 1", func(s *Scope) **string { return &s.OrgLevel1Code }},
	{"ORG_LEVEL_2", "orgLevel2Code", "Organisasi Level 2", func(s *Scope) **string { return &s.OrgLevel2Code }},
	{"ORG_LEVEL_3", "orgLevel3Code", "Organisasi Level 3", func(s *Scope) **string { return &s.OrgLevel3Code }},
}

// GroupAll is the reserved group code for every group.
const GroupAll = "ALL"

// unitLevels are scoped to one operational unit, so its module access limits them.
var unitLevels = map[string]bool{"OPERATIONAL_UNIT": true, "ORG_LEVEL_1": true, "ORG_LEVEL_2": true, "ORG_LEVEL_3": true}

func levelIndex(level string) int {
	return slices.IndexFunc(fields, func(f field) bool { return f.level == level })
}

// allowed are the codes of field f that agree with what is chosen above it (the users page's scopeOptions).
func (t *tree) allowed(f field, s *Scope) []string {
	g := s.GroupCode
	if g != nil && *g == GroupAll {
		g = nil
	}
	eq := func(a *string, b *string) bool { return a == nil || b == nil || *a == *b }
	var out []string
	o := t.options
	switch f.key {
	case "groupCode":
		out = append(out, GroupAll)
		for _, x := range o.Groups {
			out = append(out, x.Code)
		}
	case "regionCode":
		for _, x := range o.Regions {
			if g == nil || len(x.GroupCodes) == 0 || slices.Contains(x.GroupCodes, *g) {
				out = append(out, x.Code)
			}
		}
	case "wilayahCode":
		for _, x := range o.Wilayahs {
			if eq(s.RegionCode, x.RegionCode) {
				out = append(out, x.Code)
			}
		}
	case "companyCode":
		for _, x := range o.Companies {
			if eq(g, x.GroupCode) && eq(s.RegionCode, x.RegionCode) {
				out = append(out, x.Code)
			}
		}
	case "operationalUnitCode":
		for _, x := range o.Units {
			if eq(s.CompanyCode, x.CompanyCode) {
				out = append(out, x.Code)
			}
		}
	case "orgLevel1Code":
		for _, x := range o.OrgLevel1s {
			if eq(s.OperationalUnitCode, x.UnitCode) {
				out = append(out, x.Code)
			}
		}
	case "orgLevel2Code":
		for _, x := range o.OrgLevel2s {
			if eq(s.OrgLevel1Code, x.OrgLevel1Code) {
				out = append(out, x.Code)
			}
		}
	case "orgLevel3Code":
		for _, x := range o.OrgLevel3s {
			if eq(s.OrgLevel2Code, x.OrgLevel2Code) {
				out = append(out, x.Code)
			}
		}
	}
	return out
}

// checkScope clears what the level does not use (retired Owner/GMK, levels below) and adds a problem per code
// missing at the level or not fitting what is chosen above it.
func (t *tree) checkScope(level string, s *Scope, p *record.Problems) {
	s.OwnerCode, s.GmkCode = nil, nil
	at := levelIndex(level)
	if at < 0 {
		p.Add("levelCode", "Level akses wajib dipilih.")
		return
	}
	for i, f := range fields {
		v := f.get(s)
		if *v != nil && *(*v) == "" {
			*v = nil
		}
		switch {
		case i > at:
			*v = nil
		case *v == nil && i == at:
			p.Add(f.key, fmt.Sprintf("%s wajib dipilih untuk level ini.", f.label))
		case *v != nil && !slices.Contains(t.allowed(f, s), **v):
			p.Add(f.key, fmt.Sprintf("%s \"%s\" tidak ada di master organisasi atau tidak sesuai pilihan di atasnya.", f.label, **v))
		}
	}
}

// names are the unit names of the scope codes (the users page shows them).
func (t *tree) names(s Scope) map[string]*string {
	out := map[string]*string{"ownerCode": nil, "gmkCode": nil}
	for _, f := range fields {
		var name *string
		if v := *f.get(&s); v != nil {
			n := *v
			if *v == GroupAll {
				n = "Semua group"
			} else if u, ok := t.units[*v]; ok {
				n = u.Name
			}
			name = &n
		}
		out[f.key] = name
	}
	return out
}
