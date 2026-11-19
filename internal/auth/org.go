package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"alir.local/auth-service/internal/token"
)

// The organisation tree comes from Portal Master (levels and units). Authentication keeps a copy in memory, read
// again after copyTTL or on POST /org/sync; user scopes are checked and named against it.

const copyTTL = time.Minute

// SystemUserID acts for the service itself (its calls to Portal Master).
const SystemUserID = "00000000-0000-7000-8000-000000000000"

type pmUnit struct {
	Code       string  `json:"code"`
	Name       string  `json:"name"`
	Active     bool    `json:"active"`
	LevelCode  string  `json:"levelCode"`
	ParentCode *string `json:"parentCode"`
}

// pmEmployee is an employee as Portal Master answers it (Karyawan).
type pmEmployee struct {
	ID     string  `json:"id"`
	Code   string  `json:"code"`
	Name   string  `json:"name"`
	Nik    string  `json:"nik"`
	Email  *string `json:"email"`
	Active bool    `json:"active"`
}

type pmLevel struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

// Option is one choice of a scope field, with the code of the level above it.
type Option struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

// Options are the scope choices (GET /org/options), the shape the ALIR users page reads (types/users.ts).
type Options struct {
	Groups  []Option `json:"groups"`
	Regions []struct {
		Option
		GroupCodes []string `json:"groupCodes"`
	} `json:"regions"`
	Wilayahs []struct {
		Option
		RegionCode *string `json:"regionCode"`
	} `json:"wilayahs"`
	Companies []struct {
		Option
		GroupCode  *string `json:"groupCode"`
		RegionCode *string `json:"regionCode"`
	} `json:"companies"`
	Units []struct {
		Option
		CompanyCode *string `json:"companyCode"`
	} `json:"units"`
	Gmks       []any `json:"gmks"`
	OrgLevel1s []struct {
		Option
		UnitCode *string `json:"unitCode"`
	} `json:"orgLevel1s"`
	OrgLevel2s []struct {
		Option
		OrgLevel1Code *string `json:"orgLevel1Code"`
	} `json:"orgLevel2s"`
	OrgLevel3s []struct {
		Option
		OrgLevel2Code *string `json:"orgLevel2Code"`
	} `json:"orgLevel3s"`
	LevelNames map[string]string `json:"levelNames"`
}

// tree is one copy of the organisation.
type tree struct {
	at        time.Time
	units     map[string]pmUnit // by code
	levels    []pmLevel
	options   Options
	employees []pmEmployee
	empByID   map[string]pmEmployee
	empByCode map[string]pmEmployee // upper-case code
}

// employee is the live employee with code (any case).
func (t *tree) employee(code string) (pmEmployee, bool) {
	e, ok := t.empByCode[strings.ToUpper(strings.TrimSpace(code))]
	return e, ok
}

// up is the code of the nearest ancestor of u at level (nil when none).
func (t *tree) up(u pmUnit, level string) *string {
	for p := u.ParentCode; p != nil; {
		x, ok := t.units[*p]
		if !ok {
			return nil
		}
		if x.LevelCode == level {
			c := x.Code
			return &c
		}
		p = x.ParentCode
	}
	return nil
}

func build(units []pmUnit, levels []pmLevel, employees []pmEmployee, at time.Time) *tree {
	t := &tree{at: at, units: map[string]pmUnit{}, levels: levels, employees: employees, empByID: map[string]pmEmployee{}, empByCode: map[string]pmEmployee{}}
	for _, e := range employees {
		t.empByID[e.ID], t.empByCode[strings.ToUpper(e.Code)] = e, e
	}
	for _, u := range units {
		t.units[u.Code] = u
	}
	live := slices.DeleteFunc(slices.Clone(units), func(u pmUnit) bool { return !u.Active })
	slices.SortFunc(live, func(a, b pmUnit) int { return strings.Compare(a.Code, b.Code) })
	o := &t.options
	o.Gmks = []any{}
	o.LevelNames = map[string]string{}
	for _, l := range levels {
		if strings.HasPrefix(l.Code, "org") {
			o.LevelNames[l.Code] = l.Name
		}
	}
	for _, u := range live {
		opt := Option{u.Code, u.Name}
		switch u.LevelCode {
		case "group":
			o.Groups = append(o.Groups, opt)
		case "region":
			g := []string{}
			if c := t.up(u, "group"); c != nil {
				g = append(g, *c)
			}
			o.Regions = append(o.Regions, struct {
				Option
				GroupCodes []string `json:"groupCodes"`
			}{opt, g})
		case "wilayah":
			o.Wilayahs = append(o.Wilayahs, struct {
				Option
				RegionCode *string `json:"regionCode"`
			}{opt, t.up(u, "region")})
		case "company":
			o.Companies = append(o.Companies, struct {
				Option
				GroupCode  *string `json:"groupCode"`
				RegionCode *string `json:"regionCode"`
			}{opt, t.up(u, "group"), t.up(u, "region")})
		case "unit":
			o.Units = append(o.Units, struct {
				Option
				CompanyCode *string `json:"companyCode"`
			}{opt, t.up(u, "company")})
		case "org1":
			o.OrgLevel1s = append(o.OrgLevel1s, struct {
				Option
				UnitCode *string `json:"unitCode"`
			}{opt, t.up(u, "unit")})
		case "org2":
			o.OrgLevel2s = append(o.OrgLevel2s, struct {
				Option
				OrgLevel1Code *string `json:"orgLevel1Code"`
			}{opt, t.up(u, "org1")})
		case "org3":
			o.OrgLevel3s = append(o.OrgLevel3s, struct {
				Option
				OrgLevel2Code *string `json:"orgLevel2Code"`
			}{opt, t.up(u, "org2")})
		}
	}
	// Lists are never null in the answer.
	if o.Groups == nil {
		o.Groups = []Option{}
	}
	return t
}

// Org is the copy of the Portal Master organisation of each tenant.
type Org struct {
	PMURL  string
	Keys   *token.Keys
	Issuer string
	Client *http.Client

	mu     sync.Mutex
	copies map[string]*orgCopy // by tenant id
}

// orgCopy is one tenant's copy; its own lock, so a slow tenant does not hold up the others.
type orgCopy struct {
	mu   sync.Mutex
	tree *tree
}

// Tree is the tenant's current copy, read again when older than copyTTL (or when force).
func (o *Org) Tree(ctx context.Context, tenantID string, force bool) (*tree, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("organisation: no tenant")
	}
	o.mu.Lock()
	if o.copies == nil {
		o.copies = map[string]*orgCopy{}
	}
	c := o.copies[tenantID]
	if c == nil {
		c = &orgCopy{}
		o.copies[tenantID] = c
	}
	o.mu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.tree != nil && time.Since(c.tree.at) < copyTTL {
		return c.tree, nil
	}
	var units []pmUnit
	var levels []pmLevel
	if err := o.get(ctx, tenantID, "/pm/masters/org-units", &units); err != nil {
		if c.tree != nil && !force {
			return c.tree, nil // Portal Master is away: keep answering from the last copy
		}
		return nil, err
	}
	if err := o.get(ctx, tenantID, "/pm/masters/levels", &levels); err != nil {
		return nil, err
	}
	var employees []pmEmployee
	if err := o.get(ctx, tenantID, "/pm/masters/employees", &employees); err != nil {
		return nil, err
	}
	c.tree = build(units, levels, employees, time.Now().UTC())
	return c.tree, nil
}

// get calls Portal Master as the service itself, in one tenant, allowed to read units, levels and employees only.
func (o *Org) get(ctx context.Context, tenantID, path string, into any) error {
	now := time.Now()
	tok, err := o.Keys.Sign(token.Claims{Issuer: o.Issuer, Audience: token.Audience, Subject: SystemUserID, SessionID: "service", TenantID: tenantID,
		IssuedAt: now.Unix(), Expires: now.Add(time.Minute).Unix(), Username: "svc-auth", Name: "Authentication", Role: "system",
		Grants: map[string][]string{"pm.orgUnit": {"read"}, "pm.orgLevel": {"read"}, "pm.employee": {"read"}}})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.PMURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := o.Client.Do(req)
	if err != nil {
		return fmt.Errorf("portal master: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("portal master %s: HTTP %d", path, res.StatusCode)
	}
	return json.NewDecoder(res.Body).Decode(into)
}
