package db

import (
	origcatalog "GoHunt/Db/Dados"
	"GoHunt/Escopo"
	"GoHunt/Modelo"
	"GoHunt/Util"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Advisory struct {
	Ranges     []VersionRange `json:"ranges,omitempty"`
	Requires   []string       `json:"requires,omitempty"`
	ID         string         `json:"id"`
	Product    string         `json:"product"`
	Introduced string         `json:"introduced,omitempty"`
	Fixed      string         `json:"fixed,omitempty"`
	Reference  string         `json:"reference"`
	Conditions string         `json:"conditions"`
	Verifier   string         `json:"verifier,omitempty"`
}

type Catalog struct {
	Schema     int                   `json:"schema"`
	Reviewed   string                `json:"reviewed"`
	Advisories []Advisory            `json:"advisories"`
	ByProduct  map[string][]Advisory `json:"-"`
	ByID       map[string]Advisory   `json:"-"`
	Cache      map[string][]Advisory `json:"-"`
}

type VersionRange struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

func (a Advisory) Affects(v string) bool {
	if _, ok := VersionParts(v); !ok {
		return false
	}
	for _, r := range a.VersionRanges() {
		if VersionCompare(v, r.Introduced) >= 0 && VersionCompare(v, r.Fixed) < 0 {
			return true
		}
	}
	return false
}

func (c *Catalog) Candidates(product, version string) []Advisory {
	key := product + "\x00" + version
	if a, ok := c.Cache[key]; ok {
		return a
	}
	var a []Advisory
	for _, v := range c.ByProduct[product] {
		if v.Affects(version) {
			a = append(a, v)
		}
	}
	if c.Cache == nil {
		c.Cache = map[string][]Advisory{}
	}
	if len(c.Cache) >= 4096 {
		c.Cache = map[string][]Advisory{}
	}
	c.Cache[key] = a
	return a
}

func CanonicalProduct(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "node.js", "node", "nodejs":
		return "nodejs"
	case "next.js", "next", "nextjs":
		return "nextjs"
	case "apache", "apache http server", "apache-httpd":
		return "apache-httpd"
	default:
		return strings.ToLower(strings.TrimSpace(p))
	}
}

var CveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

func LoadCatalog(path string) (*Catalog, error) {
	c := &Catalog{}
	var err error
	if path == "" {
		err = util.StrictJSON(origcatalog.Advisories, c)
	} else {
		err = util.ReadBoundedJSON(path, c)
	}
	if err != nil {
		return nil, err
	}
	date, err := time.Parse("2006-01-02", c.Reviewed)
	if (c.Schema != 1 && c.Schema != 2) || err != nil || date.After(time.Now().Add(24*time.Hour)) || len(c.Advisories) > 10000 {
		return nil, fmt.Errorf("catálogo: schema/data/quantidade inválidos")
	}
	c.ByProduct = map[string][]Advisory{}
	c.ByID = map[string]Advisory{}
	for _, a := range c.Advisories {
		valid := true
		if len(a.Ranges) > 0 && (a.Introduced != "" || a.Fixed != "") {
			valid = false
		}
		for i, r := range a.VersionRanges() {
			_, lo := VersionParts(r.Introduced)
			_, hi := VersionParts(r.Fixed)
			if !lo || !hi || VersionCompare(r.Introduced, r.Fixed) >= 0 {
				valid = false
				break
			}
			if i > 0 && VersionCompare(a.Ranges[i-1].Fixed, r.Introduced) > 0 {
				valid = false
				break
			}
		}
		seenRequirements := map[string]bool{}
		for _, r := range a.Requires {
			if r == "" || seenRequirements[r] {
				valid = false
			}
			seenRequirements[r] = true
		}
		u, x := url.Parse(a.Reference)
		if !CveID.MatchString(a.ID) || a.Product == "" || a.Product != CanonicalProduct(a.Product) || strings.TrimSpace(a.Product) != a.Product || !valid || x != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || a.Conditions == "" || c.ByID[a.ID].ID != "" {
			return nil, fmt.Errorf("aviso inválido/duplicado: %s", a.ID)
		}
		if a.Verifier != "" && (a.Verifier != "joomla-public-users-v1" || a.ID != "CVE-2023-23752" || a.Product != "joomla" || a.Introduced != "4.0.0" || a.Fixed != "4.2.8") {
			return nil, fmt.Errorf("verificador não revisado: %s", a.Verifier)
		}
		c.ByProduct[a.Product] = append(c.ByProduct[a.Product], a)
		c.ByID[a.ID] = a
	}
	return c, nil
}

func LoadComponents(path string, scope *escopo.Scope) ([]modelo.Component, error) {
	if path == "" {
		return nil, nil
	}
	var cs []modelo.Component
	if err := util.ReadBoundedJSON(path, &cs); err != nil {
		return nil, err
	}
	if len(cs) > 10000 {
		return nil, fmt.Errorf("inventário excede 10000 componentes")
	}
	for i := range cs {
		c := &cs[i]
		c.Product = CanonicalProduct(c.Product)
		if c.Product == "" && c.Ecosystem == "npm" && c.Name == "next" {
			c.Product = "nextjs"
		}
		if c.SourceType != "" && c.SourceType != "inventory" {
			return nil, fmt.Errorf("source_type de inventário deve ser inventory")
		}
		c.SourceType = "inventory"
		for k, v := range c.Facts {
			if k == "" || strings.TrimSpace(v.Evidence) == "" || len(v.Evidence) > 2048 {
				return nil, fmt.Errorf("fato sem evidência válida")
			}
		}
		raw, err := escopo.Normalize(c.URL)
		if err != nil || !scope.Allows(raw) || c.Version == "" || len(c.Version) > 128 || c.Evidence == "" || len(c.Evidence) > 2048 || (c.Product == "" && (c.Name == "" || c.Ecosystem == "")) || ((c.Name == "") != (c.Ecosystem == "")) {
			return nil, fmt.Errorf("componente inválido/fora de escopo na posição %d", i)
		}
		u, _ := url.Parse(raw)
		if u.RawQuery != "" {
			return nil, fmt.Errorf("componente deve usar URL de instalação sem query")
		}
		if !strings.HasSuffix(u.Path, "/") {
			u.Path += "/"
		}
		c.URL = u.String()
	}
	return cs, nil
}

var numericVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func VersionCompare(a, b string) int {
	aa, _ := VersionParts(a)
	bb, _ := VersionParts(b)
	for i := range aa {
		if aa[i] < bb[i] {
			return -1
		}
		if aa[i] > bb[i] {
			return 1
		}
	}
	return 0
}

func VersionParts(v string) ([]int, bool) {
	if !numericVersion.MatchString(v) {
		return nil, false
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

func (a Advisory) VersionRanges() []VersionRange {
	if len(a.Ranges) > 0 {
		return a.Ranges
	}
	return []VersionRange{{a.Introduced, a.Fixed}}
}
