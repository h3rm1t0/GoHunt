package vuln

import (
	"GoHunt/Db"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"GoHunt/Rede"
	"GoHunt/Util"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func AssessOSV(e *nucleo.Engine, ctx context.Context, t modelo.Task) ([]modelo.Task, []modelo.Record, error) {
	if !e.Config.OSV {
		return nil, nil, fmt.Errorf("OSV desativado")
	}
	var c modelo.Component
	if err := json.Unmarshal([]byte(t.Path), &c); err != nil {
		return nil, nil, err
	}
	if c.URL != t.URL || !e.Scope.Allows(c.URL) || c.Name == "" || c.Ecosystem == "" || c.Version == "" {
		return nil, nil, fmt.Errorf("identidade de componente inválida")
	}
	advisories, fetched, err := QueryOSV(e, ctx, c)
	if err != nil {
		return nil, nil, err
	}
	var records []modelo.Record
	seen := map[string]bool{}
	unresolved := 0
	for _, a := range advisories {
		if a.Withdrawn != "" {
			continue
		}
		if !OsvAffects(a, c) {
			unresolved++
			continue
		}
		ids := []string{}
		for _, alias := range a.Aliases {
			if db.CveID.MatchString(alias) {
				ids = append(ids, alias)
			}
		}
		if db.CveID.MatchString(a.ID) {
			ids = append(ids, a.ID)
		}
		if len(ids) == 0 {
			ids = []string{a.ID}
		}
		sort.Strings(ids)
		for _, id := range ids {
			if seen[id] {
				continue
			}
			seen[id] = true
			records = append(records, modelo.Record{Kind: "cve-correlation", URL: c.URL, Priority: 5, Source: id, Summary: id + ": dependência na faixa afetada; alcance e impacto não verificados", Evidence: map[string]string{"advisory": id, "osv_id": a.ID, "package": c.Name, "ecosystem": c.Ecosystem, "version": c.Version, "signal": c.Evidence, "assessment": "correlated", "reference": "https://osv.dev/vulnerability/" + a.ID, "modified": a.Modified, "database_checked": fetched.Format(time.RFC3339), "validation": "identidade exata e versão explícita ou faixa SEMVER numérica; sem prova de exploração"}})
		}
	}
	records = append(records, modelo.Record{Kind: "cve-coverage", URL: c.URL, Priority: 5, Summary: "Consulta OSV concluída; ausência de correlação não comprova ausência de vulnerabilidades", Evidence: map[string]string{"package": c.Name, "ecosystem": c.Ecosystem, "version": c.Version, "correlations": fmt.Sprint(len(seen)), "unsupported_or_unmatched": fmt.Sprint(unresolved), "assessment": "inventory-checked", "database_checked": fetched.Format(time.RFC3339), "aliases": strings.Join(sortedKeys(seen), ", ")}})
	return nil, records, nil
}

func atomicCache(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".advisories-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// Confirm exact package and explicit versions or the supported numeric SEMVER
// subset locally. Fuzzy API matches and unsupported range semantics fail closed.
func OsvAffects(a modelo.OsvAdvisory, c modelo.Component) bool {
	if a.Withdrawn != "" || a.ID == "" {
		return false
	}
	for _, af := range a.Affected {
		if af.Package.Name != c.Name || af.Package.Ecosystem != c.Ecosystem {
			continue
		}
		for _, v := range af.Versions {
			if v == c.Version {
				return true
			}
		}
		if _, ok := db.VersionParts(c.Version); !ok {
			continue
		}
		for _, r := range af.Ranges {
			if r.Type != "SEMVER" || len(r.Events) == 0 {
				continue
			}
			active, valid := false, true
			intervalOpen := false
			last := ""
			for _, event := range r.Events {
				if len(event) != 1 {
					valid = false
					break
				}
				for kind, v := range event {
					if kind == "introduced" {
						if intervalOpen {
							valid = false
							break
						}
						intervalOpen = true
					} else {
						if !intervalOpen {
							valid = false
							break
						}
						intervalOpen = false
					}
					if kind != "introduced" && kind != "fixed" && kind != "last_affected" && kind != "limit" {
						valid = false
						break
					}
					if v != "0" {
						if _, ok := db.VersionParts(v); !ok {
							valid = false
							break
						}
					} else if kind != "introduced" {
						valid = false
						break
					}
					if last != "" && v != "0" && db.VersionCompare(v, last) < 0 {
						valid = false
						break
					}
					if v != "0" {
						last = v
					}
					switch kind {
					case "introduced":
						if v == "0" || db.VersionCompare(c.Version, v) >= 0 {
							active = true
						}
					case "fixed", "limit":
						if db.VersionCompare(c.Version, v) >= 0 {
							active = false
						}
					case "last_affected":
						if db.VersionCompare(c.Version, v) > 0 {
							active = false
						}
					}
				}
				if !valid {
					break
				}
			}
			if valid && active {
				return true
			}
		}
	}
	return false
}

type osvPage struct {
	Vulns []modelo.OsvAdvisory `json:"vulns"`
	Next  string               `json:"next_page_token"`
}

func QueryOSV(e *nucleo.Engine, ctx context.Context, c modelo.Component) ([]modelo.OsvAdvisory, time.Time, error) {
	key := util.Digest(c.Ecosystem + "\x00" + c.Name + "\x00" + c.Version)
	if e.OSVCache == nil {
		e.OSVCache = modelo.OsvCache{}
		if e.Config.State != "" {
			f, err := os.Open(e.Config.State + ".advisories.json")
			if err == nil {
				b, x := io.ReadAll(io.LimitReader(f, (8<<20)+1))
				f.Close()
				if x == nil && len(b) <= 8<<20 {
					_ = json.Unmarshal(b, &e.OSVCache)
				}
			}
		}
		if e.OSVCache == nil {
			e.OSVCache = modelo.OsvCache{}
		}
	}
	if cached, ok := e.OSVCache[key]; ok && time.Since(cached.Fetched) >= 0 && time.Since(cached.Fetched) < 24*time.Hour {
		return cached.Vulns, cached.Fetched, nil
	}
	var all []modelo.OsvAdvisory
	token := ""
	seen := map[string]bool{}
	for page := 0; page < 5; page++ {
		body, _ := json.Marshal(map[string]any{"package": modelo.OsvPackage{Name: c.Name, Ecosystem: c.Ecosystem}, "version": c.Version, "page_token": token})
		response, err := rede.RequestOnce(e, ctx, "https://api.osv.dev/v1/query", "POST", map[string]string{"Content-Type": "application/json"}, string(body), true)
		if err != nil {
			return nil, time.Time{}, err
		}
		if response.Status != 200 {
			return nil, time.Time{}, fmt.Errorf("OSV HTTP %d; consulta pendente", response.Status)
		}
		var data osvPage
		if err = json.Unmarshal(response.Body, &data); err != nil {
			return nil, time.Time{}, err
		}
		all = append(all, data.Vulns...)
		if len(all) > 5000 {
			return nil, time.Time{}, fmt.Errorf("OSV: resposta excede limite de 5000 avisos")
		}
		if data.Next == "" {
			now := time.Now().UTC()
			e.OSVCache[key] = modelo.OsvCacheEntry{Fetched: now, Vulns: all}
			var cacheBytes []byte
			for {
				cacheBytes, _ = json.Marshal(e.OSVCache)
				if len(e.OSVCache) <= 128 && len(cacheBytes) <= 8<<20 {
					break
				}
				oldest := ""
				for k, v := range e.OSVCache {
					if oldest == "" || v.Fetched.Before(e.OSVCache[oldest].Fetched) {
						oldest = k
					}
				}
				delete(e.OSVCache, oldest)
			}
			if e.Config.State != "" {
				if err = atomicCache(e.Config.State+".advisories.json", cacheBytes); err != nil {
					return nil, time.Time{}, err
				}
			}

			return all, now, nil
		}
		if seen[data.Next] {
			return nil, time.Time{}, fmt.Errorf("OSV repetiu token de paginação")
		}
		seen[data.Next] = true
		token = data.Next
	}
	return nil, time.Time{}, fmt.Errorf("OSV excedeu 5 páginas; consulta incompleta permanece pendente")
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
