package painel

import (
	"GoHunt/Escopo"
	"GoHunt/Estado"
	"GoHunt/Modelo"
	"GoHunt/Util"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

func surfaceHandler(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		host := strings.ToLower(q.Get("host"))
		search := strings.ToLower(q.Get("q"))
		offset, _ := strconv.Atoi(q.Get("offset"))
		if offset < 0 || offset > 10000000 || len(search) > 512 || len(host) > 253 {
			http.Error(w, "filtro inválido", 400)
			return
		}
		hosts := map[string]int{}
		nodes := map[string]*SurfaceNode{}
		truncated := false
		err := estado.WalkRecords(path, func(rec modelo.Record) {
			h := escopo.RecordHost(rec.URL)
			if h == "" {
				return
			}
			haystack := rec.URL + " " + rec.Summary + " " + rec.Evidence["parameter_names"] + " " + rec.Evidence["technology"]
			for _, f := range rec.Fields {
				haystack += " " + f.Name
			}
			if search != "" && !strings.Contains(strings.ToLower(haystack), search) {
				return
			}
			hosts[h]++
			if host == "" || h != host {
				return
			}
			n := nodes[rec.URL]
			if n == nil {
				if len(nodes) >= 150 {
					truncated = true
					return
				}
				n = &SurfaceNode{URL: rec.URL, Priority: rec.Priority, Parameters: []string{}, Technologies: []string{}, Relations: []surfaceRelation{}}
				nodes[rec.URL] = n
			}
			if rec.Priority < n.Priority {
				n.Priority = rec.Priority
			}
			if u, e := url.Parse(rec.URL); e == nil {
				for k := range u.Query() {
					n.Parameters = util.AddUnique(n.Parameters, k)
				}
			}
			for _, f := range rec.Fields {
				n.Parameters = util.AddUnique(n.Parameters, f.Name)
			}
			for _, t := range strings.Split(rec.Evidence["technologies"], ", ") {
				n.Technologies = util.AddUnique(n.Technologies, t)
			}
			n.Technologies = util.AddUnique(n.Technologies, rec.Evidence["technology"])
			relation := func(kind, target string) {
				if target == "" {
					return
				}
				x := surfaceRelation{kind, target}
				for _, existing := range n.Relations {
					if existing == x {
						return
					}
				}
				n.Relations = append(n.Relations, x)
			}
			if u, e := url.Parse(rec.Source); e == nil && (u.Scheme == "http" || u.Scheme == "https") {
				relation("descoberta em", rec.Source)
			}
			relation("redireciona para", rec.Evidence["redirect"])
			relation("CNAME / destino DNS", rec.Evidence["dns_destination"])
			relation("cadeia CNAME", rec.Evidence["cname_chain"])
			relation("IPs do destino", rec.Evidence["destination_ips"])
			relation("provedor indicado", rec.Evidence["provider"])
		})
		if err != nil {
			http.Error(w, "Não foi possível ler a superfície", 500)
			return
		}
		hs := []surfaceHost{}
		for h, n := range hosts {

			hs = append(hs, surfaceHost{h, n})
		}
		sort.Slice(hs, func(i, j int) bool { return hs[i].Host < hs[j].Host })
		total := len(hs)
		if offset > total {
			offset = total
		}
		end := offset + 100
		if end > total {
			end = total
		}
		hs = hs[offset:end]
		ns := []*SurfaceNode{}
		for _, n := range nodes {
			sort.Strings(n.Parameters)
			sort.Strings(n.Technologies)
			ns = append(ns, n)
		}
		sort.Slice(ns, func(i, j int) bool {
			if ns[i].Priority != ns[j].Priority {
				return ns[i].Priority < ns[j].Priority
			}
			return ns[i].URL < ns[j].URL
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"hosts": hs, "total_hosts": total, "offset": offset, "nodes": ns, "truncated": truncated, "host": host})
	}
}

type surfaceHost struct {
	Host    string `json:"host"`
	Records int    `json:"records"`
}

type SurfaceNode struct {
	URL          string            `json:"url"`
	Parameters   []string          `json:"parameters"`
	Technologies []string          `json:"technologies"`
	Relations    []surfaceRelation `json:"relations"`
	Priority     int               `json:"priority"`
}

type surfaceRelation struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}
