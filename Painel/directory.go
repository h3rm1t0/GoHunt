package painel

import (
	"GoHunt/Escopo"
	"GoHunt/Estado"
	"GoHunt/Modelo"
	"GoHunt/Util"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

func directoryHandler(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		host := strings.ToLower(q.Get("host"))
		prefix := q.Get("path")
		search := strings.ToLower(q.Get("q"))
		offset, err := strconv.Atoi(util.DefaultValue(q.Get("offset"), "0"))
		if err != nil || offset < 0 || offset > 10000000 || len(host) > 253 || len(prefix) > 16384 || len(search) > 512 || (prefix != "" && !strings.HasPrefix(prefix, "/")) || (host == "" && prefix != "") {
			http.Error(w, "filtro da árvore inválido", 400)
			return
		}
		nodes := map[string]*DirectoryNode{}
		err = estado.WalkRecords(path, func(rec modelo.Record) {
			if rec.Evidence["in_scope"] == "false" {
				return
			}
			u, h, isURL := directoryURL(rec.URL)
			if !isURL {
				if escopo.ValidHost(rec.URL) {
					h = strings.ToLower(strings.TrimSuffix(rec.URL, "."))
				} else {
					return
				}
			}
			if host != "" && h != host {
				return
			}
			// Search matches the URL; ancestors of matching paths are retained.
			if search != "" && !strings.Contains(strings.ToLower(rec.URL), search) {
				return
			}
			key, name := "", ""
			observed, children := false, false
			if host == "" {
				key = h
				name = h
				children = isURL
			} else {
				if !isURL {
					return
				}
				p := u.EscapedPath()
				// /a and /a/ share a display node, with both concrete URLs preserved.
				route := strings.TrimSuffix(p, "/")
				if route == "" {
					route = "/"
				}
				if prefix == "" {
					key = "/"
					name = "/"
					observed = route == "/"
					children = route != "/"
				} else {
					base := prefix + "/"
					if prefix == "/" {
						base = "/"
					}
					if !strings.HasPrefix(route, base) || route == prefix {
						return
					}
					rest := strings.TrimPrefix(route, base)
					trimmed := strings.TrimLeft(rest, "/")
					leading := rest[:len(rest)-len(trimmed)]
					segment, _, found := strings.Cut(trimmed, "/")
					segment = leading + segment
					key = base + segment
					name = segment
					if name == "" {
						name = "(segmento vazio)"
					}
					observed = !found
					children = found
				}
			}
			n := nodes[key]
			if n == nil {
				n = &DirectoryNode{Name: name, Host: h, Path: key, URLs: []string{}, Parameters: []string{}, Statuses: []string{}}
				nodes[key] = n
			}
			n.Children = n.Children || children
			n.Observed = n.Observed || observed
			if host != "" && observed {
				for k := range u.Query() {
					n.Parameters = util.AddUnique(n.Parameters, k)
				}
				for _, k := range strings.Split(rec.Evidence["parameter_names"], ", ") {
					n.Parameters = util.AddUnique(n.Parameters, k)
				}
				for _, f := range rec.Fields {
					n.Parameters = util.AddUnique(n.Parameters, f.Name)
				}
				u.RawQuery = ""
				u.ForceQuery = false
				n.URLs = util.AddUnique(n.URLs, u.String())
				if rec.Status > 0 {
					n.Statuses = util.AddUnique(n.Statuses, strconv.Itoa(rec.Status))
				}
			}
		})
		if err != nil {
			http.Error(w, "Não foi possível ler a árvore de caminhos", 500)
			return
		}
		keys := make([]string, 0, len(nodes))
		for k := range nodes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		total := len(keys)
		if offset > total {
			offset = total
		}
		end := offset + 100
		if end > total {
			end = total
		}
		result := DirectoryPage{Items: []*DirectoryNode{}, Total: total, Offset: offset, Limit: 100}
		for _, key := range keys[offset:end] {
			n := nodes[key]
			sort.Strings(n.URLs)
			sort.Strings(n.Parameters)
			sort.Strings(n.Statuses)
			result.Items = append(result.Items, n)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

// The tree describes URL paths, not a claim about the server's filesystem.
// Queries/fragments never create branches. Escaped separators and case remain distinct.
type DirectoryNode struct {
	Name       string   `json:"name"`
	Host       string   `json:"host"`
	Path       string   `json:"path"`
	Children   bool     `json:"children"`
	Observed   bool     `json:"observed"`
	URLs       []string `json:"urls"`
	Parameters []string `json:"parameters"`
	Statuses   []string `json:"statuses"`
}

type DirectoryPage struct {
	Items  []*DirectoryNode `json:"items"`
	Total  int              `json:"total"`
	Offset int              `json:"offset"`
	Limit  int              `json:"limit"`
}

func directoryURL(raw string) (*url.URL, string, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return nil, "", false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	port := u.Port()
	if port != "" && !(u.Scheme == "https" && port == "443") && !(u.Scheme == "http" && port == "80") {
		authority = net.JoinHostPort(host, port)
	}
	u.Host = authority
	// Normalize percent-escape hex case without decoding encoded slashes.
	escaped := u.EscapedPath()
	if escaped == "" {
		escaped = "/"
	}
	b := []byte(escaped)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			for j := i + 1; j <= i+2; j++ {
				if b[j] >= 'a' && b[j] <= 'f' {
					b[j] -= 32
				}
			}
			i += 2
		}
	}
	u.RawPath = string(b)
	u.Path, _ = url.PathUnescape(u.RawPath)
	u.Fragment = ""
	u.RawFragment = ""
	return u, host, true
}
