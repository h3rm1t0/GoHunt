package tecnologias

import (
	"GoHunt/Db"
	"GoHunt/Escopo"
	"GoHunt/Extractor"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"bytes"
	"encoding/json"
	"golang.org/x/net/html"
	"net/http"
	"sort"
	"strings"
)

func generators(r modelo.Response) []string {
	if !strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "html") {
		return nil
	}
	doc, err := html.Parse(bytes.NewReader(r.Body))
	if err != nil {
		return nil
	}
	var out []string
	extractor.Visit(doc, func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "meta" && strings.EqualFold(extractor.Attr(n, "name"), "generator") {
			v := extractor.Attr(n, "content")
			if len(v) <= 256 {
				out = append(out, v)
			}
		}
	})
	return out
}

func TechnologyRecords(e *nucleo.Engine, t modelo.Task, r modelo.Response) ([]modelo.Record, []string) {
	signals := map[string][]string{}
	add := func(n, s string) {
		if n != "" {
			signals[n] = append(signals[n], s)
		}
	}
	if e.Wapp != nil {
		for n := range e.Wapp.Fingerprint(r.Header, r.Body) {
			add(n, "assinatura Wappalyzer em cabeçalhos/corpo")
		}
	}
	for _, k := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"} {
		if v := r.Header.Get(k); v != "" {
			n := strings.TrimSpace(strings.Split(v, "/")[0])
			if strings.HasPrefix(k, "X-AspNet") {
				n = "ASP.NET"
			}
			add(n, k+": "+v)
		}
	}
	response := http.Response{Header: r.Header}
	for _, c := range response.Cookies() {
		switch strings.ToLower(c.Name) {
		case "phpsessid":
			add("PHP", "nome de cookie PHPSESSID")
		case "jsessionid":
			add("Java Servlet", "nome de cookie JSESSIONID")
		case "asp.net_sessionid":
			add("ASP.NET", "nome de cookie ASP.NET_SessionId")
		}
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "html") {
		doc, err := html.Parse(bytes.NewReader(r.Body))
		if err == nil {
			extractor.Visit(doc, func(n *html.Node) {
				if n.Type != html.ElementNode {
					return
				}
				if n.Data == "meta" && strings.EqualFold(extractor.Attr(n, "name"), "generator") {
					v := extractor.Attr(n, "content")
					if len(v) > 256 {
						v = v[:256]
					}
					add(v, "meta generator")
				}
				if n.Data == "script" {
					src := extractor.Attr(n, "src")
					if strings.Contains(src, "/_next/") || extractor.Attr(n, "id") == "__NEXT_DATA__" {
						add("Next.js", "script /_next/ ou __NEXT_DATA__")
					}
					if strings.Contains(src, "/_nuxt/") || extractor.Attr(n, "id") == "__NUXT_DATA__" {
						add("Nuxt", "script /_nuxt/ ou __NUXT_DATA__")
					}
				}
			})
		}
	}
	names := make([]string, 0, len(signals))
	for n := range signals {
		names = append(names, n)
	}
	sort.Strings(names)
	var records []modelo.Record
	for _, n := range names {
		sort.Strings(signals[n])
		data, _ := json.Marshal(signals[n])
		records = append(records, modelo.Record{Kind: "technology", URL: escopo.Origin(t.URL), Priority: 5, Summary: "Tecnologia indicada por sinais observáveis: " + n, Evidence: map[string]string{"product": db.CanonicalProduct(n), "version_status": "desconhecida", "source_type": "fingerprint", "assessment": "observed", "technology": n, "signals": string(data), "confidence": "indício; cabeçalhos e marcas podem ser alterados"}})
	}
	return records, names
}
