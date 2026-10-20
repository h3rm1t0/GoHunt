package extractor

import (
	"GoHunt/Diffing"
	"GoHunt/Escopo"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"GoHunt/Util"
	"bytes"
	"fmt"
	"golang.org/x/net/html"
	"net/url"
	"sort"
	"strings"
)

func Attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func Extract(e *nucleo.Engine, t modelo.Task, body []byte) ([]modelo.Task, []modelo.Record) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, []modelo.Record{{Kind: "error", URL: t.URL, Priority: 5, Summary: err.Error()}}
	}
	base, _ := url.Parse(t.URL)
	page := *base
	baseSeen := false
	Visit(doc, func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "base" && !baseSeen {
			if r, err := url.Parse(Attr(n, "href")); err == nil {
				base = base.ResolveReference(r)
				baseSeen = true
			}
		}
	})
	var tasks []modelo.Task
	var records []modelo.Record
	seen := map[string]bool{}
	enqueue := func(raw, source string) {
		if t.Depth >= e.Config.Depth {
			return
		}
		ref, err := url.Parse(raw)
		if err != nil {
			return
		}
		dest, err := escopo.Normalize(base.ResolveReference(ref).String())
		if err == nil && e.Scope.Allows(dest) && !seen[dest] {
			tasks = append(tasks, modelo.Task{Kind: "page", URL: dest, Depth: t.Depth + 1, Source: source})
			seen[dest] = true
		}
	}
	type form struct {
		Node    *html.Node
		Fields  []modelo.Field
		Blocked bool
	}
	var forms []*form
	byNode := map[*html.Node]*form{}
	byID := map[string]*form{}
	Visit(doc, func(n *html.Node) {
		if n.Type != html.ElementNode {
			return
		}
		if n.Data == "form" && len(forms) < 128 {
			f := &form{Node: n}
			forms = append(forms, f)
			byNode[n] = f
			if id := Attr(n, "id"); id != "" {
				byID[id] = f
			}
		}
	})
	var unowned []modelo.Field
	truncatedFields := false
	Visit(doc, func(n *html.Node) {
		if n.Type != html.ElementNode {
			return
		}
		switch n.Data {
		case "a", "area", "link":
			if raw := Attr(n, "href"); raw != "" {
				enqueue(raw, "link")
			}
		case "script", "iframe":
			if raw := Attr(n, "src"); raw != "" {
				enqueue(raw, "resource")
			}
		}
		if n.Data != "input" && n.Data != "textarea" && n.Data != "select" && n.Data != "button" {
			return
		}
		typ := strings.ToLower(Attr(n, "type"))
		if typ == "" {
			typ = n.Data
			if typ == "input" {
				typ = "text"
			}
		}
		field := modelo.Field{Name: Attr(n, "name"), Type: typ, Required: hasAttr(n, "required")}
		var owner *form
		if id := Attr(n, "form"); id != "" {
			owner = byID[id]
		} else {
			for parent := n.Parent; parent != nil; parent = parent.Parent {
				if byNode[parent] != nil {
					owner = byNode[parent]
					break
				}
			}
		}
		if owner != nil {
			if len(owner.Fields) < 256 {
				owner.Fields = append(owner.Fields, field)
			} else {
				truncatedFields = true
			}
			if typ == "password" || typ == "file" {
				owner.Blocked = true
			}
		} else if len(unowned) < 256 {
			unowned = append(unowned, field)
		}
	})
	for _, f := range forms {
		method := strings.ToUpper(Attr(f.Node, "method"))
		if method == "" {
			method = "GET"
		}
		raw := Attr(f.Node, "action")
		dest := page.String()
		if raw != "" {
			ref, err := url.Parse(raw)
			if err != nil {
				continue
			}
			dest = base.ResolveReference(ref).String()
		}
		canonical, err := escopo.Normalize(dest)
		if err != nil {
			continue
		}
		r := modelo.Record{Kind: "form", URL: canonical, Priority: 3, Summary: "Formulário: ponto de entrada para revisão", Source: t.URL, Method: method, Fields: f.Fields, Evidence: map[string]string{"in_scope": fmt.Sprint(e.Scope.Allows(canonical)), "observed_on": t.URL, "enctype": strings.ToLower(util.DefaultValue(Attr(f.Node, "enctype"), "application/x-www-form-urlencoded"))}}
		records = append(records, r)
		if !e.Config.FormGET || method != "GET" || f.Blocked || !e.Scope.Allows(canonical) {
			continue
		}
		u, _ := url.Parse(canonical)
		query := url.Values{}
		provided := false
		missing := false
		for _, field := range f.Fields {
			if field.Name == "" || field.Type == "submit" || field.Type == "button" || field.Type == "reset" {
				continue
			}
			value, ok := e.Forms[field.Name]
			if field.Required && !ok {
				missing = true
			}
			if ok {
				provided = true
				query.Add(field.Name, value)
			}
		}
		if provided && !missing {
			u.RawQuery = query.Encode()
			enqueue(u.String(), "form-get")
		}
	}
	if len(unowned) > 0 {
		records = append(records, modelo.Record{Kind: "inputs", URL: t.URL, Priority: 3, Summary: "Campos fora de formulários (inclusive interfaces JavaScript)", Fields: unowned})
	}
	if truncatedFields || len(tasks) >= e.Config.LinkBudget() || len(forms) >= 128 || len(unowned) >= 256 {
		records = append(records, modelo.Record{Kind: "limit", URL: t.URL, Priority: 5, Summary: "Limite de extração por página atingido; revisar manualmente"})
	}
	sort.SliceStable(tasks, func(i, j int) bool { return diffing.EndpointRank(tasks[i].URL) > diffing.EndpointRank(tasks[j].URL) })
	if len(tasks) > e.Config.LinkBudget() {
		for _, skipped := range tasks[e.Config.LinkBudget():] {
			records = append(records, modelo.UnmappedRecord(skipped, "limite de links por página"))
		}
		tasks = tasks[:e.Config.LinkBudget()]
	}
	return tasks, records
}

func hasAttr(n *html.Node, key string) bool {
	for _, a := range n.Attr {
		if a.Key == key {
			return true
		}
	}
	return false
}

func Visit(n *html.Node, fn func(*html.Node)) {
	fn(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		Visit(c, fn)
	}
}
