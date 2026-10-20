package modelo

import (
	"net/url"
	"sort"
)

func UnmappedRecord(t Task, reason string) Record {
	r := Record{Kind: "discovery", URL: t.URL, Source: t.Source, Priority: 5, Summary: "Referência preservada sem mapeamento HTTP: " + reason, Evidence: map[string]string{"mapping": "not-scheduled", "reason": reason}}
	if u, err := url.Parse(t.URL); err == nil {
		names := []string{}
		for name := range u.Query() {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			r.Fields = append(r.Fields, Field{Name: name, Type: "query"})
		}
	}
	return r
}
