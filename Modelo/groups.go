package modelo

import (
	"GoHunt/Escopo"
	"GoHunt/Util"
	"encoding/json"
	"sort"
	"strings"
)

type EntryGroup struct {
	ID    string `json:"id"`
	Count int    `json:"count"`
}

func DisplayID(r Record) string {
	if !IsEntry(r) {
		return RecordID(r)
	}
	fields := append([]Field(nil), r.Fields...)
	sort.Slice(fields, func(i, j int) bool {
		a, _ := json.Marshal(fields[i])
		b, _ := json.Marshal(fields[j])
		return string(a) < string(b)
	})
	signature := struct {
		Kind, Origin, Method, Enctype, Scope string
		Fields                               []Field
	}{r.Kind, escopo.Origin(r.URL), strings.ToUpper(util.DefaultValue(r.Method, "GET")), util.DefaultValue(r.Evidence["enctype"], "application/x-www-form-urlencoded"), r.Evidence["in_scope"], fields}
	b, _ := json.Marshal(signature)
	return util.Digest("entry-group:" + string(b))
}

func IsEntry(r Record) bool { return r.Kind == "form" || r.Kind == "inputs" }
