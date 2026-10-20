package modelo

import (
	"GoHunt/Util"
	"encoding/json"
	"net/url"
	"sort"
)

func Historical(t Task) bool {
	return t.Kind == "page" && (t.Source == "wayback" || t.Source == "commoncrawl")
}

func RecordID(r Record) string {
	r.ObservedAt = ""
	r.ID = ""
	r.Review = nil
	r.Group = nil
	r.Assessment = ""
	if r.Kind == "cve-verified" {
		return util.Digest(r.Kind + "\x00" + r.URL + "\x00" + r.Evidence["cve"] + "\x00" + r.Evidence["verifier"])
	}
	if r.Kind == "bypass-candidate" && r.Evidence["candidate_sha256"] != "" {
		return util.Digest(r.Kind + "\x00" + r.URL + "\x00" + r.Evidence["original_status"] + "\x00" + r.Evidence["candidate_sha256"])
	}
	// Findings from separate templates/mutations and distinct evidence stay separate.
	if r.Kind != "source" && r.Kind != "template-candidate" && r.Kind != "bypass-candidate" && r.Kind != "error" {
		r.Source = ""
	}
	if u, err := url.Parse(r.URL); err == nil {
		if q, err := url.ParseQuery(u.RawQuery); err == nil {
			u.RawQuery = q.Encode()
			r.URL = u.String()
		}
	}
	r.Fields = append([]Field(nil), r.Fields...)
	sort.Slice(r.Fields, func(i, j int) bool {
		a, _ := json.Marshal(r.Fields[i])
		b, _ := json.Marshal(r.Fields[j])
		return string(a) < string(b)
	})
	b, _ := json.Marshal(r)
	return util.Digest(string(b))
}
