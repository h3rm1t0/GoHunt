package modelo

import (
	"GoHunt/Util"
	"encoding/json"
)

type Field struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required,omitempty"`
}

func (t Task) ID() string { // A discovered URL is visited only once, independent of provenance/depth.
	if t.Kind == "cve" || t.Kind == "osv" {
		var c Component
		if json.Unmarshal([]byte(t.Path), &c) == nil {
			return util.Digest(t.Kind + "\x00" + t.URL + "\x00" + t.Source + "\x00" + c.Product + "\x00" + c.Ecosystem + "\x00" + c.Name + "\x00" + c.Version)
		}
	}
	if t.Kind == "page" {
		return util.Digest("page:" + t.URL)
	}
	b, _ := json.Marshal(t)
	return util.Digest(string(b))
}

type Record struct {
	Assessment string            `json:"assessment,omitempty"`
	Group      *EntryGroup       `json:"group,omitempty"`
	ID         string            `json:"id,omitempty"`
	Review     *ManualReview     `json:"review,omitempty"`
	ObservedAt string            `json:"observed_at,omitempty"`
	Kind       string            `json:"kind"`
	URL        string            `json:"url"`
	Priority   int               `json:"priority"`
	Summary    string            `json:"summary"`
	Source     string            `json:"source,omitempty"`
	Status     int               `json:"status,omitempty"`
	Method     string            `json:"method,omitempty"`
	Fields     []Field           `json:"fields,omitempty"`
	Evidence   map[string]string `json:"evidence,omitempty"`
}

type Task struct {
	Kind   string `json:"kind"`
	URL    string `json:"url"`
	Source string `json:"source,omitempty"`
	Depth  int    `json:"depth,omitempty"`
	Offset int64  `json:"offset,omitempty"`
	Path   string `json:"path,omitempty"`
}
