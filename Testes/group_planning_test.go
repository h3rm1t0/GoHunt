package testes

import (
	"GoHunt/Ativo"
	"GoHunt/Configuracao"
	"GoHunt/Escopo"
	"GoHunt/Estado"
	"GoHunt/Extractor"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"GoHunt/Painel"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeepMappingExpandsCandidateBudget(t *testing.T) {
	var body strings.Builder
	for i := 0; i < 80; i++ {
		fmt.Fprintf(&body, `<a href="/p%d">p</a>`, i)
	}
	e := &nucleo.Engine{Config: configuracao.Config{CrawlMode: "reduced", Depth: 1}, Scope: &escopo.Scope{Exact: map[string]bool{"a.test": true}}}
	small, _ := extractor.Extract(e, modelo.Task{URL: "https://a.test/"}, []byte(body.String()))
	e.Config.CrawlMode = "deep"
	e.Config.Depth = 5
	deep, _ := extractor.Extract(e, modelo.Task{URL: "https://a.test/"}, []byte(body.String()))
	if len(small) != 32 || len(deep) != 80 {
		t.Fatal(len(small), len(deep))
	}
}

func TestEntryGroupKeepsOccurrencesAndIndependentReviews(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	s, err := estado.OpenStore(path, "fp", false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a := modelo.Record{Kind: "form", URL: "https://a.test/search", Source: "https://a.test/one", Method: "GET", Priority: 3, Fields: []modelo.Field{{Name: "q", Type: "text"}}, Evidence: map[string]string{"observed_on": "https://a.test/one"}}
	b := a
	b.Source = "https://a.test/two"
	b.Evidence = map[string]string{"observed_on": b.Source}
	c := a
	c.Method = "POST"
	if modelo.RecordID(a) == modelo.RecordID(b) {
		t.Fatal("occurrence provenance lost")
	}
	if modelo.DisplayID(a) != modelo.DisplayID(b) || modelo.DisplayID(a) == modelo.DisplayID(c) {
		t.Fatal("invalid grouping")
	}
	if err = s.Append(estado.Event{Records: []modelo.Record{a, b, c}}); err != nil {
		t.Fatal(err)
	}
	if _, err = painel.SaveReview(path, modelo.RecordID(a), 0, modelo.ManualReview{Verified: true, Comment: "only one"}); err != nil {
		t.Fatal(err)
	}
	h := painel.Handler(path)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1/api/results", nil))
	var out painel.PageResult
	if err = json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 2 || out.Items[0].Group == nil || out.Items[0].Group.Count != 2 {
		t.Fatal(w.Body.String())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1/api/form-group?id="+modelo.DisplayID(a), nil))
	if err = json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 2 || out.Items[0].Review == nil || out.Items[1].Review != nil {
		t.Fatal(w.Body.String())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1/api/form-group?id="+modelo.DisplayID(a)+"&review=pending", nil))
	if err = json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 1 || out.Items[0].Source != b.Source {
		t.Fatal(w.Body.String())
	}
	d := a
	d.URL = "https://b.test/search"
	if modelo.DisplayID(a) == modelo.DisplayID(d) {
		t.Fatal("cross origin merged")
	}
}

func TestExtractionPreservesSharedActionSources(t *testing.T) {
	e := &nucleo.Engine{Scope: &escopo.Scope{Exact: map[string]bool{"a.test": true}}}
	_, one := extractor.Extract(e, modelo.Task{URL: "https://a.test/one"}, []byte(`<form action="/search"><input name="q"></form>`))
	_, two := extractor.Extract(e, modelo.Task{URL: "https://a.test/two"}, []byte(`<form action="/search"><input name="q"></form>`))
	if modelo.RecordID(one[0]) == modelo.RecordID(two[0]) || modelo.DisplayID(one[0]) != modelo.DisplayID(two[0]) {
		t.Fatal(one, two)
	}
}

func TestPageBudgetsResumeAndKeepUnscheduledParameters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	s, err := estado.OpenStore(path, "fp", false)
	if err != nil {
		t.Fatal(err)
	}
	e := &nucleo.Engine{Config: configuracao.Config{CrawlMode: "reduced", MaxPagesPerHost: 2}}
	tasks := []modelo.Task{{Kind: "page", URL: "https://a.test/info", Source: "link"}, {Kind: "page", URL: "https://a.test/search?q=a", Source: "link"}, {Kind: "page", URL: "https://a.test/search?q=b", Source: "link"}, {Kind: "page", URL: "https://a.test/api?rare=yes", Source: "link"}}
	planned, records := ativo.SchedulePages(e, s, tasks, nil)
	if len(planned) != 2 || !strings.Contains(planned[0].URL, "search") || !strings.Contains(planned[1].URL, "rare") {
		t.Fatal(planned)
	}
	if len(records) != 2 {
		t.Fatal(records)
	}
	if err = s.Commit(modelo.Task{Kind: "init"}, planned, records, 20); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = estado.OpenStore(path, "fp", true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	planned, records = ativo.SchedulePages(e, s, []modelo.Task{{Kind: "page", URL: "https://a.test/new?fresh=1"}}, nil)
	if len(planned) != 0 || len(records) != 1 || records[0].Fields[0].Name != "fresh" {
		t.Fatal(planned, records)
	}
}
