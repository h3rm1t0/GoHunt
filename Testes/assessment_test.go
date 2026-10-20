package testes

import (
	"GoHunt/Configuracao"
	"GoHunt/Db"
	"GoHunt/Escopo"
	"GoHunt/Estado"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"GoHunt/Painel"
	"GoHunt/Tecnologias"
	"GoHunt/Vuln"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestAssessmentReviewLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.jsonl")
	store, err := estado.OpenStore(path, "fp", false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	r := modelo.Record{Kind: "cve-correlation", URL: "https://a.test/", Priority: 5, Evidence: map[string]string{"cve": "CVE-2026-75604", "assessment": "correlated"}}
	if err = store.Append(estado.Event{Records: []modelo.Record{r}}); err != nil {
		t.Fatal(err)
	}
	h := painel.Handler(path)
	get := func(query string) painel.PageResult {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1/api/results?"+query, nil))
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		var p painel.PageResult
		if json.Unmarshal(w.Body.Bytes(), &p) != nil {
			t.Fatal(w.Body.String())
		}
		return p
	}
	token := get("").CSRFToken
	id := modelo.RecordID(r)
	post := func(d, comment string, rev int) int {
		b, _ := json.Marshal(map[string]any{"id": id, "disposition": d, "comment": comment, "revision": rev})
		req := httptest.NewRequest("POST", "http://127.0.0.1/api/review", strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-GoHunt-Token", token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	if post("confirmed", "", 0) != 400 {
		t.Fatal("confirmation without evidence")
	}
	if post("discarded", "não atende plataforma Windows", 0) != 200 {
		t.Fatal("discard failed")
	}
	if get("assessment=discarded&review=all").Total != 1 || get("review=pending").Total != 0 {
		t.Fatal("discard filter")
	}
	h = painel.Handler(path)
	token = get("").CSRFToken
	if get("assessment=discarded&review=all").Items[0].Assessment != "discarded" {
		t.Fatal("state not persisted")
	}
	if post("confirmed", "impacto reproduzido com autorização", 0) != 409 {
		t.Fatal("stale write accepted")
	}
	if post("confirmed", "impacto reproduzido com autorização", 1) != 200 {
		t.Fatal("confirmation failed")
	}
	if get("assessment=manual-confirmed&review=all").Total != 1 {
		t.Fatal("confirmation filter")
	}
	if post("pending", "reabrindo investigação", 2) != 200 {
		t.Fatal("reopen failed")
	}
	p := get("assessment=possible&review=pending")
	if p.Total != 1 || p.Items[0].ID != id {
		t.Fatal("identity changed on review")
	}
	r.Assessment = "manual-confirmed"
	if modelo.RecordID(r) != id {
		t.Fatal("presentation changes identity")
	}
	for _, tc := range []struct{ k, s string }{{"technology", "observed"}, {"component", "observed"}, {"cve-verified", "reproduced"}, {"cve-inconclusive", "inconclusive"}} {
		if painel.AssessmentState(modelo.Record{Kind: tc.k}, modelo.ManualReview{}) != tc.s {
			t.Fatal(tc)
		}
	}
	if painel.AssessmentState(r, modelo.ManualReview{Verified: true}) != "possible" {
		t.Fatal("legacy reviewed was promoted to confirmed")
	}
}

func TestExpandedCatalogBranches(t *testing.T) {
	c, err := db.LoadCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Advisories) != 14 {
		t.Fatal(len(c.Advisories))
	}
	for _, a := range c.Advisories {
		for _, r := range a.VersionRanges() {
			if !a.Affects(r.Introduced) || a.Affects(r.Fixed) {
				t.Errorf("boundary %s %+v", a.ID, r)
			}
		}
	}
	for _, v := range []string{"1.30.6", "1.30.9", "1.31.7", "1.31.7-dev", "1.31", ""} {
		if c.ByID["CVE-2026-15176"].Affects(v) {
			t.Errorf("nginx false positive %s", v)
		}
	}
	if c.ByID["CVE-2026-56846"].Affects("26.0.0") {
		t.Fatal("unaffected Node branch")
	}
	if c.ByID["CVE-2026-75604"].Affects("15.5.24") {
		t.Fatal("patched Next")
	}
	_ = c.Candidates("nginx", "1.31.6")
	n := len(c.Cache)
	_ = c.Candidates("nginx", "1.31.6")
	if len(c.Cache) != n {
		t.Fatal("cache identity")
	}
}

func TestExplicitVerifiersAndConditions(t *testing.T) {
	for _, c := range []configuracao.Config{{CVEMode: "verify"}, {CVEMode: "passive", CVEVerifiers: "joomla-public-users-v1"}, {CVEMode: "verify", CVEVerifiers: "unknown"}} {
		if configuracao.ValidateVerifiers(c) == nil {
			t.Fatal(c)
		}
	}
	if err := configuracao.ValidateVerifiers(configuracao.Config{CVEMode: "verify", CVEVerifiers: "joomla-public-users-v1"}); err != nil {
		t.Fatal(err)
	}
	cat, _ := db.LoadCatalog("")
	e := &nucleo.Engine{Catalog: cat, Scope: &escopo.Scope{Exact: map[string]bool{"a.test": true}}, Config: configuracao.Config{CVEMode: "passive"}}
	c := modelo.Component{URL: "https://a.test/", Product: "nextjs", Version: "16.3.2", Evidence: "lockfile autorizado", SourceType: "inventory"}
	a := cat.ByID["CVE-2026-75604"]
	assess := func() modelo.Record {
		b, _ := json.Marshal(c)
		_, r, err := vuln.AssessCVE(e, context.Background(), modelo.Task{Kind: "cve", URL: c.URL, Source: a.ID, Path: string(b)})
		if err != nil {
			t.Fatal(err)
		}
		return r[0]
	}
	if painel.AssessmentState(assess(), modelo.ManualReview{}) != "possible" {
		t.Fatal("version treated as configuration")
	}
	c.Facts = map[string]modelo.ConditionEvidence{}
	for _, k := range a.Requires {
		c.Facts[k] = modelo.ConditionEvidence{Present: true, Evidence: "verificado no inventário autorizado"}
	}
	r := assess()
	if painel.AssessmentState(r, modelo.ManualReview{}) != "preconditions-met" || r.Priority != 5 {
		t.Fatal(r)
	}
	c.Facts[a.Requires[0]] = modelo.ConditionEvidence{Present: false, Evidence: "configuração ausente"}
	if painel.AssessmentState(assess(), modelo.ManualReview{}) != "possible" {
		t.Fatal("partial conditions accepted")
	}
}

func TestNodeNextVersionEvidence(t *testing.T) {
	cat, _ := db.LoadCatalog("")
	e := &nucleo.Engine{Catalog: cat, Config: configuracao.Config{CVEMode: "passive"}}
	for _, v := range []string{"Next.js", "Next.js/16.3", "Node.js", "Node.js/24.18.1-ubuntu1"} {
		tasks, _ := tecnologias.ObservedComponents(e, modelo.Task{URL: "https://a.test/"}, modelo.Response{Status: 200, Header: http.Header{"X-Powered-By": {v}}})
		if len(tasks) > 0 {
			t.Fatal("inferred version", v)
		}
	}
	for _, v := range []string{"Next.js/16.3.2", "Node.js/24.18.0"} {
		tasks, records := tecnologias.ObservedComponents(e, modelo.Task{URL: "https://a.test/"}, modelo.Response{Status: 200, Header: http.Header{"X-Powered-By": {v}}})
		if len(tasks) == 0 || records[0].Evidence["source_type"] != "http-header" {
			t.Fatal(fmt.Sprint(tasks, records))
		}
	}
}
