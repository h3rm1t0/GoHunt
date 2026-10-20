package testes

import (
	"GoHunt/Aplicacao"
	"GoHunt/Ativo"
	"GoHunt/Configuracao"
	"GoHunt/Escopo"
	"GoHunt/Estado"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"GoHunt/Passivo"
	"GoHunt/Tecnologias"
	"GoHunt/Vuln"
	origvuln "GoHunt/Vuln/Templates"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func (f refinementTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestEquivalentBypassProofDedup(t *testing.T) {
	a := modelo.Record{Kind: "bypass-candidate", URL: "https://a.test/private", Evidence: map[string]string{"candidate_sha256": "same-proof", "original_status": "403", "candidate_url": "https://a.test/private/"}, Source: "path"}
	b := a
	b.Source = "X-Test"
	b.Evidence = map[string]string{"candidate_sha256": "same-proof", "original_status": "403", "candidate_url": a.URL}
	if modelo.RecordID(a) != modelo.RecordID(b) {
		t.Fatal("equivalent proof duplicated")
	}
	b.Evidence["candidate_sha256"] = "different-proof"
	if modelo.RecordID(a) == modelo.RecordID(b) {
		t.Fatal("distinct proof lost")
	}
}

func TestHistoricalQueuePreservesParameterSets(t *testing.T) {
	s, err := estado.OpenStore(filepath.Join(t.TempDir(), "s.jsonl"), "fp", false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tasks := []modelo.Task{{Kind: "page", Source: "wayback", URL: "https://a.test/p?id=1"}, {Kind: "page", Source: "commoncrawl", URL: "https://a.test/p?id=2"}, {Kind: "page", Source: "wayback", URL: "https://a.test/p?id=3&next=x"}, {Kind: "page", Source: "wayback", URL: "https://a.test/p?id=1&id=2"}, {Kind: "page", Source: "link", URL: "https://a.test/p?id=4"}}
	if err = s.Commit(modelo.Task{Kind: "init"}, tasks, nil, 20); err != nil {
		t.Fatal(err)
	}
	if len(s.Tasks) != 4 {
		t.Fatal(s.Tasks)
	}
}

func TestHistoricalValidationFiltersFallbackButKeepsParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<html>Same application shell</html>")
	}))
	defer server.Close()
	e := testEngine(server)
	tasks, records, err := ativo.Page(e, context.Background(), modelo.Task{Kind: "page", Source: "wayback", URL: server.URL + "/old?id=7"})
	if err != nil {
		t.Fatal(err)
	}
	_ = tasks
	if len(records) == 0 || records[0].Kind != "filtered" || !strings.Contains(records[0].Evidence["validation"], "dois controles") {
		t.Fatal(records)
	}
}

func TestHistorySuppressesPriorFindingsKeepsCurrentInventory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<form action="/search"><input name="q"></form>`)
	}))
	defer server.Close()
	dir := t.TempDir()
	scope := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scope, []byte(server.URL), 0600); err != nil {
		t.Fatal(err)
	}
	c := configuracao.Config{Scope: scope, State: filepath.Join(dir, "first.jsonl"), MaxTasks: 20, MaxBody: 1024, Timeout: time.Second}
	if err := aplicacao.Run(context.Background(), c, io.Discard); err != nil {
		t.Fatal(err)
	}
	c.History = c.State
	c.State = filepath.Join(dir, "second.jsonl")
	if err := aplicacao.Run(context.Background(), c, io.Discard); err != nil {
		t.Fatal(err)
	}
	forms, endpoints := 0, 0
	if err := estado.WalkRecords(c.State, func(r modelo.Record) {
		if r.Kind == "form" {
			forms++
		}
		if r.Kind == "endpoint" {
			endpoints++
		}
	}); err != nil {
		t.Fatal(err)
	}
	if forms != 0 || endpoints != 1 {
		t.Fatal(forms, endpoints)
	}
}

func TestPersistentRecordDedupPreservesDistinctEvidence(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state.jsonl")
	s, err := estado.OpenStore(file, "fp", false)
	if err != nil {
		t.Fatal(err)
	}
	r := modelo.Record{Kind: "endpoint", URL: "https://a.test/?b=2&a=1", Priority: 4, Evidence: map[string]string{"body_sha256": "one"}}
	if err = s.Append(estado.Event{Records: []modelo.Record{r, r}}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = estado.OpenStore(file, "fp", true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r.URL = "https://a.test/?a=1&b=2"
	r.Source = "wayback"
	r.ObservedAt = "later"
	if err = s.Append(estado.Event{Records: []modelo.Record{r}}); err != nil {
		t.Fatal(err)
	}
	if s.RecordCount != 1 {
		t.Fatal(s.RecordCount)
	}
	r.Evidence = map[string]string{"body_sha256": "two"}
	if err = s.Append(estado.Event{Records: []modelo.Record{r}}); err != nil {
		t.Fatal(err)
	}
	if s.RecordCount != 2 {
		t.Fatal("different evidence removed")
	}
}

func TestReadOldJournalDeduplicates(t *testing.T) {
	file := filepath.Join(t.TempDir(), "old.jsonl")
	r := modelo.Record{Kind: "form", URL: "https://a.test/search", Priority: 3, Method: "GET", Fields: []modelo.Field{{Name: "q", Type: "text"}}}
	line, _ := json.Marshal(estado.Event{Records: []modelo.Record{r, r}})
	if err := os.WriteFile(file, append(line, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	n := 0
	if err := estado.WalkRecords(file, func(modelo.Record) { n++ }); err != nil || n != 1 {
		t.Fatal(n, err)
	}
}

func TestTechnologyOnDeniedResponseDoesNotExposeCookies(t *testing.T) {
	e := &nucleo.Engine{}
	records, names := tecnologias.TechnologyRecords(e, modelo.Task{URL: "https://a.test/private"}, modelo.Response{Status: 403, Header: http.Header{"Server": {"nginx/1.2"}, "Set-Cookie": {"PHPSESSID=secret-value; Path=/"}, "Content-Type": {"text/html"}}, Body: []byte(`<script src="/_next/static/a.js"></script>`)})
	text, _ := json.Marshal(records)
	if strings.Contains(string(text), "secret-value") {
		t.Fatal("cookie leaked")
	}
	for _, n := range []string{"nginx", "PHP", "Next.js"} {
		if !strings.Contains(strings.Join(names, ","), n) {
			t.Fatal(names)
		}
	}
}

func TestTemplateRequiresStableProofAndRejectsGenericBody(t *testing.T) {
	for _, mode := range []string{"stable", "transient", "fallback"} {
		t.Run(mode, func(t *testing.T) {
			hits := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/proof" {
					w.WriteHeader(404)
					if mode == "fallback" {
						io.WriteString(w, "UNIQUE_PROOF alpha beta gamma")
					} else {
						io.WriteString(w, "missing")
					}
					return
				}
				hits++
				if mode == "transient" && hits > 1 {
					io.WriteString(w, "ordinary page")
					return
				}
				io.WriteString(w, "UNIQUE_PROOF alpha beta gamma")
			}))
			defer server.Close()
			e := testEngine(server)
			tpl := origvuln.Arsenal_vulns{ID: "fixture", Validacao: origvuln.ValidacaoPrecisa{OperadorGlobal: "AND", Regras: []origvuln.RegraMatcher{{Tipo: "word", Alvo: "body", Condicao: "AND", Valores: []string{"UNIQUE_PROOF"}}}}}
			tpl.Requisicao.Metodo = "GET"
			e.Templates = []origvuln.Arsenal_vulns{tpl}
			_, records, err := vuln.Template(e, context.Background(), modelo.Task{URL: server.URL + "/", Path: "/proof"})
			if err != nil {
				t.Fatal(err)
			}
			if (len(records) > 0) != (mode == "stable") {
				t.Fatal(mode, records)
			}
		})
	}
}

func TestWaybackParameterInventory(t *testing.T) {
	e := &nucleo.Engine{Config: configuracao.Config{SourceLimit: 10, MaxBody: 1 << 20}, Scope: &escopo.Scope{Exact: map[string]bool{"a.test": true}}}
	e.Client = &http.Client{Transport: refinementTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`[["original"],["https://a.test/p?id=1"],["https://a.test/p?id=2"],["https://a.test/p?id=1&next=x"],["https://a.test/p?rare=x"]]`))}, nil
	})}
	tasks, records, err := passivo.Source(e, context.Background(), modelo.Task{Kind: "source", Source: "wayback", URL: "a.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 3 {
		t.Fatal(tasks)
	}
	found := false
	for _, r := range records {
		if r.Evidence["parameter_names"] == "id" {
			found = true
			var samples []string
			if err = json.Unmarshal([]byte(r.Evidence["sample_urls"]), &samples); err != nil || len(samples) != 2 {
				t.Fatal(r)
			}
		}
	}
	if !found {
		t.Fatal(records)
	}
}

type refinementTransport func(*http.Request) (*http.Response, error)
