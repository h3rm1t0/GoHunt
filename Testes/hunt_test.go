package testes

import (
	"GoHunt/Aplicacao"
	"GoHunt/Ativo"
	"GoHunt/Bypass"
	"GoHunt/Configuracao"
	"GoHunt/Escopo"
	"GoHunt/Estado"
	"GoHunt/Extractor"
	"GoHunt/Fuzzing"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"GoHunt/Painel"
	"GoHunt/Passivo"
	"GoHunt/Rede"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func (f resolverFunc) LookupHost(ctx context.Context, host string) ([]string, error) {
	return f(ctx, host)
}

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestBypassFilters(t *testing.T) {
	for _, mode := range []string{"candidate", "redirect", "login", "home", "soft404", "same-denial", "unstable", "empty"} {
		t.Run(mode, func(t *testing.T) {
			var candidates atomic.Int32
			private := "private project records and account configuration for administrators"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/admin" {
					if r.Header.Get("X-Forwarded-For") == "" {
						w.WriteHeader(403)
						io.WriteString(w, "forbidden original denial")
						return
					}
					candidates.Add(1)
					switch mode {
					case "redirect":
						http.Redirect(w, r, "/login", 302)
					case "login":
						io.WriteString(w, `<input type="password">`)
					case "home":
						io.WriteString(w, "public landing page welcome visitors")
					case "same-denial":
						io.WriteString(w, "forbidden original denial")
					case "empty":
					case "unstable":
						if candidates.Load() > 1 {
							io.WriteString(w, "different transient view")
						} else {
							io.WriteString(w, private)
						}
					default:
						io.WriteString(w, private)
					}
					return
				}
				if r.URL.Path == "/" {
					io.WriteString(w, "public landing page welcome visitors")
					return
				}
				if mode == "soft404" {
					io.WriteString(w, private)
					return
				}
				w.WriteHeader(404)
				io.WriteString(w, "not found")
			}))
			defer server.Close()
			e := testEngine(server)
			_, records, err := bypass.Bypass(e, context.Background(), modelo.Task{Kind: "bypass", URL: server.URL + "/admin", Path: server.URL + "/admin", Source: "X-Forwarded-For"})
			if err != nil {
				t.Fatal(err)
			}
			if (len(records) == 1) != (mode == "candidate") {
				t.Fatalf("records=%v", records)
			}
		})
	}
}

func TestCancellationResumePendingHTTP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) == 1 {
			cancel()
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "ok")
	}))
	defer server.Close()
	dir := t.TempDir()
	scope := filepath.Join(dir, "scope")
	os.WriteFile(scope, []byte(server.URL), 0600)
	c := configuracao.Config{Scope: scope, State: filepath.Join(dir, "state.jsonl"), Timeout: time.Second, MaxBody: 1024, Depth: 1, MaxTasks: 10, SourceLimit: 10}
	if err := aplicacao.Run(ctx, c, io.Discard); err == nil {
		t.Fatal("canceled scan succeeded")
	}
	c.Resume = true
	if err := aplicacao.Run(context.Background(), c, io.Discard); err != nil {
		t.Fatal(err)
	}
	records := 0
	estado.WalkRecords(c.State, func(r modelo.Record) {
		if r.Kind == "endpoint" {
			records++
		}
	})
	if records != 1 || count.Load() != 2 {
		t.Fatalf("records=%d hits=%d", records, count.Load())
	}
}

func TestCorruptCompleteLineFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.jsonl")
	os.WriteFile(path, []byte("broken\n"), 0600)
	if _, err := estado.OpenStore(path, "fp", true); err == nil {
		t.Fatal("corruption ignored")
	}
}

func TestDNSWildcardSuppression(t *testing.T) {
	e := &nucleo.Engine{Config: configuracao.Config{Timeout: time.Second}, Scope: &escopo.Scope{Exact: map[string]bool{}, Wild: []string{"example.com"}}, Resolver: resolverFunc(func(context.Context, string) ([]string, error) { return []string{"192.0.2.1"}, nil })}
	tasks, records, err := passivo.Dns(e, context.Background(), modelo.Task{Kind: "dns", URL: "api.example.com", Source: "example.com"})
	if err != nil || len(tasks) != 0 || len(records) != 1 || !strings.Contains(records[0].Summary, "wildcard") {
		t.Fatalf("%v %v %v", tasks, records, err)
	}
}

func TestDashboardPriorityPaginationAndXSS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.jsonl")
	s, err := estado.OpenStore(path, "fp", false)
	if err != nil {
		t.Fatal(err)
	}
	s.Append(estado.Event{Records: []modelo.Record{{Kind: "endpoint", Priority: 4, URL: "https://example.com/"}, {Kind: "bypass-candidate", Priority: 2, URL: "https://example.com/admin", Summary: "<script>alert(1)</script>"}, {Kind: "template-candidate", Priority: 1, URL: "https://example.com/api"}}})
	s.Close()
	handler := painel.Handler(path)
	request := httptest.NewRequest("GET", "http://127.0.0.1/api/results?offset=1&limit=1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, request)
	var page painel.PageResult
	if err = json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 3 || len(page.Items) != 1 || page.Items[0].Priority != 2 {
		t.Fatal(page)
	}
	if strings.Contains(rec.Body.String(), "<script>") {
		t.Fatal("unescaped JSON")
	}
	for raw, want := range map[string]int{"http://127.0.0.1/api/results?limit=1000": 400, "http://evil.test/api/results": 403, "http://127.0.0.1/api/results?kind=form": 200} {
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("GET", raw, nil))
		if rec.Code != want {
			t.Fatalf("%s status=%d", raw, rec.Code)
		}
	}
}

func TestEndToEndResumeDoesNotRepeatCompletedRequests(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			io.WriteString(w, `<a href="/next">next</a><form method="POST" action="/update"><input name="item"></form>`)
		} else {
			io.WriteString(w, "done")
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	scope := filepath.Join(dir, "scope")
	os.WriteFile(scope, []byte(server.URL), 0600)
	config := configuracao.Config{Scope: scope, State: filepath.Join(dir, "state.jsonl"), Timeout: time.Second, MaxBody: 1 << 20, MaxTasks: 100, Depth: 2, SourceLimit: 100}
	if err := aplicacao.Run(context.Background(), config, io.Discard); err != nil {
		t.Fatal(err)
	}
	before := hits.Load()
	config.Resume = true
	if err := aplicacao.Run(context.Background(), config, io.Discard); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != before {
		t.Fatal("completed requests repeated")
	}
	count := 0
	estado.WalkRecords(config.State, func(r modelo.Record) {
		if r.Kind == "form" {
			count++
		}
	})
	if count != 1 {
		t.Fatalf("forms=%d", count)
	}
}

func TestExtractFormsAndScope(t *testing.T) {
	e := &nucleo.Engine{Config: configuracao.Config{Depth: 3, FormGET: true}, Scope: &escopo.Scope{Exact: map[string]bool{"example.com": true}}, Forms: map[string]string{"q": "security"}}
	body := []byte(`<a href="/next">next</a><a href="https://evil.test/">external</a><form id="search" action="/find" method="get"><input name="q" required><textarea name="note"></textarea></form><select form="search" name="choice"></select><form action="/change" method="post"><input name="q"></form><form action="/login"><input name="password" type="password"><input name="q"></form><input name="jsInput">`)
	tasks, records := extractor.Extract(e, modelo.Task{Kind: "page", URL: "https://example.com/"}, body)
	found := false
	for _, task := range tasks {
		if strings.Contains(task.URL, "evil.test") || strings.Contains(task.URL, "change") || strings.Contains(task.URL, "login") {
			t.Fatalf("unexpected request %s", task.URL)
		}
		if task.URL == "https://example.com/find?q=security" {
			found = true
		}
	}
	if !found {
		t.Fatal("GET form not explored")
	}
	if len(records) != 4 {
		t.Fatalf("records=%d", len(records))
	}
	if len(records[0].Fields) != 3 {
		t.Fatal("associated controls missing")
	}
	e.Config.FormGET = false
	tasks, _ = extractor.Extract(e, modelo.Task{URL: "https://example.com/"}, body)
	for _, task := range tasks {
		if task.Source == "form-get" {
			t.Fatal("GET submitted without opt-in")
		}
	}
}

func TestInvalidFlagsDoNotStartScan(t *testing.T) {
	for _, args := range [][]string{{"--jitter-min", "2s", "--jitter-max", "1s"}, {"--jitter-min", "-1s"}, {"--max-body", "0"}, {"--sources", "unknown"}, {"--depth", "-1"}} {
		if err := aplicacao.CLI(context.Background(), args, io.Discard); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	if err := aplicacao.CLI(context.Background(), []string{"--help"}, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestJitterAndBodyLimit(t *testing.T) {
	e := &nucleo.Engine{Config: configuracao.Config{JitterMin: time.Hour, JitterMax: time.Hour}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if rede.Pace(e, ctx) == nil || time.Since(start) > time.Second {
		t.Fatal("jitter not canceled")
	}
	e.Config.JitterMin = 0
	e.Config.JitterMax = 0
	if rede.Pace(e, context.Background()) != nil {
		t.Fatal("zero jitter failed")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, strings.Repeat("x", 2048)) }))
	defer server.Close()
	e = testEngine(server)
	e.Config.MaxBody = 1024
	if _, err := rede.Request(e, context.Background(), server.URL, "GET", nil, "", false); err == nil {
		t.Fatal("oversized body accepted")
	}
}

func TestNoOffScopeRedirect(t *testing.T) {
	var hits atomic.Int32
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer outside.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://localhost:"+strings.Split(outside.URL, ":")[2], 302)
	}))
	defer server.Close()
	e := testEngine(server)
	tasks, _, err := ativo.Page(e, context.Background(), modelo.Task{URL: server.URL + "/"})
	if err != nil || len(tasks) != 0 || hits.Load() != 0 {
		t.Fatalf("redirect followed: %v %v %d", err, tasks, hits.Load())
	}
}

func TestProviderFailureAndCooldown(t *testing.T) {
	attempts := 0
	e := &nucleo.Engine{Config: configuracao.Config{MaxBody: 1024}, Client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": []string{"300"}}, Body: io.NopCloser(strings.NewReader("rate limited"))}, nil
	})}}
	if _, err := rede.Request(e, context.Background(), "https://example.com", "GET", nil, "", true); err == nil {
		t.Fatal("rate limit treated as success")
	}
	if attempts != 1 {
		t.Fatal("long provider cooldown ignored")
	}
}

func TestPublicSourcesParseAndFilter(t *testing.T) {
	payloads := map[string]string{
		"crtsh":       `[{"name_value":"api.example.com\n*.example.com\nevil-example.com"}]`,
		"otx":         `{"passive_dns":[{"hostname":"api.example.com"},{"hostname":"evil-example.com"}]}`,
		"wayback":     `[["original"],["https://api.example.com/CaseSensitive?Token=ABC"],["https://evil.test/"]]`,
		"commoncrawl": "{\"url\":\"https://api.example.com/CaseSensitive?Token=ABC\"}\n{\"url\":\"https://evil.test/\"}\n",
	}
	for source, payload := range payloads {
		t.Run(source, func(t *testing.T) {
			e := &nucleo.Engine{Config: configuracao.Config{MaxBody: 1 << 20, SourceLimit: 100}, Scope: &escopo.Scope{Exact: map[string]bool{}, Wild: []string{"example.com"}}}
			e.Client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body := payload
				if r.URL.Path == "/collinfo.json" {
					body = `[{"cdx-api":"https://index.commoncrawl.org/CC-MAIN-TEST-index"}]`
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			tasks, records, err := passivo.Source(e, context.Background(), modelo.Task{Kind: "source", URL: "example.com", Source: source})
			if err != nil {
				t.Fatal(err)
			}
			if len(tasks) != 1 || len(records) != 2 {
				t.Fatalf("tasks=%v records=%v", tasks, records)
			}
			if (source == "wayback" || source == "commoncrawl") && !strings.Contains(tasks[0].URL, "CaseSensitive?Token=ABC") {
				t.Fatal("URL case changed")
			}
		})
	}
}

func TestScopeBoundaries(t *testing.T) {
	s := &escopo.Scope{Exact: map[string]bool{"example.com": true}, Wild: []string{"allowed.test"}}
	for raw, want := range map[string]bool{"https://example.com/": true, "http://example.com:8080/a": true, "https://child.allowed.test/": true, "https://notallowed.test/": false, "https://allowed.test/": false, "https://example.com.evil.test/": false, "https://example.com@evil.test/": false, "javascript:alert(1)": false} {
		if got := s.Allows(raw); got != want {
			t.Errorf("%s: %v != %v", raw, got, want)
		}
	}
}

func TestSoft404BruteFiltered(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "common fallback document 123456") }))
	defer server.Close()
	e := testEngine(server)
	tasks, records, err := fuzzing.Brute(e, context.Background(), modelo.Task{URL: server.URL + "/missing", Source: "file"})
	if err != nil || len(tasks) != 0 || len(records) != 1 || records[0].Kind != "filtered" {
		t.Fatalf("%v %v %v", tasks, records, err)
	}
}

func TestStoreResumeTornTailAndLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.jsonl")
	s, err := estado.OpenStore(path, "fingerprint", false)
	if err != nil {
		t.Fatal(err)
	}
	pending := modelo.Task{Kind: "page", URL: "https://example.com/"}
	if err = s.Commit(modelo.Task{Kind: "init"}, []modelo.Task{pending}, nil, 10); err != nil {
		t.Fatal(err)
	}
	if _, err = estado.OpenStore(path, "fingerprint", true); err == nil {
		t.Fatal("concurrent writer accepted")
	}
	s.Close()
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString(`{"done":`)
	f.Close()
	s, err = estado.OpenStore(path, "fingerprint", true)
	if err != nil {
		t.Fatal(err)
	}
	if s.Done[pending.ID()] || len(s.Tasks) != 1 {
		t.Fatal("pending task lost")
	}
	if err = s.Commit(pending, nil, []modelo.Record{{Kind: "endpoint", URL: pending.URL, Priority: 4}}, 10); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = estado.OpenStore(path, "fingerprint", true)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Done[pending.ID()] {
		t.Fatal("completion lost")
	}
	s.Close()
	if _, err = estado.OpenStore(path, "different", true); err == nil {
		t.Fatal("incompatible resume accepted")
	}
	count := 0
	if err = estado.WalkRecords(path, func(modelo.Record) { count++ }); err != nil || count != 1 {
		t.Fatalf("records=%d err=%v", count, err)
	}
}

func TestTaskLimitPreservesParent(t *testing.T) {
	s, err := estado.OpenStore(filepath.Join(t.TempDir(), "state.jsonl"), "fp", false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	parent := modelo.Task{Kind: "page", URL: "https://a.test/"}
	if err = s.Commit(modelo.Task{Kind: "init"}, []modelo.Task{parent}, nil, 1); err != nil {
		t.Fatal(err)
	}
	if err = s.Commit(parent, []modelo.Task{{Kind: "page", URL: "https://b.test/"}}, nil, 1); err == nil {
		t.Fatal("limit not enforced")
	}
	if s.Done[parent.ID()] {
		t.Fatal("parent wrongly marked done")
	}
}

func TestWordlistResumeAndDedupe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "words")
	os.WriteFile(path, []byte("# comment\nadmin\nconfig.json"), 0600)
	e := &nucleo.Engine{Scope: &escopo.Scope{Exact: map[string]bool{"example.com": true}}}
	task := modelo.Task{Kind: "wordlist", URL: "https://example.com/", Source: "file", Path: path}
	next, _, err := fuzzing.Wordlist(e, task)
	if err != nil || len(next) != 2 {
		t.Fatalf("%v %v", next, err)
	}
	if next[1].URL != "https://example.com/admin" {
		t.Fatal(next)
	}
	last, _, err := fuzzing.Wordlist(e, next[0])
	if err != nil || len(last) != 1 || last[0].URL != "https://example.com/config.json" {
		t.Fatalf("%v %v", last, err)
	}
	if (modelo.Task{Kind: "page", URL: "https://example.com/", Source: "link", Depth: 3}).ID() != (modelo.Task{Kind: "page", URL: "https://example.com/", Source: "archive"}).ID() {
		t.Fatal("URL not deduped")
	}
}

type resolverFunc func(context.Context, string) ([]string, error)

type roundTripFunc func(*http.Request) (*http.Response, error)

func testEngine(server *httptest.Server) *nucleo.Engine {
	u, _ := url.Parse(server.URL)
	return &nucleo.Engine{Config: configuracao.Config{Timeout: time.Second, MaxBody: 1 << 20, Depth: 3}, Scope: &escopo.Scope{Exact: map[string]bool{u.Hostname(): true}}, Client: &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, Forms: map[string]string{}}
}
