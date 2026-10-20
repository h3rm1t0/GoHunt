package testes

import (
	"GoHunt/Configuracao"
	"GoHunt/Db"
	"GoHunt/Escopo"
	"GoHunt/Estado"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"GoHunt/Tecnologias"
	"GoHunt/Vuln"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func (f advisoryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCVEDedupResumeAndPassive(t *testing.T) {
	cat, _ := db.LoadCatalog("")
	e := &nucleo.Engine{Catalog: cat, Scope: &escopo.Scope{Exact: map[string]bool{"a.test": true}}, Config: configuracao.Config{CVEMode: "passive"}}
	c := modelo.Component{URL: "https://a.test/", Product: "joomla", Version: "4.2.7", Evidence: "first"}
	task := vuln.ComponentTasks(e, c)[0]
	c.Evidence = "second"
	duplicate := vuln.ComponentTasks(e, c)[0]
	if task.ID() != duplicate.ID() {
		t.Fatal("same component queued twice")
	}
	_, records, err := vuln.AssessCVE(e, context.Background(), task)
	if err != nil || len(records) != 1 || records[0].Priority != 5 || records[0].Kind != "cve-correlation" {
		t.Fatal(records, err)
	}
	state := filepath.Join(t.TempDir(), "state.jsonl")
	s, err := estado.OpenStore(state, "test", false)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Commit(modelo.Task{Kind: "init"}, []modelo.Task{task, duplicate}, nil, 10); err != nil {
		t.Fatal(err)
	}
	if s.Count != 1 {
		t.Fatal(s.Count)
	}
	if err = s.Commit(task, nil, records, 10); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = estado.OpenStore(state, "test", true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !s.Done[task.ID()] || s.Count != 1 || s.RecordCount != 1 {
		t.Fatal("resume lost CVE completion")
	}
}

func TestCatalogVersionBoundaries(t *testing.T) {
	c, err := db.LoadCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	a := c.ByID["CVE-2023-23752"]
	for v, want := range map[string]bool{"4.0.0": true, "4.2.7": true, "4.2.8": false, "3.10.0": false, "4.2": false, "4.2.7-ubuntu1": false, "4.2.7-rc1": false, "04.2.7": false, "4.999999999999999999999999999999.0": false} {
		if a.Affects(v) != want {
			t.Errorf("%s", v)
		}
	}
	for _, mutate := range []func(*db.Catalog){func(c *db.Catalog) { c.Schema = 99 }, func(c *db.Catalog) { c.Advisories[0].Verifier = "arbitrary" }, func(c *db.Catalog) { c.Advisories[0].Fixed = "4.3.0" }, func(c *db.Catalog) { c.Advisories = append(c.Advisories, c.Advisories[0]) }, func(c *db.Catalog) { c.Advisories[0].Reference = "http://unsafe.test" }} {
		bad, _ := db.LoadCatalog("")
		mutate(bad)
		b, _ := json.Marshal(bad)
		p := filepath.Join(t.TempDir(), "catalog.json")
		os.WriteFile(p, b, 0600)
		if _, err := db.LoadCatalog(p); err == nil {
			t.Fatal("invalid catalog accepted")
		}
	}
}

func TestJoomlaVerificationControls(t *testing.T) {
	for _, scenario := range []string{"positive", "public-control", "generic", "html", "empty", "unstable", "final-open", "negative-login", "transport"} {
		t.Run(scenario, func(t *testing.T) {
			count, controls, repeats := 0, 0, 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count++
				if r.Method != "GET" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
					t.Error("unexpected authenticated/mutating request")
				}
				if !strings.HasPrefix(r.URL.Path, "/cms/api/index.php/v1/") {
					t.Error(r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/vnd.api+json")
				if scenario == "transport" {
					w.WriteHeader(503)
					return
				}
				if strings.Contains(r.URL.Path, "gohunt-missing-") {
					if scenario != "generic" {
						if scenario == "negative-login" {
							w.WriteHeader(401)
						} else {
							w.WriteHeader(404)
						}
						return
					}
				} else if r.URL.Query().Get("public") != "true" {
					controls++
					if scenario != "public-control" && !(scenario == "final-open" && controls > 1) {
						w.WriteHeader(401)
						return
					}
				} else {
					repeats++
				}
				if scenario == "html" {
					fmt.Fprint(w, "<html>login</html>")
					return
				}
				if scenario == "empty" {
					fmt.Fprint(w, `{"data":[]}`)
					return
				}
				id := "123"
				if scenario == "unstable" && repeats > 1 {
					id = "456"
				}
				fmt.Fprintf(w, `{"data":[{"type":"users","id":%q,"attributes":{"username":"private-user","email":"private@example.test"}}]}`, id)
			}))
			defer srv.Close()
			u, _ := url.Parse(srv.URL)
			cat, _ := db.LoadCatalog("")
			e := &nucleo.Engine{Catalog: cat, Scope: &escopo.Scope{Exact: map[string]bool{u.Hostname(): true}}, Client: srv.Client(), Config: configuracao.Config{CVEMode: "verify", CVEVerifiers: "joomla-public-users-v1", MaxBody: 1 << 20, Timeout: time.Second}}
			c := modelo.Component{URL: srv.URL + "/cms/", Product: "joomla", Version: "4.2.7", Evidence: "test"}
			b, _ := json.Marshal(c)
			_, records, err := vuln.AssessCVE(e, context.Background(), modelo.Task{Kind: "cve", URL: c.URL, Source: "CVE-2023-23752", Path: string(b)})
			if scenario == "transport" {
				if err == nil || len(records) != 0 {
					t.Fatal("transport failure became result")
				}
				return
			}
			if err != nil || len(records) != 1 {
				t.Fatal(records, err)
			}
			if (records[0].Kind == "cve-verified") != (scenario == "positive") {
				t.Fatalf("unexpected result: %+v", records)
			}
			serialized, _ := json.Marshal(records)
			if strings.Contains(string(serialized), "private-user") || strings.Contains(string(serialized), "private@example") {
				t.Fatal("personal data persisted")
			}
			if count > 5 {
				t.Fatal("request budget exceeded", count)
			}
		})
	}
}

func TestOSVExactAndUnsupported(t *testing.T) {
	c := modelo.Component{Name: "test", Ecosystem: "npm", Version: "1.2.3"}
	fixtures := []struct {
		body string
		want bool
	}{
		{`{"id":"GHSA-test","affected":[{"package":{"name":"test","ecosystem":"npm"},"versions":["1.2.3"]}]}`, true},
		{`{"id":"GHSA-test","withdrawn":"2020-01-01","affected":[{"package":{"name":"test","ecosystem":"npm"},"versions":["1.2.3"]}]}`, false},
		{`{"id":"GHSA-test","affected":[{"package":{"name":"test","ecosystem":"PyPI"},"versions":["1.2.3"]}]}`, false},
		{`{"id":"GHSA-test","affected":[{"package":{"name":"test","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.4"}]}]}]}`, true},
		{`{"id":"GHSA-test","affected":[{"package":{"name":"test","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]}`, false},
		{`{"id":"GHSA-test","affected":[{"package":{"name":"test","ecosystem":"npm"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`, false},
		{`{"id":"GHSA-test","affected":[{"package":{"name":"test","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"unknown":"2.0.0"}]}]}]}`, false},
	}
	for _, f := range fixtures {
		var a modelo.OsvAdvisory
		if err := json.Unmarshal([]byte(f.body), &a); err != nil {
			t.Fatal(err)
		}
		if vuln.OsvAffects(a, c) != f.want {
			t.Error(f.body)
		}
	}
}

func TestOSVIncompleteNeverCached(t *testing.T) {
	e := &nucleo.Engine{Config: configuracao.Config{MaxBody: 1 << 20}, Client: &http.Client{Transport: advisoryTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"next_page_token":"repeat"}`))}, nil
	})}}
	_, _, err := vuln.QueryOSV(e, context.Background(), modelo.Component{Name: "test", Ecosystem: "npm", Version: "1.2.3"})
	if err == nil || len(e.OSVCache) != 0 {
		t.Fatal("partial response accepted")
	}
}

func TestOSVPaginationCacheAndPrivacy(t *testing.T) {
	calls := 0
	e := &nucleo.Engine{Config: configuracao.Config{OSV: true, MaxBody: 1 << 20, State: filepath.Join(t.TempDir(), "state.jsonl")}, Scope: &escopo.Scope{Exact: map[string]bool{"private.test": true}}}
	e.Client = &http.Client{Transport: advisoryTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "private.test") || r.URL.Host != "api.osv.dev" {
			t.Fatal("target leaked")
		}
		body := `{"vulns":[{"id":"GHSA-test","aliases":["CVE-2020-12345","CVE-2020-12345"],"affected":[{"package":{"name":"test","ecosystem":"npm"},"versions":["1.2.3"]}]}]}`
		if calls == 1 {
			body = `{"next_page_token":"second"}`
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	c := modelo.Component{URL: "https://private.test/", Name: "test", Ecosystem: "npm", Version: "1.2.3", Evidence: "inventory"}
	b, _ := json.Marshal(c)
	task := modelo.Task{Kind: "osv", URL: c.URL, Path: string(b)}
	_, records, err := vuln.AssessOSV(e, context.Background(), task)
	if err != nil || len(records) != 2 || calls != 2 {
		t.Fatal(records, err, calls)
	}
	e.OSVCache = nil // A resumed process reuses the on-disk cache.
	_, records, err = vuln.AssessOSV(e, context.Background(), task)
	if err != nil || len(records) != 2 || calls != 2 {
		t.Fatal("cache miss", err, calls)
	}
}

func TestObservedVersionSignals(t *testing.T) {
	cat, _ := db.LoadCatalog("")
	cat.ByProduct["apache-httpd"] = cat.ByProduct["apache-httpd"][:2]
	e := &nucleo.Engine{Catalog: cat, Config: configuracao.Config{CVEMode: "passive"}}
	for _, test := range []struct {
		server, body string
		want         int
	}{
		{"Apache/2.4.49", "", 2}, {"Apache/2.4.51", "", 0}, {"Apache/2.4.49-ubuntu1", "", 0},
		{"", "Apache/2.4.49", 0}, {"", `<meta name="generator" content="Joomla! 4.2.7">`, 1},
		{"", `<meta name="generator" content="Joomla!">`, 0},
	} {
		tasks, _ := tecnologias.ObservedComponents(e, modelo.Task{URL: "https://a.test/cms/index.php"}, modelo.Response{Status: 200, Header: http.Header{"Server": {test.server}, "Content-Type": {"text/html"}}, Body: []byte(test.body)})
		if len(tasks) != test.want {
			t.Fatalf("%+v: %+v", test, tasks)
		}
		if len(tasks) == 1 && tasks[0].URL != "https://a.test/cms/" {
			t.Fatal(tasks)
		}
	}
}

type advisoryTransport func(*http.Request) (*http.Response, error)
