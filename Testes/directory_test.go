package testes

import (
	"GoHunt/Estado"
	"GoHunt/Modelo"
	"GoHunt/Painel"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDirectoryTreeDedupAndHierarchy(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state")
	s, err := estado.OpenStore(file, "fp", false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	records := []modelo.Record{
		{URL: "https://A.test:443/api/users?id=1#one", Status: 200},
		{URL: "https://a.test/api/users?id=2#two", Status: 403},
		{URL: "http://a.test:80/api/users?id=3", Fields: []modelo.Field{{Name: "token"}}},
		{URL: "https://a.test/api/users/?page=2", Evidence: map[string]string{"parameter_names": "page, sort"}},
		{URL: "https://a.test:8443/api/users"},
		{URL: "https://a.test/api/users/42"},
		{URL: "https://a.test/api/users"}, // repeated event must not duplicate nodes
		{URL: "https://a.test/api/user%2fid"},
		{URL: "https://a.test/api/user%2Fid"},
		{URL: "https://a.test/api/Users"},
		{URL: "https://a.test/api//empty/child"},
		{URL: "https://a.test//double/child"},
		{URL: "sub.a.test", Kind: "dns"},
		{URL: "https://other.test/form", Evidence: map[string]string{"in_scope": "false"}},
		{URL: "https://user:password@secret.test/"},
		{URL: "javascript:alert(1)"},
	}
	for i := range records {
		records[i].Priority = 5
	}
	if err = s.Append(estado.Event{Records: records}); err != nil {
		t.Fatal(err)
	}
	get := func(host, path, search string) painel.DirectoryPage {
		t.Helper()
		w := httptest.NewRecorder()
		q := url.Values{"host": {host}, "path": {path}, "q": {search}}
		painel.Handler(file).ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1/api/directory-tree?"+q.Encode(), nil))
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		var result painel.DirectoryPage
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	hosts := get("", "", "")
	if hosts.Total != 2 || hosts.Items[0].Host != "a.test" || hosts.Items[1].Children {
		t.Fatalf("hosts: %+v", hosts)
	}
	root := get("a.test", "", "")
	if len(root.Items) != 1 || root.Items[0].Observed || !root.Items[0].Children {
		t.Fatal(root)
	}
	api := get("a.test", "/api", "")
	if api.Total != 4 {
		t.Fatalf("nodes: %+v", api)
	}
	var users *painel.DirectoryNode
	for _, n := range api.Items {
		if n.Name == "users" {
			users = n
		}
	}
	if users == nil || !users.Observed || !users.Children || len(users.URLs) != 4 {
		t.Fatalf("users: %+v", users)
	}
	if !reflect.DeepEqual(users.Parameters, []string{"id", "page", "sort", "token"}) || !reflect.DeepEqual(users.Statuses, []string{"200", "403"}) {
		t.Fatalf("details: %+v", users)
	}
	children := get("a.test", "/api/users", "")
	if children.Total != 1 || children.Items[0].Name != "42" {
		t.Fatal(children)
	}
	double := get("a.test", "/", "double")
	if double.Total != 1 || double.Items[0].Path != "//double" {
		t.Fatal(double)
	}
	if leaf := get("a.test", "//double", ""); leaf.Total != 1 || leaf.Items[0].Name != "child" {
		t.Fatal(leaf)
	}
	if got := get("a.test", "/api", "id=2"); got.Total != 1 || got.Items[0].Name != "users" {
		t.Fatal(got)
	}
	if got := get("other.test", "", ""); got.Total != 0 {
		t.Fatal(got)
	}
}

func TestDirectoryTreePaginationAndValidation(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state")
	s, err := estado.OpenStore(file, "fp", false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var records []modelo.Record
	for i := 0; i < 205; i++ {
		records = append(records, modelo.Record{URL: fmt.Sprintf("https://a.test/path-%03d?q=1", i), Priority: 5})
	}
	if err = s.Append(estado.Event{Records: records}); err != nil {
		t.Fatal(err)
	}
	handler := painel.Handler(file)
	for _, offset := range []int{0, 100, 200, 300} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", fmt.Sprintf("http://127.0.0.1/api/directory-tree?host=a.test&path=/&offset=%d", offset), nil))
		var page painel.DirectoryPage
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil {
			t.Fatal(w.Body.String())
		}
		want := 100
		if offset == 200 {
			want = 5
		}
		if offset == 300 {
			want = 0
		}
		if page.Total != 205 || len(page.Items) != want {
			t.Fatalf("pagination: %+v", page)
		}
		if want > 0 && page.Items[0].Name != fmt.Sprintf("path-%03d", offset) {
			t.Fatal(page.Items[0])
		}
	}
	for _, query := range []string{"offset=-1", "offset=nope", "path=/api", "host=a.test&path=relative"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1/api/directory-tree?"+query, nil))
		if w.Code != 400 {
			t.Fatalf("%s: %d", query, w.Code)
		}
	}
}
