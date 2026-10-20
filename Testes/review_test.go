package testes

import (
	"GoHunt/Estado"
	"GoHunt/Modelo"
	"GoHunt/Painel"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestManualReviewPersistsMovesAndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.jsonl")
	store, err := estado.OpenStore(path, "fp", false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record := modelo.Record{Kind: "form", URL: "https://a.test/", Priority: 3, Summary: "entrada"}
	info := modelo.Record{Kind: "endpoint", URL: record.URL, Priority: 4}
	if err = store.Append(estado.Event{Records: []modelo.Record{record, info}}); err != nil {
		t.Fatal(err)
	}
	h := painel.Handler(path)
	read := httptest.NewRecorder()
	h.ServeHTTP(read, httptest.NewRequest("GET", "http://127.0.0.1/api/results", nil))
	var results painel.PageResult
	if err = json.Unmarshal(read.Body.Bytes(), &results); err != nil {
		t.Fatal(err)
	}
	token := results.CSRFToken
	post := func(id string, verified bool, revision int, origin string) int {
		body := fmt.Sprintf(`{"id":%q,"verified":%v,"comment":"teste manual concluído <script>","revision":%d}`, id, verified, revision)
		r := httptest.NewRequest("POST", "http://127.0.0.1/api/review", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-GoHunt-Token", token)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	id := modelo.RecordID(record)
	if post(id, true, 0, "https://other.test") != 403 {
		t.Fatal("cross origin accepted")
	}
	if post(modelo.RecordID(info), true, 0, "") != 404 {
		t.Fatal("P4 writable")
	}
	if post(id, true, 0, "") != 200 {
		t.Fatal("save failed")
	}
	if post(id, false, 0, "") != 409 {
		t.Fatal("stale update accepted")
	}
	h2 := painel.Handler(path)
	w := httptest.NewRecorder()
	h2.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1/api/results?review=verified", nil))
	if err = json.Unmarshal(w.Body.Bytes(), &results); err != nil {
		t.Fatal(err)
	}
	if results.Total != 1 || !results.Items[0].Review.Verified || results.Items[0].Review.Comment != "teste manual concluído <script>" {
		t.Fatal(w.Body.String())
	}
	if modelo.RecordID(results.Items[0]) != id {
		t.Fatal("presentation metadata changed identity")
	}
	if post(id, false, 1, "") != http.StatusOK {
		t.Fatal("reopen failed")
	}
	reviews, err := painel.ReadReviews(path)
	if err != nil || reviews[id].Verified || reviews[id].Revision != 2 {
		t.Fatal(reviews, err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1/api/results?review=verified", nil))
	if !strings.Contains(w.Body.String(), `"total":0`) {
		t.Fatal(w.Body.String())
	}
}
