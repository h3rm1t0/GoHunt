package testes

import (
	"GoHunt/Estado"
	"GoHunt/Modelo"
	"GoHunt/Monitoramento"
	"GoHunt/Painel"
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConsoleColorsOnlyTimestampCategoryAndWhiteMessage(t *testing.T) {
	var b bytes.Buffer
	c := monitoramento.NewConsole(&b, true)
	c.Color = true
	c.Log("PENDENTE", "Mensagem %s", "remota\x1b[31m")
	s := b.String()
	if !strings.Contains(s, "\x1b[91mPENDENTE") || !strings.Contains(s, " | \x1b[97mMensagem remota [31m\x1b[0m") {
		t.Fatal(s)
	}
	if monitoramento.LevelColor("PENDENTE") == monitoramento.LevelColor("DEPURACAO") || monitoramento.LevelColor("ESTIMATIVA") == monitoramento.LevelColor("DEPURACAO") {
		t.Fatal("indistinguishable categories")
	}
}

func TestRuntimeOverdueTaskUpdatesWithoutCompletion(t *testing.T) {
	r := &monitoramento.Runtime{}
	s := &estado.Store{Count: 2, Completed: 1, KindTotal: map[string]int{"takeover": 2}, KindDone: map[string]int{"takeover": 1}}
	r.Observe("takeover", time.Second)
	r.Update("coletando", "takeover", "a.test", true, s, 0)
	r.StartTask("takeover")
	r.Mu.Lock()
	r.ActiveSince = time.Now().Add(-3 * time.Minute)
	r.Mu.Unlock()
	first := r.Snapshot()
	if !strings.Contains(first.Stages["takeover"].Remaining, "recalculando") || first.ActiveElapsed != "03m 00s" {
		t.Fatal(first)
	}
	first.Stages["takeover"] = monitoramento.StageInfo{}
	if r.Snapshot().Stages["takeover"].Total != 2 {
		t.Fatal("snapshot mutated runtime")
	}
	r.Mu.Lock()
	r.ActiveSince = r.ActiveSince.Add(-time.Minute)
	r.Mu.Unlock()
	if r.Snapshot().ActiveElapsed != "04m 00s" {
		t.Fatal("clock stale")
	}
	r.Update("pendencias", "", "", false, s, 1)
	if r.Snapshot().Stages["takeover"].Remaining != "retomada necessária" {
		t.Fatal("failed task ETA misleading")
	}
}

func TestSurfaceConnectsFieldsSourceAndDNS(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state")
	s, err := estado.OpenStore(file, "fp", false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	err = s.Append(estado.Event{Records: []modelo.Record{{Kind: "form", URL: "https://a.test/search?q=x", Source: "https://a.test/", Priority: 3, Fields: []modelo.Field{{Name: "token", Type: "text"}}}, {Kind: "takeover-observation", URL: "https://a.test/", Priority: 5, Evidence: map[string]string{"dns_destination": "provider.test", "destination_ips": "192.0.2.1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	painel.Handler(file).ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1/api/surface?host=a.test", nil))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var result struct {
		Nodes []painel.SurfaceNode `json:"nodes"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Nodes) != 2 || !strings.Contains(w.Body.String(), "token") || !strings.Contains(w.Body.String(), "descoberta em") || !strings.Contains(w.Body.String(), "provider.test") {
		t.Fatal(w.Body.String())
	}
	w = httptest.NewRecorder()
	painel.Handler(file).ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1/api/results?host=b.test", nil))
	if !strings.Contains(w.Body.String(), `"total":0`) {
		t.Fatal(w.Body.String())
	}
}
