package testes

import (
	"GoHunt/Aplicacao"
	"GoHunt/Ativo"
	"GoHunt/Configuracao"
	"GoHunt/Diffing"
	"GoHunt/Estado"
	"GoHunt/Modelo"
	"GoHunt/Monitoramento"
	"GoHunt/Nucleo"
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDailyConfirmation(t *testing.T) {
	c := localConfig(t, "https://example.com/")
	fp, err := configuracao.Fingerprint(c)
	if err != nil {
		t.Fatal(err)
	}
	s, err := estado.OpenStore(c.State, fp, false)
	if err != nil {
		t.Fatal(err)
	}
	task := modelo.Task{Kind: "page", URL: "https://example.com/"}
	if err = s.Commit(modelo.Task{Kind: "init"}, []modelo.Task{task}, nil, 10); err != nil {
		t.Fatal(err)
	}
	s.Close()
	for _, answer := range []string{"", "n\n", "s\n"} {
		var out bytes.Buffer
		yes, err := aplicacao.ConfirmPending(c, strings.NewReader(answer), &out)
		if err != nil || yes != (answer == "s\n") {
			t.Fatalf("%q %v %v", answer, yes, err)
		}
	}
	s, err = estado.OpenStore(c.State, fp, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Commit(task, nil, nil, 10); err != nil {
		t.Fatal(err)
	}
	s.Close()
	var out bytes.Buffer
	yes, err := aplicacao.ConfirmPending(c, strings.NewReader("s\n"), &out)
	if err != nil || yes {
		t.Fatal("completed scan must not run", err)
	}
}

func TestRuntimeEstimatesExcludeHistoricalWork(t *testing.T) {
	s := &estado.Store{Count: 10, Completed: 8, KindTotal: map[string]int{"page": 10}, KindDone: map[string]int{"page": 8}}
	r := &monitoramento.Runtime{}
	r.Update("coletando", "page", "", true, s, 0)
	if r.Snapshot().Stages["page"].Remaining != "calculando" {
		t.Fatal("historical work used for speed")
	}
	r.Observe("page", 2*time.Second)
	r.Update("coletando", "page", "", true, s, 0)
	info := r.Snapshot()
	if info.Percent != 80 || info.Stages["page"].Remaining != "00m 04s" {
		t.Fatalf("%+v", info)
	}
}

func TestTriageConservative(t *testing.T) {
	e := &nucleo.Engine{}
	for _, tc := range []struct {
		body     string
		status   int
		filtered bool
	}{
		{"normal page", 200, false}, {"other! page", 200, false},
		{"<input type=password>", 200, false}, {"Access Denied", 200, true},
		{"private", 403, false}, {"private", 403, true},
	} {
		r := modelo.Record{Evidence: map[string]string{}}
		got := ativo.FilterPage(e, modelo.Task{URL: "https://example.com/a"}, modelo.Response{Status: tc.status, Body: []byte(tc.body), Header: http.Header{}}, &r)
		if got != tc.filtered {
			t.Fatalf("%+v: %v", tc, got)
		}
	}
	for raw, want := range map[string]int{"https://a/a.png": 0, "https://a/a.png?id=1": 4, "https://a/app.js": 1, "https://a/api/users": 3} {
		if diffing.EndpointRank(raw) != want {
			t.Fatal(raw)
		}
	}
}
