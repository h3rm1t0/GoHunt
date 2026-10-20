package testes

import (
	"GoHunt/Aplicacao"
	"GoHunt/Configuracao"
	"GoHunt/Estado"
	"GoHunt/Modelo"
	"GoHunt/Monitoramento"
	"GoHunt/Painel"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func (p *panelOutput) String() string { p.mu.Lock(); defer p.mu.Unlock(); return p.buffer.String() }

func TestConsoleHighlightsAndSanitizesRemoteContent(t *testing.T) {
	var output bytes.Buffer
	console := monitoramento.NewConsole(&output, true)
	console.Begin(modelo.Task{Kind: "takeover", URL: "https://orphan.example/"}, 0, 1)
	console.Findings([]modelo.Record{{Kind: "takeover-candidate", Priority: 2, URL: "https://orphan.example/", Summary: "evidência\n\x1b[2J remota", Evidence: map[string]string{"provider": "GitHub Pages", "urls_to_check": "https://orphan.example/"}}})
	console.Progress(1, 1, 0, 1, true)
	console.Progress(1, 1, 0, 1, true)
	text := output.String()
	if strings.Count(text, "PROGRESSO") != 1 {
		t.Fatal("duplicate final progress", text)
	}
	for _, word := range []string{"FASE", "Triagem de subdomain takeover", "DEPURACAO", "ACHADO", ">>> P2", "URLs para validar", "PROGRESSO"} {
		if !strings.Contains(text, word) {
			t.Fatal(text)
		}
	}
	if strings.Contains(text, "\x1b") {
		t.Fatal("remote terminal escape was not removed")
	}
}

func TestOccupiedPanelPortPreventsScan(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, "ok") }))
	defer target.Close()
	c := localConfig(t, target.URL)
	c.Listen = listener.Addr().String()
	if err = aplicacao.Run(context.Background(), c, io.Discard); err == nil {
		t.Fatal("occupied port accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("scan started before successful panel startup")
	}
	c.Resume = true
	c.Listen = ""
	if err = aplicacao.Run(context.Background(), c, io.Discard); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("prepared state could not resume")
	}
}

func TestPanelStartsBeforeScanAndStaysUntilCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output := &panelOutput{ready: make(chan string, 1)}
	panelAddress := make(chan string, 1)
	readyBeforeScan := make(chan error, 1)
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case address := <-output.ready:
			info, err := fetchRuntime(client, address)
			if err == nil && !info.Running {
				err = fmt.Errorf("runtime not marked as collecting")
			}
			readyBeforeScan <- err
			panelAddress <- address
		case <-time.After(time.Second):
			readyBeforeScan <- fmt.Errorf("panel not ready before first target request")
		}
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "ok")
	}))
	defer target.Close()
	config := localConfig(t, target.URL)
	done := make(chan error, 1)
	go func() { done <- aplicacao.Run(ctx, config, output) }()
	select {
	case err := <-readyBeforeScan:
		if err != nil {
			t.Fatal(err)
		}
	case err := <-done:
		t.Fatalf("scan exited before target request: %v; log: %s", err, output.String())
	// The race detector substantially slows Wappalyzer regex compilation.
	case <-time.After(15 * time.Second):
		t.Fatalf("scan did not start; log: %s", output.String())
	}
	address := <-panelAddress
	deadline := time.After(3 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		info, err := fetchRuntime(client, address)
		if err != nil {
			t.Fatal(err)
		}
		if info.State == "concluido" {
			if info.Running || info.Pending != 0 || info.Completed != info.Total || info.Records == 0 {
				t.Fatalf("incorrect final status: %+v", info)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("scan did not complete")
		case <-ticker.C:
		}
	}
	select {
	case err := <-done:
		t.Fatalf("server exited before cancellation: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not shut down")
	}
	if _, err := fetchRuntime(client, address); err == nil {
		t.Fatal("panel still accepting requests")
	}
	if !strings.Contains(output.String(), "FASE") || !strings.Contains(output.String(), "PROGRESSO") || !strings.Contains(output.String(), "RESUMO") {
		t.Fatal(output.String())
	}
}

func TestResumeAddsTakeoverToPreviouslyCompletedPages(t *testing.T) {
	s, err := estado.OpenStore(filepath.Join(t.TempDir(), "state.jsonl"), "fp", false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	page := modelo.Task{Kind: "page", URL: "https://orphan.example/"}
	s.Commit(modelo.Task{Kind: "init"}, []modelo.Task{page}, nil, 10)
	s.Commit(page, nil, nil, 10)
	e := takeoverEngine("retired.github.io", dnsmessage.RCodeNameError)
	e.Config.MaxTasks = 10
	e.Log = monitoramento.NewConsole(io.Discard, false)
	e.Scope.Seeds = []string{"orphan.example"}
	runtime := &monitoramento.Runtime{}
	if err = aplicacao.Scan(e, context.Background(), s, runtime); err != nil {
		t.Fatal(err)
	}
	if s.Completed != 2 || s.Count != 2 || s.RecordCounts[2] != 1 {
		t.Fatalf("counts=%d completed=%d priorities=%v", s.Count, s.Completed, s.RecordCounts)
	}
	records := s.RecordCount
	if err = aplicacao.Scan(e, context.Background(), s, runtime); err != nil {
		t.Fatal(err)
	}
	if s.RecordCount != records {
		t.Fatal("completed takeover repeated on resume")
	}
}

func TestRuntimeAPIConcurrentReads(t *testing.T) {
	runtime := &monitoramento.Runtime{}
	runtime.Update("coletando", "Reconhecimento passivo", "orphan.example", true, nil, 0)
	handler := painel.HandlerWithRuntime("unused", runtime)
	var workers sync.WaitGroup
	for i := 0; i < 10; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 10; j++ {
				runtime.Update("coletando", "Reconhecimento passivo", "orphan.example", true, nil, j)
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, httptest.NewRequest("GET", "http://127.0.0.1/api/status", nil))
				if recorder.Code != 200 {
					t.Errorf("status=%d", recorder.Code)
				}
			}
		}()
	}
	workers.Wait()
}

func TestServerAndDebugFlagsDoNotInvalidateFingerprint(t *testing.T) {
	c := localConfig(t, "https://orphan.example/")
	a, err := configuracao.Fingerprint(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Listen = "127.0.0.1:8099"
	c.Debug = true
	b, err := configuracao.Fingerprint(c)
	if err != nil || a != b {
		t.Fatalf("%s %s %v", a, b, err)
	}
}

func (p *panelOutput) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n, err := p.buffer.Write(data)
	if strings.Contains(string(data), "Servidor HTTP iniciado antes da coleta:") {
		for _, field := range strings.Fields(string(data)) {
			if strings.HasPrefix(field, "http://") {
				p.once.Do(func() { p.ready <- field })
				break
			}
		}
	}
	return n, err
}

func fetchRuntime(client *http.Client, address string) (monitoramento.RuntimeInfo, error) {
	response, err := client.Get(address + "/api/status")
	if err != nil {
		return monitoramento.RuntimeInfo{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return monitoramento.RuntimeInfo{}, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	var info monitoramento.RuntimeInfo
	err = json.NewDecoder(response.Body).Decode(&info)
	return info, err
}

func localConfig(t *testing.T, target string) configuracao.Config {
	dir := t.TempDir()
	scope := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scope, []byte(target), 0600); err != nil {
		t.Fatal(err)
	}
	return configuracao.Config{Scope: scope, State: filepath.Join(dir, "state.jsonl"), Listen: "127.0.0.1:0", Timeout: time.Second, MaxBody: 1024, MaxTasks: 50, Depth: 1, SourceLimit: 10}
}

type panelOutput struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	ready  chan string
	once   sync.Once
}
