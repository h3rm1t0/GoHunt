package painel

import (
	"GoHunt/Estado"
	"GoHunt/Modelo"
	"GoHunt/Monitoramento"
	"GoHunt/Util"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func (p *PanelServer) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.server.Shutdown(ctx); err != nil {
		p.server.Close()
	}
	<-p.Exited
}

func Handler(path string) http.Handler {
	return HandlerWithRuntime(path, nil)
}

func Serve(ctx context.Context, address, path string, out io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	f.Close()
	panel, err := StartPanel(address, path, nil)
	if err != nil {
		return err
	}
	defer panel.Close()
	monitoramento.NewConsole(out, false).Log("PAINEL", "Consulta disponível em %s | Ctrl+C encerra o servidor", panel.URL())
	select {
	case <-ctx.Done():
		return nil
	case <-panel.Exited:
		return panel.Err
	}
}

func (p *PanelServer) URL() string { return "http://" + p.listener.Addr().String() }

//go:embed dashboard.html
var dashboard []byte

//go:embed favicon.svg
var favicon []byte

func HandlerWithRuntime(path string, runtime *monitoramento.Runtime) http.Handler {
	mux := http.NewServeMux()
	token := util.RandomID()
	mux.HandleFunc("/api/form-group", groupHandler(path))
	mux.HandleFunc("/api/review", reviewHandler(path, token))
	mux.HandleFunc("/favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write(favicon)
	})
	mux.HandleFunc("/banner.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(webBanner)
	})
	mux.HandleFunc("/api/surface", surfaceHandler(path))
	mux.HandleFunc("/api/directory-tree", directoryHandler(path))
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(runtime.Snapshot())
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(dashboard)
	})
	mux.HandleFunc("/api/results", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		reviews, reviewErr := ReadReviews(path)
		if reviewErr != nil {
			http.Error(w, "Não foi possível ler as revisões manuais", 500)
			return
		}
		offset, err := strconv.Atoi(util.DefaultValue(q.Get("offset"), "0"))
		if err != nil || offset < 0 || offset > 10000000 {
			http.Error(w, "offset inválido", 400)
			return
		}
		limit, err := strconv.Atoi(util.DefaultValue(q.Get("limit"), "50"))
		if err != nil || limit < 1 || limit > 100 {
			http.Error(w, "limit deve ser 1..100", 400)
			return
		}
		priority, err := strconv.Atoi(util.DefaultValue(q.Get("priority"), "0"))
		if err != nil || priority < 0 || priority > 5 {
			http.Error(w, "priority deve ser 0..5", 400)
			return
		}
		search := strings.ToLower(q.Get("q"))
		if len(search) > 512 {
			http.Error(w, "busca muito longa", 400)
			return
		}
		matches := func(record modelo.Record) bool { return matchesResult(record, q, reviews) }
		result := PageResult{CSRFToken: token, Offset: offset, Limit: limit, Items: []modelo.Record{}}
		info, statErr := os.Stat(path)
		if statErr != nil {
			http.Error(w, "Estado não encontrado", 500)
			return
		}
		groupCounts := map[string]int{}
		err = estado.WalkRecordsAt(path, info.Size(), func(record modelo.Record) {
			if matches(record) {
				key := modelo.DisplayID(record)
				groupCounts[key]++
				if groupCounts[key] > 1 {
					return
				}
				result.Counts[record.Priority]++
				result.Total++
			}
		})
		if err != nil {
			http.Error(w, "Não foi possível ler o estado", 500)
			return
		}
		var start [6]int
		for i := 2; i <= 5; i++ {
			start[i] = start[i-1] + result.Counts[i-1]
		}
		var seen [6]int
		var buckets [6][]modelo.Record
		shown := map[string]bool{}
		err = estado.WalkRecordsAt(path, info.Size(), func(record modelo.Record) {
			if !matches(record) {
				return
			}
			key := modelo.DisplayID(record)
			if shown[key] {
				return
			}
			shown[key] = true
			p := record.Priority
			position := start[p] + seen[p]
			seen[p]++
			if position >= offset && position < offset+limit && len(buckets[p]) < limit {
				record.Assessment = AssessmentState(record, reviews[modelo.RecordID(record)])
				record.ID = modelo.RecordID(record)
				if review, ok := reviews[record.ID]; ok {
					record.Review = &review
				}
				if modelo.IsEntry(record) && groupCounts[key] > 1 {
					record.Group = &modelo.EntryGroup{ID: key, Count: groupCounts[key]}
					record.ID = key
					record.Review = nil
					record.Summary = "Estrutura de entrada compartilhada; revisar as ocorrências individualmente"
				}
				buckets[p] = append(buckets[p], record)
			}
		})
		if err != nil {
			http.Error(w, "Não foi possível ler o estado", 500)
			return
		}
		for p := 1; p <= 5; p++ {
			result.Items = append(result.Items, buckets[p]...)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		if r.Method != "GET" && r.Method != "HEAD" && !(r.Method == "POST" && r.URL.Path == "/api/review") {
			http.Error(w, "método não permitido", 405)
			return
		}
		// Avoid exposing local findings through DNS rebinding.
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			http.Error(w, "host não permitido", 403)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

type PageResult struct {
	CSRFToken string          `json:"csrf_token"`
	Total     int             `json:"total"`
	Offset    int             `json:"offset"`
	Limit     int             `json:"limit"`
	Counts    [6]int          `json:"counts"`
	Items     []modelo.Record `json:"items"`
}

type PanelServer struct {
	server   *http.Server
	listener net.Listener
	Exited   chan struct{} `json:"-"`
	Err      error         `json:"-"`
}

func StartPanel(address, path string, runtime *monitoramento.Runtime) (*PanelServer, error) {
	if err := ValidatePanelAddress(address); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("não foi possível iniciar o painel em %s: %w", address, err)
	}
	p := &PanelServer{listener: listener, Exited: make(chan struct{}), server: &http.Server{Handler: HandlerWithRuntime(path, runtime), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second}}
	go func() {
		err := p.server.Serve(listener)
		if err == http.ErrServerClosed {
			err = nil
		}
		p.Err = err
		close(p.Exited)
	}()
	return p, nil
}

func ValidatePanelAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("endereço do painel inválido; use host:porta (ex.: 127.0.0.1:8080): %w", err)
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("o painel deve escutar em loopback, ex.: 127.0.0.1:8080")
	}
	return nil
}

//go:embed banner.txt
var webBanner []byte
