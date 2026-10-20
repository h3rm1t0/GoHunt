package testes

import (
	"GoHunt/Configuracao"
	"GoHunt/DNS"
	"GoHunt/Escopo"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"GoHunt/Takeover"
	"context"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func (f inspectorFunc) Inspect(ctx context.Context, host string) (dns.CNAMEInfo, error) {
	return f(ctx, host)
}

func TestTakeoverDanglingAliasPreservesEvidenceWithoutHTTP(t *testing.T) {
	e := takeoverEngine("retired.github.io", dnsmessage.RCodeNameError)
	e.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("HTTP should not run for an NXDOMAIN destination")
		return nil, nil
	})}
	_, records, err := takeover.Takeover(e, context.Background(), modelo.Task{URL: "https://orphan.example/"})
	if err != nil || len(records) != 1 {
		t.Fatalf("%v %v", records, err)
	}
	r := records[0]
	if r.Kind != "takeover-candidate" || r.Priority != 2 || r.Evidence["dns_destination_status"] != "NXDOMAIN" || r.Evidence["provider"] != "GitHub Pages" || !strings.Contains(r.Evidence["cname_records"], `"ttl":60`) {
		t.Fatalf("missing evidence: %+v", r)
	}
	for _, url := range []string{"https://orphan.example/", "http://orphan.example/"} {
		if !strings.Contains(r.Evidence["urls_to_check"], url) {
			t.Fatal("review URL missing")
		}
	}
}

func TestTakeoverHTTPUnavailableRemainsInconclusive(t *testing.T) {
	e := takeoverEngine("active.github.io", dnsmessage.RCodeSuccess)
	e.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("TLS fixture error") })}
	_, records, err := takeover.Takeover(e, context.Background(), modelo.Task{URL: "https://orphan.example/"})
	if err != nil || records[0].Kind != "takeover-observation" || records[0].Evidence["http_error"] == "" {
		t.Fatalf("%v %v", records, err)
	}
}

func TestTakeoverMissingNameWithoutAliasIsNotCandidate(t *testing.T) {
	e := takeoverEngine("", dnsmessage.RCodeNameError)
	e.CNAME = inspectorFunc(func(context.Context, string) (dns.CNAMEInfo, error) {
		return dns.CNAMEInfo{Destination: "orphan.example", RCode: dnsmessage.RCodeNameError}, nil
	})
	_, records, err := takeover.Takeover(e, context.Background(), modelo.Task{URL: "https://orphan.example/"})
	if err != nil || records[0].Kind != "takeover-observation" || records[0].Priority != 5 {
		t.Fatalf("%v %v", records, err)
	}
}

func TestTakeoverProviderMarkersAndFalsePositives(t *testing.T) {
	cases := []struct {
		name, target, body string
		status             int
		candidate          bool
	}{
		{"S3 missing bucket", "retired.s3-website-us-east-1.amazonaws.com", "<Error><Code>NoSuchBucket</Code></Error>", 404, true},
		{"S3 missing key", "active.s3.amazonaws.com", "<Error><Code>NoSuchKey</Code></Error>", 404, false},
		{"GitHub unconfigured", "retired.github.io", "There isn't a GitHub Pages site here.", 404, true},
		{"Azure unconfigured", "retired.azurewebsites.net", "404 Web Site not found.", 404, true},
		{"Generic 404", "active.github.io", "Page not found", 404, false},
		{"Wrong provider marker", "active.github.io", "<Code>NoSuchBucket</Code>", 404, false},
		{"Misleading provider suffix", "retired.github.io.evil.test", "There isn't a GitHub Pages site here.", 404, false},
		{"CloudFront generic denial", "active.cloudfront.net", "ERROR: The request could not be satisfied", 403, false},
		{"Marker in successful document", "active.github.io", "There isn't a GitHub Pages site here.", 200, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			e := takeoverEngine(tt.target, dnsmessage.RCodeSuccess)
			calls := 0
			e.Client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.URL.Hostname() != "orphan.example" {
					t.Fatal("out-of-scope provider contacted")
				}
				return &http.Response{StatusCode: tt.status, Header: http.Header{"Server": []string{"fixture"}}, Body: io.NopCloser(strings.NewReader(tt.body))}, nil
			})}
			_, records, err := takeover.Takeover(e, context.Background(), modelo.Task{URL: "https://orphan.example/"})
			if err != nil || len(records) != 1 || calls != 1 {
				t.Fatalf("%v %v requests=%d", records, err, calls)
			}
			if (records[0].Kind == "takeover-candidate") != tt.candidate {
				t.Fatalf("incorrect candidate: %+v", records[0])
			}
			if records[0].Evidence["body_sha256"] == "" || records[0].Evidence["dns_destination_status"] != "RESOLVIDO" {
				t.Fatal("HTTP/DNS evidence missing")
			}
		})
	}
}

func TestTakeoverTasksDeduplicateOriginAndRespectScope(t *testing.T) {
	s := &escopo.Scope{Exact: map[string]bool{"orphan.example": true, "127.0.0.1": true}}
	tasks := takeover.TakeoverTasks(s, []modelo.Task{{Kind: "page", URL: "https://orphan.example/a"}, {Kind: "page", URL: "https://orphan.example/b"}, {Kind: "page", URL: "http://orphan.example/"}, {Kind: "page", URL: "https://evil.test/"}, {Kind: "page", URL: "http://127.0.0.1/"}})
	if len(tasks) != 3 || tasks[0].ID() != tasks[1].ID() || tasks[1].ID() == tasks[2].ID() {
		t.Fatal(tasks)
	}
}

func TestTakeoverTemporaryDNSFailureStaysPending(t *testing.T) {
	e := takeoverEngine("active.github.io", dnsmessage.RCodeSuccess)
	e.CNAME = inspectorFunc(func(context.Context, string) (dns.CNAMEInfo, error) {
		return dns.CNAMEInfo{Chain: []dns.CNAMEHop{{Name: "orphan.example", Target: "active.github.io"}}}, &net.DNSError{IsTimeout: true, Err: "timeout"}
	})
	_, records, err := takeover.Takeover(e, context.Background(), modelo.Task{URL: "https://orphan.example/"})
	if err == nil || len(records) != 1 || records[0].Kind == "takeover-candidate" {
		t.Fatalf("%v %v", records, err)
	}
}

func TestUnresolvedWordlistHostStillGetsTakeoverTask(t *testing.T) {
	scope := &escopo.Scope{Exact: map[string]bool{}, Wild: []string{"example"}}
	tasks := takeover.WithTakeover(scope, []modelo.Task{{Kind: "dns", URL: "orphan.example", Source: "example"}})
	if len(tasks) != 2 || tasks[0].Kind != "takeover" || tasks[0].URL != "https://orphan.example/" || tasks[1].Kind != "dns" {
		t.Fatal(tasks)
	}
}

type inspectorFunc func(context.Context, string) (dns.CNAMEInfo, error)

func takeoverEngine(target string, code dnsmessage.RCode) *nucleo.Engine {
	return &nucleo.Engine{
		Config: configuracao.Config{Timeout: time.Second, MaxBody: 1024},
		Scope:  &escopo.Scope{Exact: map[string]bool{"orphan.example": true}},
		CNAME: inspectorFunc(func(context.Context, string) (dns.CNAMEInfo, error) {
			return dns.CNAMEInfo{Chain: []dns.CNAMEHop{{Name: "orphan.example", Target: target, TTL: 60}}, Destination: target, RCode: code}, nil
		}),
		Resolver: resolverFunc(func(context.Context, string) ([]string, error) { return []string{"192.0.2.1"}, nil }),
	}
}
