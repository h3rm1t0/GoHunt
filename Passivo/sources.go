package passivo

import (
	"GoHunt/Diffing"
	"GoHunt/Escopo"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"GoHunt/Rede"
	"GoHunt/Util"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
)

func Dns(e *nucleo.Engine, ctx context.Context, t modelo.Task) ([]modelo.Task, []modelo.Record, error) {
	if !e.Scope.Allows("https://" + t.URL + "/") {
		return nil, nil, nil
	}
	if err := rede.Pace(e, ctx); err != nil {
		return nil, nil, err
	}
	resolver := e.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	lookupCtx, cancel := context.WithTimeout(ctx, e.Config.Timeout)
	defer cancel()
	ips, err := resolver.LookupHost(lookupCtx, t.URL)
	if err != nil {
		if dns, ok := err.(*net.DNSError); ok && dns.IsNotFound {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	// Detect catch-all DNS using two unrelated random labels. Do not classify it as a confirmed host.
	parent := t.Source
	wildcard := false
	for i := 0; i < 2; i++ {
		if err := rede.Pace(e, ctx); err != nil {
			return nil, nil, err
		}
		control := "gohunt-" + util.RandomID() + "." + parent
		cctx, done := context.WithTimeout(ctx, e.Config.Timeout)
		other, xerr := resolver.LookupHost(cctx, control)
		done()
		if xerr != nil {
			if d, ok := xerr.(*net.DNSError); ok && d.IsNotFound {
				continue
			}
			return nil, nil, xerr
		}
		if len(other) > 0 {
			wildcard = true
		}
	}
	r := modelo.Record{Kind: "dns", URL: t.URL, Priority: 5, Summary: "DNS resolvido", Evidence: map[string]string{"ips": strings.Join(ips, ",")}}
	if wildcard {
		r.Summary = "Possível DNS wildcard; candidato não confirmado"
		return nil, []modelo.Record{r}, nil
	}
	return []modelo.Task{{Kind: "page", URL: "https://" + t.URL + "/", Source: "wordlist-subs"}, {Kind: "page", URL: "http://" + t.URL + "/", Source: "wordlist-subs"}}, []modelo.Record{r}, nil
}

func Source(e *nucleo.Engine, ctx context.Context, t modelo.Task) ([]modelo.Task, []modelo.Record, error) {
	domain := t.URL
	limit := e.Config.SourceLimit
	var address string
	switch t.Source {
	case "crtsh":
		address = "https://crt.sh/?q=" + url.QueryEscape("%."+domain) + "&output=json"
	case "otx":
		address = "https://otx.alienvault.com/api/v1/indicators/domain/" + url.PathEscape(domain) + "/passive_dns"
	case "wayback":
		address = "https://web.archive.org/cdx/search/cdx?" + url.Values{"url": {domain}, "matchType": {"domain"}, "output": {"json"}, "fl": {"original"}, "collapse": {"urlkey"}, "limit": {fmt.Sprint(limit)}}.Encode()
	case "commoncrawl":
		r, err := rede.Request(e, ctx, "https://index.commoncrawl.org/collinfo.json", "GET", nil, "", true)
		if err != nil {
			return nil, nil, err
		}
		if r.Status != 200 {
			return nil, nil, fmt.Errorf("índices Common Crawl HTTP %d", r.Status)
		}
		var indexes []struct {
			API string `json:"cdx-api"`
		}
		if err = json.Unmarshal(r.Body, &indexes); err != nil || len(indexes) == 0 {
			return nil, nil, fmt.Errorf("índices Common Crawl inválidos")
		}
		u, err := url.Parse(indexes[0].API)
		if err != nil || u.Scheme != "https" || u.Host != "index.commoncrawl.org" || u.User != nil {
			return nil, nil, fmt.Errorf("endpoint Common Crawl inválido")
		}
		address = indexes[0].API + "?" + url.Values{"url": {"*." + domain}, "output": {"json"}, "filter": {"status:200"}, "pageSize": {"1"}}.Encode()
	}
	headers := map[string]string{}
	if t.Source == "otx" {
		if key := os.Getenv("OTX_API_KEY"); key != "" {
			headers["X-OTX-API-KEY"] = key
		}
	}
	r, err := rede.Request(e, ctx, address, "GET", headers, "", true)
	if err != nil {
		return nil, nil, err
	}
	if r.Status != 200 {
		if t.Source == "commoncrawl" && r.Status == 404 && strings.Contains(string(r.Body), "No Captures found") {
			return nil, []modelo.Record{{Kind: "source", URL: domain, Priority: 5, Source: t.Source, Summary: "Nenhuma captura no índice consultado"}}, nil
		}
		return nil, nil, fmt.Errorf("%s retornou HTTP %d", t.Source, r.Status)
	}
	var values []string
	switch t.Source {
	case "crtsh":
		var rows []struct {
			Name string `json:"name_value"`
		}
		if err = json.Unmarshal(r.Body, &rows); err != nil {
			return nil, nil, err
		}
		for _, row := range rows {
			values = append(values, strings.Split(row.Name, "\n")...)
		}
	case "otx":
		var result struct {
			Rows []struct {
				Host string `json:"hostname"`
			} `json:"passive_dns"`
		}
		if err = json.Unmarshal(r.Body, &result); err != nil {
			return nil, nil, err
		}
		if result.Rows == nil {
			return nil, nil, fmt.Errorf("resposta OTX sem passive_dns")
		}
		for _, row := range result.Rows {
			values = append(values, row.Host)
		}
	case "wayback":
		var rows [][]string
		if err = json.Unmarshal(r.Body, &rows); err != nil {
			return nil, nil, err
		}
		for _, row := range rows {
			if len(row) > 0 && row[0] != "original" {
				values = append(values, row[0])
			}
		}
	case "commoncrawl":
		scan := bufio.NewScanner(strings.NewReader(string(r.Body)))
		scan.Buffer(make([]byte, 4096), 1<<20)
		for scan.Scan() {
			var row struct {
				URL string `json:"url"`
			}
			if err = json.Unmarshal(scan.Bytes(), &row); err != nil {
				return nil, nil, err
			}
			if row.URL == "" {
				return nil, nil, fmt.Errorf("registro Common Crawl sem URL")
			}
			values = append(values, row.URL)
		}
		if err = scan.Err(); err != nil {
			return nil, nil, err
		}
	}
	var tasks []modelo.Task
	var records []modelo.Record
	seen := map[string]bool{}
	total := len(values)
	historicalGroups := map[string]int{}
	historicalSamples := map[string][]string{}
	historicalCounts := map[string]int{}
	sort.SliceStable(values, func(i, j int) bool { return diffing.EndpointRank(values[i]) > diffing.EndpointRank(values[j]) })
	for _, value := range values {
		value = strings.TrimSpace(value)
		if !strings.Contains(value, "://") {
			value = strings.TrimPrefix(strings.ToLower(value), "*.")
			if !escopo.ValidHost(value) {
				continue
			}
			value = "https://" + value + "/"
		}
		canonical, err := escopo.Normalize(value)
		if err != nil || !e.Scope.Allows(canonical) || seen[canonical] {
			continue
		}
		seen[canonical] = true
		if t.Source == "wayback" || t.Source == "commoncrawl" {
			key := escopo.RouteKey(canonical)
			historicalCounts[key]++
			if len(historicalSamples[key]) < 5 {
				historicalSamples[key] = append(historicalSamples[key], canonical)
			}
			if _, exists := historicalGroups[key]; exists {
				continue
			}
			if len(records) >= limit {
				continue
			}
			historicalGroups[key] = len(records)
		}
		if len(records) >= limit {
			continue
		}
		if diffing.EndpointRank(canonical) == 0 {
			records = append(records, modelo.Record{Kind: "filtered", URL: canonical, Priority: 5, Source: t.Source, Summary: "Asset estático passivo; referência preservada sem consulta HTTP"})
			continue
		}
		tasks = append(tasks, modelo.Task{Kind: "page", URL: canonical, Source: t.Source})
		records = append(records, modelo.Record{Kind: "discovery", URL: canonical, Priority: 5, Summary: "Referência pública; disponibilidade ainda não confirmada", Source: t.Source})
	}
	for key, index := range historicalGroups {
		r := &records[index]
		u, _ := url.Parse(r.URL)
		var names []string
		for name := range u.Query() {
			names = append(names, name)
		}
		sort.Strings(names)
		samples, _ := json.Marshal(historicalSamples[key])
		r.Evidence = map[string]string{"route_signature": key, "parameter_names": strings.Join(names, ", "), "sample_urls": string(samples), "observed_variants": fmt.Sprint(historicalCounts[key]), "validation": "referência histórica; somente a URL representante será verificada", "sampling": "até 5 exemplos; valores diferentes podem produzir comportamentos diferentes"}
		for _, name := range names {
			r.Fields = append(r.Fields, modelo.Field{Name: name, Type: "query"})
		}
		if len(names) > 0 && r.Kind != "filtered" {
			r.Kind = "parameters"
			r.Summary = "Parâmetros históricos preservados para revisão manual"
		}
	}
	records = append(records, modelo.Record{Kind: "source", URL: domain, Priority: 5, Source: t.Source, Summary: fmt.Sprintf("%d referências em escopo; %d entradas na resposta; limite configurado %d (consulta limitada, não exaustiva)", len(records), total, limit)})
	return tasks, records, nil
}
