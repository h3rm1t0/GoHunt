package takeover

import (
	"GoHunt/DNS"
	"GoHunt/Escopo"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"GoHunt/Rede"
	"GoHunt/Util"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"net/url"
	"regexp"
	"strings"
)

func providerFor(chain []dns.CNAMEHop) providerRule {
	for _, hop := range chain {
		target := strings.ToLower(strings.TrimSuffix(hop.Target, "."))
		for _, provider := range takeoverProviders {
			for _, suffix := range provider.Suffixes {
				if strings.HasSuffix(target, "."+suffix) {
					return provider
				}
			}
		}
		if s3Endpoint.MatchString(target) {
			return takeoverProviders[3]
		}
	}
	return providerRule{}
}

type providerRule struct {
	Name      string
	Suffixes  []string
	Reference string
}

var s3Endpoint = regexp.MustCompile(`(?i)^.+\.s3(?:[.-][a-z0-9-]+)*\.amazonaws\.com(?:\.cn)?$`)

func Takeover(e *nucleo.Engine, ctx context.Context, t modelo.Task) ([]modelo.Task, []modelo.Record, error) {
	if !e.Scope.Allows(t.URL) {
		return nil, nil, nil
	}
	u, err := url.Parse(t.URL)
	if err != nil {
		return nil, nil, err
	}
	host := strings.ToLower(u.Hostname())
	inspector := e.CNAME
	if inspector == nil {
		inspector = &dns.SystemCNAMEInspector{Timeout: e.Config.Timeout, Before: func(ctx context.Context) error { return rede.Pace(e, ctx) }, Log: e.Log}
	}
	info, dnsErr := inspector.Inspect(ctx, host)
	chainJSON, _ := json.Marshal(info.Chain)
	var chainNames []string
	if len(info.Chain) > 0 {
		chainNames = append(chainNames, info.Chain[0].Name)
		for _, hop := range info.Chain {
			chainNames = append(chainNames, hop.Target)
		}
	}
	rule := providerFor(info.Chain)
	https := *u
	https.Scheme = "https"
	httpURL := *u
	httpURL.Scheme = "http"
	evidence := map[string]string{"hostname": host, "cname_chain": strings.Join(chainNames, " -> "), "cname_records": string(chainJSON), "dns_destination": info.Destination, "dns_rcode": dns.RcodeLabel(info.RCode), "urls_to_check": https.String() + " , " + httpURL.String(), "confidence": "triagem; disponibilidade para registro não confirmada", "manual_validation": "Reconfirmar DNS e HTTP, conferir vínculo e proteções de domínio do provedor antes de concluir takeover."}
	if rule.Name != "" {
		evidence["provider"] = rule.Name
		evidence["provider_reference"] = rule.Reference
	}
	record := modelo.Record{Kind: "takeover-observation", URL: t.URL, Priority: 5, Source: "dns-http", Summary: "Evidências DNS coletadas para revisão de subdomain takeover", Evidence: evidence}
	if dnsErr != nil {
		evidence["dns_rcode"] = "INCONCLUSIVO"
		record.Summary = "Análise DNS incompleta; tarefa permanece pendente"
		evidence["dns_error"] = dnsErr.Error()
		return nil, []modelo.Record{record}, dnsErr
	}
	if len(info.Chain) == 0 {
		evidence["dns_destination_status"] = dns.RcodeLabel(info.RCode)
		record.Summary = "Sem CNAME observado; ausência de DNS isolada não indica takeover"
		return nil, []modelo.Record{record}, nil
	}
	if info.RCode == dnsmessage.RCodeNameError {
		evidence["dns_destination_status"] = "NXDOMAIN"
		record.Kind = "takeover-candidate"
		record.Priority = 3
		record.Summary = "CNAME aponta para destino inexistente; revisar vínculo e possibilidade de takeover"
		if rule.Name != "" {
			record.Priority = 2
			record.Summary = "CNAME associado a " + rule.Name + " aponta para destino NXDOMAIN; validar disponibilidade do recurso"
		}
		evidence["http_observation"] = "Não consultado: destino DNS inexistente"
		return nil, []modelo.Record{record}, nil
	}
	resolver := e.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if err = rede.Pace(e, ctx); err != nil {
		return nil, nil, err
	}
	lookup, cancel := context.WithTimeout(ctx, e.Config.Timeout)
	ips, lookupErr := resolver.LookupHost(lookup, info.Destination)
	cancel()
	if lookupErr != nil {
		if dns, ok := lookupErr.(*net.DNSError); ok && dns.IsNotFound {
			evidence["dns_destination_status"] = "SEM_ENDERECOS_A_AAAA"
			record.Kind = "takeover-candidate"
			record.Priority = 3
			record.Summary = "Destino CNAME sem endereços A/AAAA; revisar DNS antes de investigar takeover"
			evidence["http_observation"] = "Não consultado: destino sem endereços"
			return nil, []modelo.Record{record}, nil
		}
		evidence["dns_error"] = lookupErr.Error()
		return nil, []modelo.Record{record}, lookupErr
	}
	evidence["dns_destination_status"] = "RESOLVIDO"
	evidence["destination_ips"] = strings.Join(ips, ",")
	// Probe only the scoped alias. Never send HTTP to an out-of-scope provider target.
	response, httpErr := rede.Request(e, ctx, t.URL, "GET", nil, "", false)
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	if response.Status != 0 {
		record.Status = response.Status
		evidence["http_status"] = fmt.Sprint(response.Status)
		evidence["body_sha256"] = util.Digest(string(response.Body))
		evidence["server"] = response.Header.Get("Server")
		evidence["content_type"] = response.Header.Get("Content-Type")
		if location := response.Header.Get("Location"); location != "" {
			evidence["redirect_location"] = location
		}
	}
	if httpErr != nil {
		evidence["http_error"] = httpErr.Error()
		record.Summary = "CNAME resolvido; HTTP indisponível/inconclusivo, revisar evidências manualmente"
	}
	if marker := takeoverMarker(rule.Name, response); marker != "" {
		evidence["http_marker"] = marker
		record.Kind = "takeover-candidate"
		record.Priority = 2
		record.Summary = "CNAME de " + rule.Name + " com resposta de recurso não configurado; validar disponibilidade e proteção de domínio"
	}
	return nil, []modelo.Record{record}, nil
}

func takeoverMarker(provider string, response modelo.Response) string {
	if response.Status != 404 {
		return ""
	}
	body := strings.ToLower(string(response.Body))
	switch provider {
	case "Amazon S3":
		if strings.Contains(body, "<code>nosuchbucket</code>") {
			return "NoSuchBucket"
		}
	case "GitHub Pages":
		if strings.Contains(body, "there isn't a github pages site here") {
			return "GitHub Pages: site não configurado"
		}
	case "Azure App Service":
		if strings.Contains(body, "404 web site not found") {
			return "Azure App Service: Web Site not found"
		}
	}
	return ""
}

var takeoverProviders = []providerRule{
	{Name: "GitHub Pages", Suffixes: []string{"github.io"}, Reference: "https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages"},
	{Name: "Azure App Service", Suffixes: []string{"azurewebsites.net"}, Reference: "https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover"},
	{Name: "Azure (CDN/Front Door/Storage/Traffic Manager)", Suffixes: []string{"azureedge.net", "azurefd.net", "blob.core.windows.net", "trafficmanager.net", "cloudapp.net", "cloudapp.azure.com"}, Reference: "https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover"},
	{Name: "Amazon S3", Suffixes: []string{"s3.amazonaws.com"}, Reference: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html"},
	{Name: "Amazon CloudFront", Suffixes: []string{"cloudfront.net"}, Reference: "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html"},
}

// Enqueue checks independently from page reachability: dangling aliases can fail HTTP entirely.
// Task IDs use the origin, so archived URLs do not repeat DNS for every path.
func TakeoverTasks(s *escopo.Scope, tasks []modelo.Task) []modelo.Task {
	var out []modelo.Task
	for _, task := range tasks {
		if task.Kind != "page" && task.Kind != "dns" {
			continue
		}
		raw := task.URL
		if task.Kind == "dns" {
			raw = "https://" + task.URL + "/"
		}
		if !s.Allows(raw) {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || net.ParseIP(u.Hostname()) != nil {
			continue
		}
		out = append(out, modelo.Task{Kind: "takeover", URL: escopo.Origin(raw)})
	}
	return out
}

func WithTakeover(s *escopo.Scope, tasks []modelo.Task) []modelo.Task {
	return append(TakeoverTasks(s, tasks), tasks...)
}
