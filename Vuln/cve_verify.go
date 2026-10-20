package vuln

import (
	"GoHunt/Configuracao"
	"GoHunt/Db"
	"GoHunt/Diffing"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"GoHunt/Rede"
	"GoHunt/Util"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

func AssessCVE(e *nucleo.Engine, ctx context.Context, t modelo.Task) ([]modelo.Task, []modelo.Record, error) {
	if e.Config.CVEMode == "off" || e.Config.CVEMode == "" || e.Catalog == nil {
		return nil, nil, fmt.Errorf("análise CVE não configurada")
	}
	a, ok := e.Catalog.ByID[t.Source]
	if !ok {
		return nil, nil, fmt.Errorf("CVE ausente do catálogo")
	}
	var c modelo.Component
	if err := json.Unmarshal([]byte(t.Path), &c); err != nil {
		return nil, nil, err
	}
	if c.URL != t.URL || c.Product != a.Product || !a.Affects(c.Version) || !e.Scope.Allows(t.URL) {
		return nil, nil, fmt.Errorf("pré-condições de CVE inconsistentes")
	}
	r := modelo.Record{Kind: "cve-correlation", URL: t.URL, Priority: 5, Source: a.ID, Summary: a.ID + ": versão na faixa afetada; exposição não comprovada", Evidence: map[string]string{"cve": a.ID, "product": c.Product, "version": c.Version, "signal": c.Evidence, "reference": a.Reference, "conditions": a.Conditions, "catalog_reviewed": e.Catalog.Reviewed, "assessment": "correlated", "limitation": "correlação não comprova configuração, alcance nem ausência de backport"}}
	missing := db.MissingRequirements(a, c)
	facts, _ := json.Marshal(c.Facts)
	r.Evidence["condition_evidence"] = string(facts)
	r.Evidence["missing_conditions"] = strings.Join(missing, ", ")
	r.Evidence["confidence"] = modelo.ComponentRecord(c).Evidence["confidence"]
	r.Evidence["source_type"] = c.SourceType
	if len(a.Requires) > 0 && len(missing) == 0 {
		r.Evidence["assessment"] = "preconditions-met"
		r.Summary = a.ID + ": pré-condições documentadas no inventário; exploração não comprovada"
	}
	if e.Config.CVEMode != "verify" || a.Verifier == "" || !configuracao.SelectedVerifier(e.Config, a.Verifier) {
		return nil, []modelo.Record{r}, nil
	}
	proof, reason, err := VerifyJoomla(e, ctx, t.URL)
	if err != nil {
		return nil, nil, err
	} // Do not mark transport failures as negative; journal retries on resume.
	if proof == nil {
		r.Kind = "cve-inconclusive"
		r.Summary = a.ID + ": verificação não confirmou exposição"
		r.Evidence["assessment"] = "inconclusive"
		r.Evidence["reason"] = reason
		return nil, []modelo.Record{r}, nil
	}
	r.Kind = "cve-verified"
	r.Priority = 2
	r.Summary = a.ID + ": acesso sem autenticação a dados de usuários reproduzido; revisar impacto"
	r.Evidence["assessment"] = "reproduced"
	r.Evidence["missing_conditions"] = ""
	r.Evidence["verifier"] = a.Verifier
	for k, v := range proof {
		r.Evidence[k] = v
	}
	return nil, []modelo.Record{r}, nil
}

func userIDs(r modelo.Response) ([]string, bool) {
	if r.Status != 200 || !strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "json") || diffing.LoginOrChallenge(r) {
		return nil, false
	}
	var doc struct {
		Data []struct {
			Type       string                     `json:"type"`
			ID         string                     `json:"id"`
			Attributes map[string]json.RawMessage `json:"attributes"`
		} `json:"data"`
		Errors json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(r.Body, &doc) != nil || len(doc.Data) == 0 || len(doc.Data) > 10 || len(doc.Errors) > 0 {
		return nil, false
	}
	var ids []string
	for _, item := range doc.Data {
		var username, email string
		if item.Type != "users" || item.ID == "" || json.Unmarshal(item.Attributes["username"], &username) != nil || json.Unmarshal(item.Attributes["email"], &email) != nil || username == "" || !strings.Contains(email, "@") {
			return nil, false
		}
		ids = append(ids, item.ID)
	}
	sort.Strings(ids)
	return ids, true
}

func VerifyJoomla(e *nucleo.Engine, ctx context.Context, base string) (map[string]string, string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, "", err
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/api/index.php/v1/users"
	u.RawQuery = "page%5Blimit%5D=1"
	controlURL := u.String()
	// One controlled collection item; neither configuration secrets nor response
	// bodies are persisted. No credentials, cookies or state-changing methods.
	control, err := rede.RequestOnce(e, ctx, controlURL, "GET", nil, "", false)
	if err != nil {
		return nil, "", err
	}
	if !diffing.Denied(control.Status) {
		return nil, "rota de controle não exige autenticação", nil
	}
	q := u.Query()
	q.Set("public", "true")
	u.RawQuery = q.Encode()
	candidateURL := u.String()
	candidate, err := rede.RequestOnce(e, ctx, candidateURL, "GET", nil, "", false)
	if err != nil {
		return nil, "", err
	}
	ids, ok := userIDs(candidate)
	if !ok {
		return nil, "resposta sem estrutura de usuários esperada", nil
	}
	missing := *u
	missing.Path = strings.TrimSuffix(u.Path, "/users") + "/gohunt-missing-" + util.RandomID()
	negative, err := rede.RequestOnce(e, ctx, missing.String(), "GET", nil, "", false)
	if err != nil {
		return nil, "", err
	}
	if _, ok := userIDs(negative); ok || diffing.Similar(candidate, negative) {
		return nil, "controle negativo devolve dados equivalentes", nil
	}
	if negative.Status != 404 {
		return nil, "controle negativo inconclusivo", nil
	}
	repeat, err := rede.RequestOnce(e, ctx, candidateURL, "GET", nil, "", false)
	if err != nil {
		return nil, "", err
	}
	again, ok := userIDs(repeat)
	if !ok || strings.Join(ids, "\x00") != strings.Join(again, "\x00") {
		return nil, "dados não reproduzíveis", nil
	}
	after, err := rede.RequestOnce(e, ctx, controlURL, "GET", nil, "", false)
	if err != nil {
		return nil, "", err
	}
	if !diffing.Denied(after.Status) {
		return nil, "controle final deixou de exigir autenticação", nil
	}
	return map[string]string{"checked_url": candidateURL, "control_url": controlURL, "control_status": fmt.Sprint(control.Status), "negative_status": fmt.Sprint(negative.Status), "repeat_status": fmt.Sprint(repeat.Status), "body_sha256": util.Digest(string(candidate.Body)), "records_observed": fmt.Sprint(len(ids)), "validation": "negação antes/depois, JSON de usuários, rota inexistente e repetição; 5 GETs; corpos e dados pessoais não persistidos"}, "", nil
}
