package bypass

import (
	origbypass "GoHunt/Bypass/Regras"
	"GoHunt/Diffing"
	"GoHunt/Escopo"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"GoHunt/Rede"
	"GoHunt/Util"
	"context"
	"fmt"
	"net/url"
)

func Bypass(e *nucleo.Engine, ctx context.Context, t modelo.Task) ([]modelo.Task, []modelo.Record, error) {
	original, err := rede.Request(e, ctx, t.URL, "GET", nil, "", false)
	if err != nil {
		return nil, nil, err
	}
	if !diffing.Denied(original.Status) {
		return nil, nil, nil
	}
	headers := map[string]string{}
	if t.Source != "path" {
		value, ok := origbypass.HeadersBypass[t.Source]
		if !ok {
			return nil, nil, fmt.Errorf("cabeçalho de bypass inválido")
		}
		headers[t.Source] = value
	}
	candidate, err := rede.Request(e, ctx, t.Path, "GET", headers, "", false)
	if err != nil {
		return nil, nil, err
	}
	if candidate.Status != 200 || len(candidate.Body) == 0 || diffing.LoginOrChallenge(candidate) {
		return nil, nil, nil
	}
	// Ignore status differences when comparing the denial body itself.
	originalBody := original
	originalBody.Status = candidate.Status
	if diffing.Similar(candidate, originalBody) {
		return nil, nil, nil
	}
	controls := []string{escopo.Origin(t.URL), escopo.Origin(t.URL) + "gohunt-missing-" + util.RandomID()}
	// Repeat the same mutation against a nonexistent path, detecting generic route fallbacks.
	u, _ := url.Parse(t.Path)
	u.Path = "/gohunt-missing-" + util.RandomID() + u.Path
	u.RawPath = ""
	controls = append(controls, u.String())
	for _, control := range controls {
		r, err := rede.Request(e, ctx, control, "GET", headers, "", false)
		if err != nil {
			return nil, nil, err
		}
		if diffing.Similar(candidate, r) {
			return nil, nil, nil
		}
	}
	repeat, err := rede.Request(e, ctx, t.Path, "GET", headers, "", false)
	if err != nil {
		return nil, nil, err
	}
	if !diffing.Similar(candidate, repeat) {
		return nil, nil, nil
	}
	after, err := rede.Request(e, ctx, t.URL, "GET", nil, "", false)
	if err != nil {
		return nil, nil, err
	}
	if !diffing.Denied(after.Status) {
		return nil, nil, nil
	}
	r := modelo.Record{Kind: "bypass-candidate", URL: t.URL, Priority: 2, Status: candidate.Status, Summary: "Candidato reproduzível a bypass; requer validação com sessão autorizada", Source: t.Source, Evidence: map[string]string{"candidate_url": t.Path, "original_status": fmt.Sprint(original.Status), "candidate_sha256": util.Digest(string(candidate.Body)), "confidence": "heurística, não confirmado", "controls": "negação original, raiz, rota inexistente, mutação inexistente, repetição e nova negação"}}
	return nil, []modelo.Record{r}, nil
}
