package vuln

import (
	"GoHunt/Diffing"
	"GoHunt/Escopo"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"GoHunt/Rede"
	"GoHunt/Util"
	origvuln "GoHunt/Vuln/Templates"
	"context"
	"fmt"
	"net/url"
)

func Template(e *nucleo.Engine, ctx context.Context, t modelo.Task) ([]modelo.Task, []modelo.Record, error) {
	if t.Offset < 0 || int(t.Offset) >= len(e.Templates) {
		return nil, nil, fmt.Errorf("índice de template inválido")
	}
	tpl := e.Templates[t.Offset]
	base, _ := url.Parse(t.URL)
	path, err := url.Parse(t.Path)
	if err != nil {
		return nil, nil, err
	}
	target := base.ResolveReference(path).String()
	if !e.Scope.Allows(target) {
		return nil, nil, nil
	}
	method := tpl.Requisicao.Metodo
	if method == "" {
		method = "GET"
	}
	response, err := rede.Request(e, ctx, target, method, tpl.Requisicao.Headers, tpl.Requisicao.Body, false)
	if err != nil {
		return nil, nil, err
	}
	if !origvuln.Match(string(response.Body), response.Header, response.Status, tpl) {
		return nil, nil, nil
	}
	controlMethod := "GET"
	var controlHeaders map[string]string
	if method == "GET" || method == "HEAD" {
		controlMethod = method
		controlHeaders = tpl.Requisicao.Headers
	}
	control, err := rede.Request(e, ctx, escopo.Origin(target)+"gohunt-missing-"+util.RandomID(), controlMethod, controlHeaders, "", false)
	if err != nil {
		return nil, nil, err
	}
	genericBody := len(response.Body) > 0 && len(control.Body) > 0
	sameStatus := response.Status == control.Status
	control.Status = response.Status
	if (genericBody && diffing.Similar(response, control)) || (method == "HEAD" && sameStatus && origvuln.Match("", control.Header, control.Status, tpl)) || diffing.LoginOrChallenge(response) {
		return nil, nil, nil
	}
	validation := "matcher e controle negativo; método sem repetição automática"
	if method == "GET" || method == "HEAD" {
		repeat, err := rede.Request(e, ctx, target, method, tpl.Requisicao.Headers, tpl.Requisicao.Body, false)
		if err != nil {
			return nil, nil, err
		}
		if !origvuln.Match(string(repeat.Body), repeat.Header, repeat.Status, tpl) || !diffing.Similar(response, repeat) {
			return nil, nil, nil
		}
		validation = "matcher reproduzido; resposta estável e distinta do controle negativo"
	}
	priority := 5 // Converted matchers never demonstrate CVE impact.
	return nil, []modelo.Record{{Kind: "template-candidate", URL: target, Priority: priority, Status: response.Status, Source: tpl.ID, Summary: tpl.Info.Nome + " — matcher satisfeito; validar impacto", Evidence: map[string]string{"severity": tpl.Info.Severidade, "body_sha256": util.Digest(string(response.Body)), "confidence": "candidato", "validation": validation}}}, nil
}
