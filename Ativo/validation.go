package ativo

import (
	"GoHunt/Diffing"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"GoHunt/Rede"
	"GoHunt/Util"
	"context"
	"net/url"
	"path"
)

func ValidateHistorical(e *nucleo.Engine, ctx context.Context, t modelo.Task, response modelo.Response, record *modelo.Record) (bool, error) {
	u, err := url.Parse(t.URL)
	if err != nil {
		return false, err
	}
	for i := 0; i < 2; i++ {
		control := *u
		control.Path = path.Dir(u.Path) + "/gohunt-missing-" + util.RandomID()
		control.RawPath = ""
		r, err := rede.Request(e, ctx, control.String(), "GET", nil, "", false)
		if err != nil {
			record.Priority = 5
			record.Evidence["validation"] = "inconclusiva: controle indisponível"
			return false, err
		}
		if !diffing.Similar(response, r) {
			record.Evidence["validation"] = "resposta distinta da rota inexistente; não comprova vulnerabilidade"
			return false, nil
		}
	}
	record.Kind, record.Priority = "filtered", 5
	record.Summary = "Deep link com resposta equivalente a duas rotas inexistentes; possível SPA/soft-404"
	record.Evidence["validation"] = "dois controles negativos equivalentes"
	record.Evidence["manual_review"] = "parâmetros históricos preservados; equivalência de respostas não descarta falhas de lógica"
	return true, nil
}
