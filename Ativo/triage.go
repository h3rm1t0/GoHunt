package ativo

import (
	"GoHunt/Diffing"
	"GoHunt/Escopo"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"GoHunt/Util"
	"fmt"
)

func FilterPage(e *nucleo.Engine, t modelo.Task, r modelo.Response, record *modelo.Record) bool {
	record.Evidence["body_length"] = fmt.Sprint(len(r.Body))
	if diffing.BlockPage(r) {
		record.Kind, record.Priority = "filtered", 5
		record.Summary = "Possível bloqueio/WAF ou soft-403; expansão suspensa, revisar manualmente"
		record.Evidence["filter_reason"] = "block-content"
		return true
	}
	// Group only identical access-denied responses from the same origin. Equal size
	// alone is never sufficient; normal successful pages are not discarded.
	if r.Status == 401 || r.Status == 403 {
		key := escopo.Origin(t.URL) + fmt.Sprint(r.Status) + r.Header.Get("Content-Type") + util.Digest(string(r.Body))
		if e.DeniedBodies == nil {
			e.DeniedBodies = map[string]string{}
		}
		if first := e.DeniedBodies[key]; first != "" {
			record.Kind, record.Priority = "filtered", 5
			record.Summary = "Resposta de acesso negado idêntica; expansão duplicada suspensa"
			record.Evidence["representative_url"] = first
			return true
		}
		e.DeniedBodies[key] = t.URL
	}
	return false
}
