package ativo

import (
	origbypass "GoHunt/Bypass/Regras"
	"GoHunt/Escopo"
	"GoHunt/Extractor"
	origextractor "GoHunt/Extractor/Padroes"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"GoHunt/Rede"
	"GoHunt/Tecnologias"
	"GoHunt/Util"
	origvuln "GoHunt/Vuln/Templates"
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

func Page(e *nucleo.Engine, ctx context.Context, t modelo.Task) ([]modelo.Task, []modelo.Record, error) {
	resp, err := rede.Request(e, ctx, t.URL, "GET", nil, "", false)
	if err != nil {
		return nil, nil, err
	}
	record := modelo.Record{Kind: "endpoint", URL: t.URL, Priority: 4, Status: resp.Status, Source: t.Source, Summary: "Endpoint observado", Evidence: map[string]string{"body_sha256": util.Digest(string(resp.Body)), "content_type": resp.Header.Get("Content-Type")}}
	technologyRecords, techs := tecnologias.TechnologyRecords(e, t, resp)
	record.Evidence["technologies"] = strings.Join(techs, ", ")
	if FilterPage(e, t, resp, &record) {
		return nil, append([]modelo.Record{record}, technologyRecords...), nil
	}
	if resp.Status == 404 || resp.Status == 410 {
		record.Kind, record.Priority = "filtered", 5
		record.Summary = "Rota indisponível no alvo atual"
		record.Evidence["validation"] = "HTTP 404/410"
		return nil, append([]modelo.Record{record}, technologyRecords...), nil
	}
	if modelo.Historical(t) && t.URL != escopo.Origin(t.URL) && resp.Status >= 200 && resp.Status < 300 {
		filtered, validationErr := ValidateHistorical(e, ctx, t, resp, &record)
		if validationErr != nil {
			return nil, append([]modelo.Record{record}, technologyRecords...), validationErr
		}
		if filtered {
			return []modelo.Task{{Kind: "page", URL: escopo.Origin(t.URL), Source: "origin"}}, append([]modelo.Record{record}, technologyRecords...), nil
		}
	}
	var tasks []modelo.Task
	records := append([]modelo.Record{record}, technologyRecords...)
	if resp.Status == 401 || resp.Status == 403 {
		records[0].Priority = 3
		records[0].Summary = "Recurso com controle de acesso; validar autorização"
		keys := make([]string, 0, len(origbypass.HeadersBypass))
		for key := range origbypass.HeadersBypass {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			tasks = append(tasks, modelo.Task{Kind: "bypass", URL: t.URL, Source: key, Path: t.URL})
		}
		u, _ := url.Parse(t.URL)
		for _, pre := range origbypass.PrefixosBypass {
			for _, suf := range origbypass.SufixosBypass {
				candidate := strings.TrimSuffix(escopo.Origin(t.URL), "/") + pre + strings.TrimPrefix(u.EscapedPath(), "/") + suf
				if candidate != t.URL {
					if _, err := url.Parse(candidate); err == nil {
						tasks = append(tasks, modelo.Task{Kind: "bypass", URL: t.URL, Path: candidate, Source: "path"})
					}
				}
			}
		}
	}
	if resp.Status >= 300 && resp.Status < 400 {
		u, _ := url.Parse(t.URL)
		r, err := url.Parse(resp.Header.Get("Location"))
		if err == nil && resp.Header.Get("Location") != "" {
			dest, _ := escopo.Normalize(u.ResolveReference(r).String())
			records[0].Evidence["redirect"] = dest
			if e.Scope.Allows(dest) && t.Depth < e.Config.Depth {
				tasks = append(tasks, modelo.Task{Kind: "page", URL: dest, Depth: t.Depth + 1, Source: "redirect"})
			}
		}
		return tasks, records, nil
	}
	if resp.Status < 200 || resp.Status >= 300 {
		return tasks, records, nil
	}
	moreCVE, componentRecords := tecnologias.ObservedComponents(e, t, resp)
	tasks = append(tasks, moreCVE...)
	records = append(records, componentRecords...)
	base := escopo.Origin(t.URL)
	if t.URL == base {
		if e.Config.DirWords != "" {
			tasks = append(tasks, modelo.Task{Kind: "wordlist", URL: base, Source: "dir", Path: e.Config.DirWords})
		}
		if e.Config.FileWords != "" {
			tasks = append(tasks, modelo.Task{Kind: "wordlist", URL: base, Source: "file", Path: e.Config.FileWords})
		}
		for i, tpl := range e.Templates {
			if origvuln.Eligible(techs, tpl.TecnologiasAlvo) {
				for _, path := range tpl.Requisicao.Caminhos {
					tasks = append(tasks, modelo.Task{Kind: "template", URL: base, Offset: int64(i), Path: path, Source: tpl.ID})
				}
			}
		}
	} else {
		tasks = append(tasks, modelo.Task{Kind: "page", URL: base, Source: "origin"})
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "html") {
		more, forms := extractor.Extract(e, t, resp.Body)
		tasks = append(tasks, more...)
		records = append(records, forms...)
	}
	// Reuse the project's existing extractors, without creating per-response files or exporting secrets.
	keys := make([]string, 0, len(origextractor.RegexSegredos))
	for name := range origextractor.RegexSegredos {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		matches := origextractor.RegexSegredos[name].FindAll(resp.Body, 20)
		if len(matches) > 0 {
			records = append(records, modelo.Record{Kind: "extraction", URL: t.URL, Priority: 3, Summary: name + " — correspondência heurística; validar manualmente", Evidence: map[string]string{"matches": fmt.Sprint(len(matches)), "sample_sha256": util.Digest(string(matches[0]))}})
		}
	}
	return tasks, records, nil
}
