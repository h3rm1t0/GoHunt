package aplicacao

import (
	"GoHunt/Ativo"
	"GoHunt/Bypass"
	"GoHunt/Configuracao"
	"GoHunt/Db"
	"GoHunt/Escopo"
	"GoHunt/Estado"
	"GoHunt/Fuzzing"
	"GoHunt/Modelo"
	"GoHunt/Monitoramento"
	"GoHunt/Nucleo"
	"GoHunt/Painel"
	"GoHunt/Passivo"
	"GoHunt/Takeover"
	"GoHunt/Util"
	"GoHunt/Vuln"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"io"
	"net/http"
	"os"
	"time"
)

func Run(ctx context.Context, c configuracao.Config, out io.Writer) error {
	if err := configuracao.ValidateVerifiers(c); err != nil {
		return err
	}
	console := monitoramento.NewConsole(out, c.Debug)
	console.Log("INICIO", "Inicializando GoHunt | escopo=%s | estado=%s", c.Scope, c.State)
	scope, err := escopo.LoadScope(c.Scope)
	if err != nil {
		return err
	}
	fp, err := configuracao.Fingerprint(c)
	if err != nil {
		return err
	}
	e := &nucleo.Engine{Config: c, Scope: scope, Forms: map[string]string{}, Log: console}
	e.Client = &http.Client{Timeout: c.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer e.Client.CloseIdleConnections()
	e.Wapp, err = wappalyzer.New()
	if err != nil {
		return err
	}
	if c.CVEMode != "" && c.CVEMode != "off" {
		e.Catalog, err = db.LoadCatalog(c.CVEDB)
		if err != nil {
			return err
		}
		e.Components, err = db.LoadComponents(c.Components, scope)
		if err != nil {
			return err
		}
		console.Log("CONFIG", "CVEs: modo=%s | catálogo revisado em %s | %d avisos | correlação não é confirmação", c.CVEMode, e.Catalog.Reviewed, len(e.Catalog.Advisories))
		if c.CVEMode == "verify" {
			console.Log("AVISO", "Verificadores ativos dirigidos: até 5 GETs por instalação/CVE elegível; podem ler uma entrada de usuário, sem persistir dados pessoais")
		}
	}
	if c.FormValues != "" {
		b, x := os.ReadFile(c.FormValues)
		if x != nil {
			return x
		}
		if x = json.Unmarshal(b, &e.Forms); x != nil {
			return x
		}
	}
	if c.Templates != "" {
		if !c.AllowLegacyTemplates {
			return errors.New("templates legados exigem autorização por --allow-legacy-templates")
		}
		console.Log("AVISO", "Templates legados: resultados informativos, sem confirmação de CVE")
		b, x := os.ReadFile(c.Templates)
		if x != nil {
			return x
		}
		if x = json.Unmarshal(b, &e.Templates); x != nil {
			return x
		}
	}
	store, err := estado.OpenStore(c.State, fp, c.Resume)
	if err != nil {
		return err
	}
	defer store.Close()
	for _, previous := range util.SplitSources(c.History) {
		count := 0
		if err := estado.WalkRecords(previous, func(r modelo.Record) {
			if r.Priority >= 1 && r.Priority <= 3 {
				id := modelo.RecordID(r)
				if !store.RecordKeys[id] {
					store.RecordKeys[id] = true
					count++
				}
			}
		}); err != nil {
			return fmt.Errorf("histórico %s: %w", previous, err)
		}
		console.Log("HISTORICO", "%d assinaturas de achados anteriores carregadas de %s", count, previous)
	}
	e.DeniedBodies = map[string]string{}
	if err := estado.WalkRecords(c.State, func(r modelo.Record) {
		if r.Kind == "endpoint" && (r.Status == 401 || r.Status == 403) && r.Evidence["body_sha256"] != "" {
			key := escopo.Origin(r.URL) + fmt.Sprint(r.Status) + r.Evidence["content_type"] + r.Evidence["body_sha256"]
			e.DeniedBodies[key] = r.URL
		}
	}); err != nil {
		return err
	}

	runtime := &monitoramento.Runtime{}
	runtime.Update("preparando", "Inicialização do painel e da fila", "", false, store, 0)
	var panel *painel.PanelServer
	if c.Listen != "" {
		panel, err = painel.StartPanel(c.Listen, c.State, runtime)
		if err != nil {
			return err
		}
		defer panel.Close()
		console.Log("PAINEL", "Servidor HTTP iniciado antes da coleta: %s", panel.URL())
	}
	scanCtx, cancelScan := context.WithCancel(ctx)
	defer cancelScan()
	if panel != nil {
		go func() {
			select {
			case <-panel.Exited:
				cancelScan()
			case <-scanCtx.Done():
			}
		}()
	}
	stopHeartbeat := make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopHeartbeat:
				return
			case <-ticker.C:
				info := runtime.Snapshot()
				if info.Running {
					console.Log("AGUARDANDO", "Fase: %s | Alvo: %s | Concluídas: %d | Pendentes: %d", info.Phase, info.Target, info.Completed, info.Pending)
					console.Log("ESTIMATIVA", "%s", info.Timing)
				}
			}
		}
	}()
	scanErr := Scan(e, scanCtx, store, runtime)
	close(stopHeartbeat)
	cancelScan()
	if panel != nil {
		select {
		case <-panel.Exited:
			if panel.Err != nil {
				return fmt.Errorf("servidor do painel encerrou inesperadamente: %w", panel.Err)
			}
		default:
		}
	}
	state := "concluido"
	phase := "Coleta concluída"
	if scanErr != nil {
		state = "pendencias"
		phase = "Coleta encerrada com tarefas pendentes"
		console.Log("AVISO", "%v", scanErr)
	}
	if ctx.Err() != nil {
		state = "interrompido"
		phase = "Coleta interrompida; estado preservado"
	}
	runtime.Update(state, phase, "", false, store, runtime.Snapshot().Failures)
	if panel == nil || ctx.Err() != nil {
		return scanErr
	}
	console.Log("PAINEL", "%s | Resultados disponíveis em %s | Ctrl+C encerra o servidor", phase, panel.URL())
	select {
	case <-ctx.Done():
		console.Log("FINAL", "Encerrando o servidor HTTP; estado preservado")
		return scanErr
	case <-panel.Exited:
		return panel.Err
	}
}

func Execute(e *nucleo.Engine, ctx context.Context, t modelo.Task) ([]modelo.Task, []modelo.Record, error) {
	switch t.Kind {
	case "cve":
		return vuln.AssessCVE(e, ctx, t)
	case "osv":
		return vuln.AssessOSV(e, ctx, t)
	case "takeover":
		return takeover.Takeover(e, ctx, t)
	case "source":
		return passivo.Source(e, ctx, t)
	case "dns":
		return passivo.Dns(e, ctx, t)
	case "wordlist":
		return fuzzing.Wordlist(e, t)
	case "page":
		return ativo.Page(e, ctx, t)
	case "brute":
		return fuzzing.Brute(e, ctx, t)
	case "bypass":
		return bypass.Bypass(e, ctx, t)
	case "template":
		return vuln.Template(e, ctx, t)
	}
	return nil, nil, fmt.Errorf("tipo de tarefa desconhecido: %s", t.Kind)
}

func Scan(e *nucleo.Engine, ctx context.Context, store *estado.Store, runtime *monitoramento.Runtime) error {
	var err error
	failures := 0
	defer func() {
		e.Log.Progress(store.Completed, store.Count, failures, store.RecordCount, true)
		e.Log.Log("RESUMO", "Registros por prioridade: P1=%d | P2=%d | P3=%d | P4=%d | P5=%d", store.RecordCounts[1], store.RecordCounts[2], store.RecordCounts[3], store.RecordCounts[4], store.RecordCounts[5])
		e.Log.Log("ARQUIVO", "Resultados e estado salvos em %s", e.Config.State)
	}()
	if len(store.Tasks) == 0 {
		var initial []modelo.Task
		for _, component := range e.Components {
			initial = append(initial, vuln.ComponentTasks(e, component)...)
		}
		for _, raw := range e.Scope.URLs {
			initial = append(initial, modelo.Task{Kind: "page", URL: raw, Source: "scope"})
		}
		for _, seed := range e.Scope.Seeds {
			for _, source := range util.SplitSources(e.Config.Sources) {
				initial = append(initial, modelo.Task{Kind: "source", URL: seed, Source: source})
			}
			if e.Config.SubWords != "" {
				initial = append(initial, modelo.Task{Kind: "wordlist", URL: seed, Source: "sub", Path: e.Config.SubWords})
			}
		}
		if len(initial) == 0 {
			return errors.New("nenhuma tarefa: escopo apenas curinga requer fontes ou wordlist de subdomínios")
		}
		initial, initialRecords := ativo.SchedulePages(e, store, initial, nil)
		for _, c := range e.Components {
			initialRecords = append(initialRecords, modelo.ComponentRecord(c))
		}
		if err = store.Commit(modelo.Task{Kind: "init"}, takeover.WithTakeover(e.Scope, initial), initialRecords, e.Config.MaxTasks); err != nil {
			return err
		}
	}
	// Older states gain independent takeover tasks without changing their input fingerprint.
	extra := takeover.TakeoverTasks(e.Scope, store.Tasks)
	fresh := false
	for _, task := range extra {
		if !store.Known[task.ID()] {
			fresh = true
			break
		}
	}
	if fresh {
		before := store.Count
		if err := store.Commit(modelo.Task{Kind: "takeover-upgrade"}, extra, nil, e.Config.MaxTasks); err != nil {
			return err
		}
		e.Log.Log("ESTADO", "Agendadas %d novas tarefas de triagem de takeover", store.Count-before)
	}
	runtime.Update("coletando", "Preparação da fila", "", true, store, failures)
	e.Log.Log("CONFIG", "Sementes: %d | Fontes: %s | Profundidade: %d | Jitter: %s a %s | Timeout: %s", len(e.Scope.Seeds), util.DefaultValue(e.Config.Sources, "desativadas"), e.Config.Depth, e.Config.JitterMin, e.Config.JitterMax, e.Config.Timeout)
	e.Log.Log("ESTADO", "Concluídas anteriormente: %d | Pendentes: %d | Registros preservados: %d", store.Completed, store.Count-store.Completed, store.RecordCount)
	e.Log.Log("CONFIG", "Modo de mapeamento: %s | páginas/host: %d | links/página: %d", util.DefaultValue(e.Config.CrawlMode, "balanced"), e.Config.PageBudget(), e.Config.LinkBudget())
	if e.Config.CrawlMode == "deep" {
		e.Log.Log("AVISO", "Modo aprofundado: mais requisições, tempo, armazenamento e possibilidade de bloqueios; sem execução de JavaScript ou envio automático de POST")
	}
	e.Log.Log("PRIORIDADE", "P1: candidatos de impacto alto | P2: candidatos a vulnerabilidade/takeover | P3: entradas e indícios | P4/P5: endpoints e inventário")
	checkedRoutes := map[string]bool{}
	for _, task := range store.Tasks {
		if modelo.Historical(task) && store.Done[task.ID()] {
			checkedRoutes[escopo.RouteKey(task.URL)] = true
		}
	}
	for i := 0; i < len(store.Tasks); i++ {
		t := store.Tasks[i]
		if store.Done[t.ID()] {
			continue
		}
		if err = ctx.Err(); err != nil {
			return fmt.Errorf("interrompido; retome com --resume: %w", err)
		}
		if modelo.Historical(t) && checkedRoutes[escopo.RouteKey(t.URL)] {
			if err = store.Commit(t, nil, nil, e.Config.MaxTasks); err != nil {
				return err
			}
			e.Log.Detail("Variante histórica já representada; tarefa agrupada | %s", t.URL)
			continue
		}
		e.Log.Begin(t, store.Completed, store.Count)
		runtime.Update("coletando", monitoramento.TaskPhase(t), t.URL, true, store, failures)
		runtime.StartTask(t.Kind)
		startedTask := time.Now()
		children, records, runErr := Execute(e, ctx, t)
		runtime.Observe(t.Kind, time.Since(startedTask))
		if runErr != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("interrompido; tarefa preservada: %w", ctx.Err())
			}
			failures++
			errorRecord := modelo.Record{Kind: "error", URL: t.URL, Priority: 5, Source: t.Kind + ":" + t.Source, Summary: "Tarefa pendente: " + runErr.Error()}
			if err = store.Append(estado.Event{Records: append(records, errorRecord)}); err != nil {
				return err
			}
			e.Log.Log("PENDENTE", "%s | alvo=%s | motivo=%s | tarefa preservada para --resume", monitoramento.TaskLabel(t), t.URL, monitoramento.DescribeError(runErr))
			e.Log.Detail("Detalhe técnico da falha | alvo=%s | erro=%v", t.URL, runErr)
			runtime.Update("coletando", monitoramento.TaskPhase(t), t.URL, true, store, failures)
			continue
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		children, records = ativo.SchedulePages(e, store, children, records)
		freshRecords := store.UniqueRecords(records)
		if err = store.Commit(t, takeover.WithTakeover(e.Scope, children), records, e.Config.MaxTasks); err != nil {
			return err
		}
		if modelo.Historical(t) {
			checkedRoutes[escopo.RouteKey(t.URL)] = true
		}
		e.Log.Findings(freshRecords)
		e.Log.Detail("Concluído %s | alvo=%s | registros=%d | próximas tarefas propostas=%d", monitoramento.TaskLabel(t), t.URL, len(records), len(children))
		runtime.Update("coletando", monitoramento.TaskPhase(t), t.URL, true, store, failures)
		e.Log.Progress(store.Completed, store.Count, failures, store.RecordCount, false)
		info := runtime.Snapshot()
		e.Log.Log("ESTIMATIVA", "%s", info.Timing)
		if stage, ok := info.Stages[t.Kind]; ok {
			e.Log.Log("ETAPA", "%s | %.1f%% | %d/%d | restante ~%s", monitoramento.TaskLabel(t), stage.Percent, stage.Completed, stage.Total, stage.Remaining)
		}
	}
	if failures > 0 {
		return fmt.Errorf("%d tarefas falharam e permanecem pendentes para --resume", failures)
	}
	return nil
}
