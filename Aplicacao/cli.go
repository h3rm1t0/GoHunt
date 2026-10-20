package aplicacao

import (
	"GoHunt/Configuracao"
	"GoHunt/Estado"
	"GoHunt/Painel"
	"GoHunt/Util"
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func CLI(ctx context.Context, args []string, out io.Writer) error {
	c := configuracao.Config{}
	fs := flag.NewFlagSet("gohunt", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() {
		fmt.Fprintln(out, "Uso: GoHunt [opções]")
		fmt.Fprintln(out, "Coleta com painel HTTP, estado persistente e triagem de vulnerabilidades.")
		var help bytes.Buffer
		previous := fs.Output()
		fs.SetOutput(&help)
		fs.PrintDefaults()
		fs.SetOutput(previous)
		text := strings.ReplaceAll(help.String(), "(default ", "(padrão ")
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "  -") {
				fields := strings.Fields(line)
				if len(fields) > 0 && len(strings.TrimPrefix(fields[0], "-")) > 1 {
					line = strings.Replace(line, "  -", "  --", 1)
				}
			}
			fmt.Fprintln(out, line)
		}
		fmt.Fprintln(out, "  -h, --help: mostrar ajuda")
	}
	fs.StringVar(&c.Scope, "scope", "escopo.txt", "Escopo: hosts exatos, URLs ou *.dominio")
	fs.StringVar(&c.State, "state", "", "Estado; padrão: output/AAAA-MM-DD/<escopo>/state.jsonl")
	fs.StringVar(&c.History, "history", "", "Estados JSONL anteriores separados por vírgula; suprimir achados já reportados (P1 a P3)")
	fs.BoolVar(&c.Resume, "resume", false, "Retomar execução compatível existente")
	fs.DurationVar(&c.JitterMin, "jitter-min", 300*time.Millisecond, "Espera mínima antes de cada requisição HTTP/DNS")
	fs.DurationVar(&c.JitterMax, "jitter-max", 800*time.Millisecond, "Espera máxima antes de cada requisição HTTP/DNS")
	fs.DurationVar(&c.Timeout, "timeout", 15*time.Second, "Timeout de cada requisição")
	fs.StringVar(&c.DirWords, "wordlist-dirs", "", "Wordlist opcional de diretórios")
	fs.StringVar(&c.FileWords, "wordlist-files", "", "Wordlist opcional de arquivos")
	fs.StringVar(&c.SubWords, "wordlist-subs", "", "Wordlist opcional de subdomínios")
	fs.StringVar(&c.Sources, "sources", "crtsh,otx,wayback,commoncrawl", "Fontes separadas por vírgula; vazio desativa")
	fs.StringVar(&c.CrawlMode, "crawl-mode", "balanced", "Mapeamento: reduced (leve), balanced (padrão), deep (mais tráfego/tempo; sem executar JavaScript)")
	fs.IntVar(&c.MaxPagesPerHost, "max-pages-per-host", 0, "Máximo de páginas por hostname; 0 usa perfil: reduced=25, balanced=200, deep=2000")
	fs.IntVar(&c.Depth, "depth", 2, "Profundidade máxima do crawler")
	fs.IntVar(&c.MaxTasks, "max-tasks", 100000, "Máximo de tarefas persistidas; aumente para retomar ao atingir limite")
	fs.Int64Var(&c.MaxBody, "max-body", 2<<20, "Limite de bytes por resposta")
	fs.IntVar(&c.SourceLimit, "source-limit", 1000, "Máximo de entradas por consulta OSINT")
	fs.BoolVar(&c.FormGET, "crawl-forms", false, "Explorar formulários GET com os valores fornecidos")
	fs.StringVar(&c.FormValues, "form-values", "", "JSON com valores de campos para formulários GET")
	fs.StringVar(&c.CVEVerifiers, "cve-verifiers", "", "IDs explícitos separados por vírgula; disponível: joomla-public-users-v1; requer cve-mode verify")
	fs.StringVar(&c.CVEMode, "cve-mode", "passive", "CVEs: off, passive (correlação local), verify (verificadores revisados; até 5 GETs por instalação/CVE)")
	fs.StringVar(&c.CVEDB, "cve-db", "", "Catálogo revisado JSON; vazio usa catálogo incorporado; não aceita templates Nuclei")
	fs.StringVar(&c.Components, "components", "", "Inventário JSON com URL, produto/pacote, versão e evidência")
	fs.BoolVar(&c.OSV, "osv", false, "Consultar OSV para pacotes do inventário; envia nome/ecossistema/versão, sem URL do alvo; cache 24h")
	fs.BoolVar(&c.AllowLegacyTemplates, "allow-legacy-templates", false, "Habilitar formato antigo sem garantias de equivalência ao Nuclei; resultados apenas informativos")
	fs.StringVar(&c.Templates, "templates", "", "JSON legado: exige --allow-legacy-templates; prefira --cve-db")
	fs.StringVar(&c.Listen, "listen", "127.0.0.1:8080", "Painel iniciado antes da coleta; vazio desativa; permanece aberto até Ctrl+C")
	fs.BoolVar(&c.Debug, "debug", false, "Exibir detalhes de tarefas, requisições, respostas e novas tentativas")
	var serve string
	fs.StringVar(&serve, "serve", "", "Servir resultados existentes, ex.: 127.0.0.1:8080; não inicia scan")
	// Aliases share the same flag.Value, including boolean semantics.
	for short, long := range map[string]string{"s": "scope", "o": "state", "r": "resume", "t": "timeout", "d": "depth", "l": "listen", "v": "debug", "h": "help"} {
		if f := fs.Lookup(long); f != nil {
			fs.Var(f.Value, short, "Alias de --"+long)
		}
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if c.CVEMode != "off" && c.CVEMode != "passive" && c.CVEMode != "verify" {
		return errors.New("cve-mode deve ser off, passive ou verify")
	}
	if c.CVEMode == "off" && (c.OSV || c.Components != "" || c.CVEDB != "") {
		return errors.New("cve-mode off não aceita inventário, catálogo ou OSV")
	}
	if c.Templates != "" && !c.AllowLegacyTemplates {
		return errors.New("conversões antigas exigem --allow-legacy-templates; use o catálogo --cve-db para análise rastreável")
	}
	if c.OSV && c.Components == "" {
		return errors.New("--osv exige --components com identidade, versão e evidência dos pacotes")
	}
	if err := configuracao.ValidateVerifiers(c); err != nil {
		return err
	}
	depthSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "depth" || f.Name == "d" {
			depthSet = true
		}
	})
	switch c.CrawlMode {
	case "balanced":
		c.CrawlMode = ""
	case "reduced":
		if !depthSet {
			c.Depth = 1
		}
	case "deep":
		if !depthSet {
			c.Depth = 5
		}
	default:
		return errors.New("crawl-mode deve ser reduced, balanced ou deep")
	}
	if c.MaxPagesPerHost < 0 || c.MaxPagesPerHost > 100000 {
		return errors.New("max-pages-per-host deve ser 0..100000")
	}
	if fs.NArg() != 0 {
		return errors.New("argumentos posicionais não são aceitos")
	}
	if c.Listen != "" {
		if err := painel.ValidatePanelAddress(c.Listen); err != nil {
			return err
		}
	}
	if c.State == "" {
		scopeBytes, err := os.ReadFile(c.Scope)
		if err != nil {
			return err
		}
		c.State = filepath.Join("output", time.Now().Format("2006-01-02"), util.Digest(string(scopeBytes))[:16], "state.jsonl")
	}
	if serve != "" {
		return painel.Serve(ctx, serve, c.State, out)
	}
	if c.JitterMin < 0 || c.JitterMax < c.JitterMin || c.JitterMax > time.Hour || c.Timeout <= 0 || c.Depth < 0 || c.Depth > 20 || c.MaxTasks < 1 || c.MaxBody < 1024 || c.MaxBody > 16<<20 || c.SourceLimit < 1 || c.SourceLimit > 10000 {
		return errors.New("limites inválidos: jitter 0..1h, timeout positivo, depth 0..20, max-body 1KiB..16MiB, source-limit 1..10000")
	}
	for _, s := range util.SplitSources(c.Sources) {
		if s != "crtsh" && s != "otx" && s != "wayback" && s != "commoncrawl" {
			return fmt.Errorf("fonte desconhecida: %s", s)
		}
	}
	if !c.Resume {
		if _, err := os.Stat(c.State); err == nil {
			proceed, err := ConfirmPending(c, os.Stdin, out)
			if err != nil {
				return err
			}
			if !proceed {
				return nil
			}
			c.Resume = true
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return Run(ctx, c, out)
}

// Inspection uses the journal lock and never sends network requests.
func ConfirmPending(c configuracao.Config, in io.Reader, out io.Writer) (bool, error) {
	fp, err := configuracao.Fingerprint(c)
	if err != nil {
		return false, err
	}
	s, err := estado.OpenStore(c.State, fp, true)
	if err != nil {
		return false, err
	}
	completed, pending := s.Completed, s.Count-s.Completed
	s.Close()
	fmt.Fprintf(out, "Histórico: %d tarefas concluídas; %d pendentes. Estado: %s\n", completed, pending, c.State)
	if pending == 0 && completed > 0 {
		fmt.Fprintln(out, "Scan já concluído; nenhuma consulta será repetida.")
		return false, nil
	}
	fmt.Fprint(out, "Executar consultas pendentes e novas descobertas, sem repetir tarefas concluídas? [s/N]: ")
	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		return false, scanner.Err()
	}
	answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
	return answer == "s" || answer == "sim" || answer == "y" || answer == "yes", nil
}
