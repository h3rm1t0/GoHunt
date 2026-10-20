package monitoramento

import (
	"GoHunt/Modelo"
	"GoHunt/Util"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
)

// All terminal output passes through this logger, including the HTTP server.
// Control characters from remote content cannot create misleading terminal lines.
type Console struct {
	entryGroups  map[string]bool
	mu           sync.Mutex
	out          io.Writer
	Color        bool `json:"-"`
	debug        bool
	phase        string
	started      time.Time
	lastProgress time.Time
	lastSnapshot [4]int
}

func PrintBanner(out io.Writer, banner string) {
	if terminalColor(out) {
		fmt.Fprint(out, "\x1b[1;36m")
		defer fmt.Fprint(out, "\x1b[0m")
	}
	fmt.Fprintln(out, banner)
}

func (c *Console) Begin(t modelo.Task, completed, total int) {
	phase := TaskPhase(t)
	if phase != c.phase {
		c.phase = phase
		c.Log("FASE", "%s", phase)
		c.Log("ALVO", "%s | %s", t.URL, TaskLabel(t))
	}
	c.Detail("Iniciando %s | alvo=%s | profundidade=%d | concluídas=%d | fila=%d", TaskLabel(t), t.URL, t.Depth, completed, total)
}

func DescribeError(err error) string {
	if errors.Is(err, context.Canceled) {
		return "Operação interrompida; estado preservado"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "Tempo limite de resposta excedido"
	}
	if errors.Is(err, os.ErrPermission) {
		return "Sem permissão de acesso ao arquivo ou diretório"
	}
	if errors.Is(err, os.ErrNotExist) {
		return "Arquivo ou diretório não encontrado"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		if dns.IsNotFound {
			return "Nome DNS não encontrado"
		}
		if dns.IsTimeout {
			return "Consulta DNS excedeu o tempo limite"
		}
		return "Não foi possível concluir a consulta DNS"
	}
	var certificate x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &certificate) || errors.As(err, &hostname) || errors.As(err, &invalid) {
		return "Certificado TLS não validado; revisar domínio e configuração HTTPS"
	}
	var syntax *json.SyntaxError
	var jsonType *json.UnmarshalTypeError
	if errors.As(err, &syntax) || errors.As(err, &jsonType) {
		return "Resposta ou arquivo JSON inválido/incompatível"
	}
	var network net.Error
	if errors.As(err, &network) {
		if network.Timeout() {
			return "Conexão ou resposta excedeu o tempo limite"
		}
		return "Falha de conexão; use --debug para consultar o detalhe técnico"
	}
	return err.Error()
}

func (c *Console) Detail(message string, args ...any) {
	if c != nil && c.debug {
		c.Log("DEPURACAO", message, args...)
	}
}

func evidenceLabel(key string) string {
	switch key {
	case "cname_chain":
		return "Cadeia CNAME"
	case "provider":
		return "Provedor associado"
	case "dns_destination_status":
		return "DNS do destino"
	case "http_marker":
		return "Sinal HTTP"
	case "urls_to_check":
		return "URLs para validar"
	case "candidate_url":
		return "URL candidata"
	case "confidence":
		return "Classificação"
	default:
		return key
	}
}

func (c *Console) Findings(records []modelo.Record) {
	for _, r := range records {
		if modelo.IsEntry(r) {
			if c.entryGroups == nil {
				c.entryGroups = map[string]bool{}
			}
			key := modelo.DisplayID(r)
			if c.entryGroups[key] {
				c.Detail("Nova ocorrência de estrutura já apresentada | origem=%s | destino=%s", util.DefaultValue(r.Evidence["observed_on"], r.Source), r.URL)
				continue
			}
			c.entryGroups[key] = true
		}
		if r.Priority <= 2 {
			c.Log("ACHADO", ">>> P%d | %s | %s", r.Priority, recordLabel(r.Kind), r.URL)
			c.Log("EVIDENCIA", "%s", r.Summary)
			for _, key := range []string{"cname_chain", "provider", "dns_destination_status", "http_marker", "urls_to_check", "candidate_url", "confidence"} {
				if value := r.Evidence[key]; value != "" {
					c.Log("EVIDENCIA", "%s: %s", evidenceLabel(key), value)
				}
			}
		} else if r.Kind == "form" || r.Kind == "inputs" || r.Kind == "extraction" || r.Kind == "takeover-candidate" || (r.Kind == "endpoint" && (r.Status == 401 || r.Status == 403)) {
			c.Log("MAPEAMENTO", "P%d | %s | %s | %s", r.Priority, recordLabel(r.Kind), r.URL, r.Summary)
		} else if r.Kind == "source" {
			c.Log("COLETA", "%s | alvo=%s | %s", r.Source, r.URL, r.Summary)
		} else {
			c.Detail("Registro P%d | %s | %s | %s", r.Priority, recordLabel(r.Kind), r.URL, r.Summary)
		}
	}
}

func LevelColor(level string) string {
	switch level {
	case "DEPURACAO":
		return "90"
	case "PENDENTE":
		return "91"
	case "ESTIMATIVA":
		return "95"
	case "ACHADO":
		return "1;93"
	case "EVIDENCIA":
		return "94"
	case "FASE":
		return "1;96"
	case "ALVO":
		return "36"
	case "PROGRESSO", "ETAPA":
		return "92"
	case "AVISO", "AGUARDANDO":
		return "33"
	case "INICIO", "FINAL", "RESUMO":
		return "1;32"
	case "CONFIG", "ESTADO", "HISTORICO":
		return "34"
	case "PAINEL", "ARQUIVO":
		return "35"
	case "MAPEAMENTO", "COLETA":
		return "96"
	case "PRIORIDADE":
		return "93"
	default:
		return "37"
	}
}

func (c *Console) Log(level, message string, args ...any) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	messageText := terminalText(fmt.Sprintf(message, args...))
	if c.Color {
		fmt.Fprintf(c.out, "\x1b[36m%s\x1b[0m | \x1b[%sm%-10s\x1b[0m | \x1b[97m%s\x1b[0m\n", time.Now().Format("2006-01-02 15:04:05"), LevelColor(level), level, messageText)
	} else {
		fmt.Fprintf(c.out, "%s | %-10s | %s\n", time.Now().Format("2006-01-02 15:04:05"), level, messageText)
	}
}

func NewConsole(out io.Writer, debug bool) *Console {
	return &Console{out: out, debug: debug, Color: terminalColor(out), started: time.Now()}
}

func (c *Console) Progress(completed, total, failed, records int, force bool) {
	snapshot := [4]int{completed, total, failed, records}
	if force && !c.lastProgress.IsZero() && snapshot == c.lastSnapshot {
		return
	}
	if !force && !c.lastProgress.IsZero() && completed%25 != 0 && time.Since(c.lastProgress) < 15*time.Second {
		return
	}
	c.lastProgress = time.Now()
	c.lastSnapshot = snapshot
	c.Log("PROGRESSO", "Concluídas: %d | Pendentes: %d | Fila total: %d | Falhas nesta rodada: %d | Registros: %d | Tempo: %s", completed, total-completed, total, failed, records, time.Since(c.started).Round(time.Second))
}

func recordLabel(kind string) string {
	switch kind {
	case "takeover-candidate":
		return "Candidato a subdomain takeover"
	case "takeover-observation":
		return "Observação DNS/HTTP para takeover"
	case "bypass-candidate":
		return "Candidato a bypass de autorização"
	case "template-candidate":
		return "Candidato encontrado por template"
	case "technology":
		return "Tecnologia observada"
	case "parameters":
		return "Parâmetros históricos"
	case "form":
		return "Formulário"
	case "inputs":
		return "Campos de entrada"
	case "extraction":
		return "Extração heurística"
	case "endpoint":
		return "Endpoint"
	case "dns":
		return "Registro DNS"
	case "discovery":
		return "Descoberta pública"
	case "source":
		return "Fonte pública"
	case "filtered":
		return "Resposta filtrada"
	case "error":
		return "Tarefa pendente"
	case "limit":
		return "Limite de coleta"
	default:
		return kind
	}
}

func TaskLabel(t modelo.Task) string {
	switch t.Kind {
	case "source":
		return "consulta à fonte " + t.Source
	case "takeover":
		return "triagem de takeover"
	case "dns":
		return "resolução DNS"
	case "wordlist":
		return "leitura de wordlist"
	case "page":
		return "mapeamento de página"
	case "brute":
		return "enumeração de caminho"
	case "bypass":
		return "teste de autorização"
	case "template":
		return "template " + t.Source
	default:
		return "preparação"
	}
}

func TaskPhase(t modelo.Task) string {
	switch t.Kind {
	case "source":
		return "Reconhecimento passivo: consulta a fontes públicas"
	case "takeover":
		return "Triagem de subdomain takeover: evidências DNS e HTTP"
	case "dns":
		return "Reconhecimento DNS: subdomínios da wordlist"
	case "wordlist":
		switch t.Source {
		case "sub":
			return "Leitura da wordlist de subdomínios"
		case "dir":
			return "Leitura da wordlist de diretórios"
		default:
			return "Leitura da wordlist de arquivos"
		}
	case "page":
		return "Reconhecimento ativo: páginas, tecnologias e entradas de dados"
	case "brute":
		return "Enumeração de diretórios e arquivos: verificação de respostas"
	case "bypass":
		return "Validação de candidatos a bypass de autorização"
	case "cve":
		return "Correlação e verificação dirigida de CVEs"
	case "osv":
		return "Consulta de dependências no OSV"
	case "template":
		return "Verificação de vulnerabilidades pelos templates selecionados"
	default:
		return "Preparação da varredura"
	}
}

func terminalColor(out io.Writer) bool {
	if _, disabled := os.LookupEnv("NO_COLOR"); disabled || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := out.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func terminalText(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	if len([]rune(s)) > 800 {
		s = string([]rune(s)[:800]) + "..."
	}
	return s
}
