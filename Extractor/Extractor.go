package extractor

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var tempo string

func telegram(mensagem string) {
	var telegram_key string = "<INSIRA_SUA_CHAVE_API_DO_TELEGRAM_AQUI>"
	var chat_id string = "<INSIRA_ID_DO_SEU_CHAT_TELEGRAM_AQUI>"
	ritmo := time.NewTicker(time.Millisecond / time.Duration(2500))
	defer ritmo.Stop()

	api_url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", telegram_key)

	dados := url.Values{}
	dados.Set("chat_id", chat_id)
	dados.Set("text", mensagem)
	dados.Set("parse_mode", "Markdown")

	<-ritmo.C
	resp, err := http.PostForm(api_url, dados)
	if err != nil {
		fmt.Printf(momento(tempo)+" - [ERRO] Falha ao conectar na API do Telegram: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Printf("%s", momento(tempo)+" - [INFO] Notificação enviada para o celular com sucesso!\n")
	} else {
		fmt.Printf(momento(tempo)+" - [ERRO] Telegram retornou status HTTP %d\n", resp.StatusCode)
	}

}

type ResultadoRegex struct {
	Alvo      string   `json:"alvo"`
	Vazamento []string `json:"vazamentos"`
	Tipo      string   `json:"tipo_segredo"`
	Arquivo   string   `json:"arquivo_local"`
	Timestamp string   `json:"timestamp"`
}

var muRegex sync.Mutex

func carregarEstado(caminhoEstado string) map[string]bool {
	estado := make(map[string]bool)
	arquivo, err := os.Open(caminhoEstado)
	if err != nil {
		return estado 
	}
	defer arquivo.Close()

	scanner := bufio.NewScanner(arquivo)
	for scanner.Scan() {
		estado[strings.TrimSpace(scanner.Text())] = true
	}
	return estado
}

func registrarEstado(caminhoEstado, identificador string) {
	muRegex.Lock()
	defer muRegex.Unlock()
	f, err := os.OpenFile(caminhoEstado, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		f.WriteString(identificador + "\n")
		f.Close()
	}
}

func salvarAchadoRegex(dominio string, resultado ResultadoRegex) {
	pastaFuzzing := filepath.Join("Alvos", dominio, "Fuzzing")
	os.MkdirAll(pastaFuzzing, 0755)
	caminhoResultados := filepath.Join(pastaFuzzing, "resultados_sast.jsonl")

	linhaJSON, _ := json.Marshal(resultado)

	muRegex.Lock()
	defer muRegex.Unlock()
	f, err := os.OpenFile(caminhoResultados, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		f.WriteString(string(linhaJSON) + "\n")
		f.Close()
	}

}

func carregarMapaUrls(caminhoLista string) map[string]string {
	mapa := make(map[string]string)

	arquivo, err := os.Open(caminhoLista)
	if err != nil {
		return mapa
	}
	defer arquivo.Close()

	scanner := bufio.NewScanner(arquivo)
	for scanner.Scan() {
		linha := scanner.Text()
		partes := strings.Split(linha, " -> Arquivo Local: ")
		if len(partes) == 2 {
			urlOriginal := partes[0]
			nomeArquivoMD5 := partes[1]
			mapa[nomeArquivoMD5] = urlOriginal
		}
	}
	return mapa
}

var RegexSegredos = map[string]*regexp.Regexp{
	"AWS Access Key":           regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"AWS Temporário (Session)": regexp.MustCompile(`ASIA[0-9A-Z]{16}`),
	"Google API Key":           regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	"GitHub PAT":               regexp.MustCompile(`(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}`),
	"JWT Token":                regexp.MustCompile(`eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`),
	"Chave Privada":            regexp.MustCompile(`(?s)-----BEGIN [ A-Z]+PRIVATE KEY-----.*?-----END [ A-Z]+PRIVATE KEY-----`),
	"Slack Token":              regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`),
	"Stripe API":               regexp.MustCompile(`(?i)sk_live_[0-9a-zA-Z]{24}`),

	"Potencial IDOR":             regexp.MustCompile(`(?i)(user_id|account_id|router_id|profile_id|order_id)\s*=\s*["']?[0-9a-zA-Z_-]+["']?`),
	"Esquema Custom (Deep Link)": regexp.MustCompile(`(?i)["']((?:[a-z0-9-]+\.)+[a-z0-9-]+:\/\/[^"']+)["']`),
	"jsonpRegex":                 regexp.MustCompile(`(?i)[?&](callback|cb|jsonp|jsonpcallback)=([a-zA-Z0-9_.-]+)`),
	"Pacote Android Interno":     regexp.MustCompile(`(?i)package_name["\s:]+["']?com\.[a-zA-Z0-9_\.]*\.(dev|stg|test|qa|sandbox|internal|beta)["']?`),
	"Credencial de Banco (URI)":  regexp.MustCompile(`(?i)(postgres|mysql|mongodb)://[a-zA-Z0-9_-]+:[^@]+@[a-zA-Z0-9_\.\-]+:[0-9]+`),
	"Android Intent":             regexp.MustCompile(`(?i)["'](intent:\/\/[^"']+)["']`),

	"Firebase Database":   regexp.MustCompile(`(?i)https?://[a-z0-9-]+\.firebaseio\.com`),
	"Bucket S3 Potencial": regexp.MustCompile(`(?i)[a-z0-9-\.]+\.s3\.amazonaws\.com`),

	"Credencial Twilio (SID+Token)": regexp.MustCompile(`(?i)(AC[a-zA-Z0-9]{32})["'\s:,]+([a-zA-Z0-9]{32})`),
	"Chave SendGrid (Email)":        regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`),
	"Chave Mailgun (Email)":         regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),

	"Endpoint GraphQL":       regexp.MustCompile(`(?i)(/graphql|/graphiql|/graphql/console)`),
	"Telegram Bot Token":     regexp.MustCompile(`[0-9]{9,10}:[a-zA-Z0-9_-]{35}`),
	"Discord Webhook":        regexp.MustCompile(`(?i)https:\/\/discord\.com\/api\/webhooks\/[0-9]{17,19}\/[a-zA-Z0-9_-]{68}`),
	"Mercado Pago Token":     regexp.MustCompile(`(?i)(?:TEST|APP_USR)-[0-9]{10,15}-[a-zA-Z0-9]+-[0-9a-zA-Z]{32}-[0-9]{10}`),
	"Braintree Access Token": regexp.MustCompile(`access_token\$production\$[0-9a-zA-Z]+\$[0-9a-zA-Z]{32}`),
}

func MotorRegex(dominio string) {
	fmt.Printf("%s - [INFO] Iniciando varredura profunda de Regex (SAST) para: %s ... \n", momento(tempo), dominio)

	pastaFuzzing := filepath.Join("Alvos", dominio, "Fuzzing")
	pastaRespostas := filepath.Join(pastaFuzzing, "Respostas_Raw")
	caminhoLista := filepath.Join(pastaFuzzing, "alvos_regex.txt")

	mapaUrls := carregarMapaUrls(caminhoLista)

	arquivos, err := os.ReadDir(pastaRespostas)
	if err != nil {
		fmt.Printf("%s - [ERRO] Pasta de respostas raw não encontrada. Nenhuma extração realizada.\n", momento(tempo))
		return
	}

	achados := 0
	var relatorioTelegram []string

	for _, arquivo := range arquivos {
		if arquivo.IsDir() {
			continue
		}

		caminhoCompleto := filepath.Join(pastaRespostas, arquivo.Name())
		conteudo, err := os.ReadFile(caminhoCompleto)
		if err != nil {
			continue
		}

		urlAlvo := mapaUrls[arquivo.Name()]
		if urlAlvo == "" {
			urlAlvo = "Local: " + arquivo.Name()
		}

		for nomeSegredo, expressao := range RegexSegredos {
			matches := expressao.FindAll(conteudo, -1)

			if len(matches) > 0 {
				mapaUnicos := make(map[string]bool)

				for _, vazamento := range matches {
					textoVazado := string(vazamento)

					textoLimpo := textoVazado
					if nomeSegredo == "Esquema Custom (Deep Link)" {
						textoLimpo = strings.Trim(textoLimpo, `"'`) 
					} else if nomeSegredo == "Vazamento JSONP" {
						textoLimpo = strings.TrimLeft(textoLimpo, `?&`) 
					}

					textoLower := strings.ToLower(textoLimpo)
					deveIgnorar := false

					if nomeSegredo == "Esquema Custom (Deep Link)" {
						if strings.HasPrefix(textoLower, "http://") ||
							strings.HasPrefix(textoLower, "https://") ||
							strings.HasPrefix(textoLower, "ws://") ||
							strings.HasPrefix(textoLower, "wss://") ||
							strings.HasPrefix(textoLower, "fb://") ||
							strings.HasPrefix(textoLower, "twitter://") ||
							strings.HasPrefix(textoLower, "mailto:") ||
							strings.Contains(textoLower, "youtube") ||
							strings.Contains(textoLower, "schema.org") ||
							strings.Contains(textoLower, "w3.org") {
							deveIgnorar = true 
						}
					}

					if nomeSegredo == "Endpoint Hardcoded API" {
						if strings.Contains(textoLower, "api.jquery") ||
							strings.Contains(textoLower, "api.github") {
							deveIgnorar = true
						}
					}

					if nomeSegredo == "Vazamento JSONP" {
						if strings.Contains(textoLower, "function") || strings.Contains(textoLower, "jquery") {
							deveIgnorar = true
						}
					}

					if deveIgnorar {
						continue
					}
					if len(textoLimpo) > 60 {
						textoLimpo = textoLimpo[:60] + "...[trunc]"
					}
					mapaUnicos[textoLimpo] = true
				}

				if len(mapaUnicos) > 0 {
					achados += len(mapaUnicos)

					fmt.Printf("%s - \033[31m[%sENCONTRADO]\033[0m Em: %s\n", momento(tempo), nomeSegredo, urlAlvo)

					linhaAlerta := fmt.Sprintf("[OURO] *%s*\n*Alvo:* %s\n", nomeSegredo, urlAlvo)
					for vazamento := range mapaUnicos {
						fmt.Printf("   └── [CHAVE] %s\n", vazamento)
						linhaAlerta += fmt.Sprintf("[CHAVE] `%s`\n", vazamento)
					}
					relatorioTelegram = append(relatorioTelegram, linhaAlerta)
				}
			}
		}
	}

	fmt.Printf("%s - [SUCESSO] SAST concluído. %d evidências encontradas.\n", momento(tempo), achados)

	if len(relatorioTelegram) > 0 {
		mensagemFinal := fmt.Sprintf("[CHECK-POINT] Varredura no domínio *%s* finalizada.Total de Exposição: %d", dominio, achados)
		telegram(mensagemFinal)

		for _, alerta := range relatorioTelegram {
			telegram(alerta)
		}
	}
}

type TarefaRegex struct {
	Dominio      string
	URL          string
	CaminhoLocal string
}

func WorkerExtrator(canalTarefas <-chan TarefaRegex, wg *sync.WaitGroup) {
	defer wg.Done()

	for tarefa := range canalTarefas {

		pastaFuzzing := filepath.Join("Alvos", tarefa.Dominio, "Fuzzing")
		caminhoEstado := filepath.Join(pastaFuzzing, "estado_regex.txt")

		estadoAtual := carregarEstado(caminhoEstado)
		if estadoAtual[tarefa.CaminhoLocal] {
			continue
		}

		conteudo, err := os.ReadFile(tarefa.CaminhoLocal)
		if err != nil {
			continue
		}

		achados := 0
		var relatorioTelegram []string

		for nomeSegredo, expressao := range RegexSegredos {
			matches := expressao.FindAll(conteudo, -1)

			if len(matches) > 0 {
				achados += len(matches)

				// Normaliza e deduplica
				mapaUnicos := make(map[string]bool)
				for _, vazamento := range matches {

					textoVazado := string(vazamento)
					if len(textoVazado) > 60 {
						textoVazado = textoVazado[:60] + "...[trunc]"
					}
					mapaUnicos[textoVazado] = true
				}

				var listaVazamentos []string
				for vazamento := range mapaUnicos {
					listaVazamentos = append(listaVazamentos, vazamento)
				}

				resultado := ResultadoRegex{
					Alvo:      tarefa.URL,
					Vazamento: listaVazamentos,
					Tipo:      nomeSegredo,
					Arquivo:   tarefa.CaminhoLocal,
					Timestamp: time.Now().Format(time.RFC3339),
				}
				salvarAchadoRegex(tarefa.Dominio, resultado)

				fmt.Printf("%s - \033[31m[%sENCONTRADO EM TEMPO REAL]\033[0m Em: %s\n", momento(tempo), nomeSegredo, tarefa.URL)

				linhaAlerta := fmt.Sprintf("[OURO] *%s*\n*Alvo:* %s\n", nomeSegredo, tarefa.URL)
				for vazamento := range mapaUnicos {
					linhaAlerta += fmt.Sprintf("[CHAVE] `%s`\n", vazamento)
				}
				relatorioTelegram = append(relatorioTelegram, linhaAlerta)
			}
		}

		if len(relatorioTelegram) > 0 {
			for _, alerta := range relatorioTelegram {
				telegram(alerta)
				time.Sleep(2 * time.Second) 
			}
		}
		registrarEstado(caminhoEstado, tarefa.CaminhoLocal)
	}
}

func momento(agora string) string {
	agora = time.Now().Format("2006-01-02 15:04:05")
	return agora
}
