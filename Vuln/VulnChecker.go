package vuln

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func telegram(laudo_vuln Laudo_Vuln) {
	var telegram_key string = "<INSIRA_SUA_CHAVE_API_DO_TELEGRAM_AQUI>"
	var chat_id string = "<INSIRA_ID_DO_SEU_CHAT_TELEGRAM_AQUI>"
	ritmo := time.NewTicker(time.Millisecond / time.Duration(2000))
	defer ritmo.Stop()

	mensagem := fmt.Sprintf("[-------- [Vulnerabilidade encontrada] --------]\n\n"+
		"URL : %s \n"+
		"ID  : %s \n"+
		"Severidadade  : %s \n"+
		"Caminhos  : %#v \n"+
		"Nome : %s \n", laudo_vuln.URL, laudo_vuln.ID, laudo_vuln.Severidade, laudo_vuln.Caminhos, laudo_vuln.Nome)

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

type RastreadorETA struct {
	Total      uint64
	Processado uint64
	Inicio     time.Time
}

func NovoETA(total uint64) *RastreadorETA {
	return &RastreadorETA{Total: total, Inicio: time.Now()}
}

func (r *RastreadorETA) Incrementar() {
	atomic.AddUint64(&r.Processado, 1)
}

func (r *RastreadorETA) Calcular() string {
	feito := atomic.LoadUint64(&r.Processado)
	if feito == 0 {
		return "Calculando..."
	}
	decorrido := time.Since(r.Inicio).Seconds()
	if decorrido == 0 {
		return "Calculando..."
	}
	taxaPorSegundo := float64(feito) / decorrido
	restante := float64(r.Total-feito) / taxaPorSegundo

	tempoRestante := time.Duration(restante * float64(time.Second))
	return fmt.Sprintf("ETA: %v | Velocidade: %.2f req/s", tempoRestante.Round(time.Second), taxaPorSegundo)
}

var tempo string

type Arsenal_vulns struct {
	ID   string `json:"id"`
	Info struct {
		Nome       string `json:"nome"`
		Severidade string `json:"severidade"`
	} `json:"info"`
	TecnologiasAlvo []string `json:"tecnologias_alvo"`
	Requisicao      struct {
		Metodo   string            `json:"metodo"`
		Caminhos []string          `json:"caminhos"`
		Headers  map[string]string `json:"headers"`
		Body     string            `json:"body"`
	} `json:"requisicao"`
	Validacao ValidacaoPrecisa `json:"validacao"`
}

type RegraMatcher struct {
	Tipo     string   `json:"tipo"`     
	Alvo     string   `json:"alvo"`     
	Valores  []string `json:"valores"`
	Condicao string   `json:"condicao"` 
	Negativo bool     `json:"negativo"` 
}

type ValidacaoPrecisa struct {
	OperadorGlobal string         `json:"operador_global"`
	Regras         []RegraMatcher `json:"regras"`
}

type Laudo struct {
	URL           string
	StatusCode    int
	Server        []string
	Allow         string
	ContentLength int64
	Tecnologia    []string
	WAF           string
}

type Laudo_Vuln struct {
	URL        string
	ID         string
	Vuln       string
	Severidade string
	Caminhos   []string
	Nome       string
}

type Tiro struct {
	Laudo Laudo         
	Vuln  Arsenal_vulns
}

func validacao_vuln(body string, headersResp map[string][]string, status_code int, vuln Arsenal_vulns) bool {
	if len(vuln.Validacao.Regras) == 0 {
		return false
	}

	operadorGlobal := strings.ToUpper(vuln.Validacao.OperadorGlobal)
	if operadorGlobal != "OR" {
		operadorGlobal = "AND"
	}

	var headerTexto string
	headersCarregados := false

	for _, regra := range vuln.Validacao.Regras {

		alvoTexto := body
		if regra.Alvo == "header" || regra.Alvo == "all" {
			if !headersCarregados {
				var headersStr strings.Builder
				for key, values := range headersResp {
					for _, v := range values {
						headersStr.WriteString(fmt.Sprintf("%s: %s\n", key, v))
					}
				}
				headerTexto = headersStr.String()
				headersCarregados = true
			}

			if regra.Alvo == "header" {
				alvoTexto = headerTexto
			} else { // "all"
				alvoTexto = headerTexto + "\n\n" + body
			}
		}
		condicaoInterna := strings.ToUpper(regra.Condicao)
		if condicaoInterna != "AND" {
			condicaoInterna = "OR"
		}

		passouRegra := (condicaoInterna == "AND")

		for _, valor := range regra.Valores {
			match := false

			switch regra.Tipo {
			case "status":
				statusEsperado, err := strconv.Atoi(valor)
				if err == nil {
					match = (status_code == statusEsperado)
				}
			case "word":
				match = strings.Contains(alvoTexto, valor)
			case "regex":
				re, err := regexp.Compile(valor)
				if err == nil {
					match = re.MatchString(alvoTexto)
				}
			}

			if condicaoInterna == "OR" {
				if match {
					passouRegra = true
					break
				}
			} else {
				if !match {
					passouRegra = false
					break
				}
			}
		}

		if regra.Negativo {
			passouRegra = !passouRegra
		}

		if operadorGlobal == "AND" {
			if !passouRegra {
				return false
			}
		} else {
			if passouRegra {
				return true
			}
		}
	}

	return operadorGlobal == "AND"
}
func alvo_elegível(techs_alvo []string, techs_template []string) bool {
	if len(techs_template) == 0 {
		return true
	}
	for _, regra_tech := range techs_template {
		regraLimpa := strings.TrimSpace(strings.ToLower(regra_tech))
		if regraLimpa == "" {
			continue
		}
		for _, tech_alvo := range techs_alvo {
			alvoLimpo := strings.TrimSpace(strings.ToLower(tech_alvo))

			if strings.Contains(alvoLimpo, regraLimpa) {
				return true
			}
		}
	}

	return false
}

func analise_vulns_work(jobs <-chan Tiro, results chan<- Laudo_Vuln, wg *sync.WaitGroup, client *http.Client, ticker <-chan time.Time, eta *RastreadorETA, mapa404 map[string]AssinaturaSoft404) error {
	defer wg.Done()

	for tiro := range jobs {
		eta.Incrementar()

		if atomic.LoadUint64(&eta.Processado)%500 == 0 {
			fmt.Printf("%s - \033[36m[PROGRESSO VULN]\033[0m Processados %d/%d alvos. %s\n", momento(tempo), atomic.LoadUint64(&eta.Processado), eta.Total, eta.Calcular())
		}

		if !alvo_elegível(tiro.Laudo.Tecnologia, tiro.Vuln.TecnologiasAlvo) {
			continue
		}

		fantasma404 := mapa404[tiro.Laudo.URL]

		for _, caminho := range tiro.Vuln.Requisicao.Caminhos {
			<-ticker

			req, err := http.NewRequest(tiro.Vuln.Requisicao.Metodo, tiro.Laudo.URL+caminho, strings.NewReader(tiro.Vuln.Requisicao.Body))
			if err != nil || req == nil {
				continue
			}

			for header, valor := range tiro.Vuln.Requisicao.Headers {
				req.Header.Set(header, valor)
			}
			req.Header.Set("X-Bug-Bounty", "True")
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			respHeader := resp.Header
			status_code := resp.StatusCode
			bodybytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			bodyString := string(bodybytes)

			if strings.Contains(bodyString, "Access Denied") || strings.Contains(bodyString, "Reference #") || strings.Contains(bodyString, "Cloudflare") {
				continue
			}

			tamanhoAtual := int64(len(bodybytes))
			palavrasAtuais := len(strings.Fields(bodyString))
			margemTamanho := float64(fantasma404.ContentLength) * 0.05 // 5% de variação

			diff := float64(tamanhoAtual - fantasma404.ContentLength)
			if diff < 0 {
				diff = -diff
			}

			if status_code == fantasma404.StatusCode && (diff <= margemTamanho || palavrasAtuais == fantasma404.Palavras) {
				continue
			}

			validadade := validacao_vuln(bodyString, respHeader, status_code, tiro.Vuln)
			if validadade {
				novo_laudo := Laudo_Vuln{
					URL:        tiro.Laudo.URL,
					ID:         tiro.Vuln.ID,
					Severidade: tiro.Vuln.Info.Severidade,
					Caminhos:   tiro.Vuln.Requisicao.Caminhos,
					Nome:       tiro.Vuln.Info.Nome,
				}
				results <- novo_laudo
			}
		}
	}
	return nil
}

type AssinaturaSoft404 struct {
	StatusCode    int
	ContentLength int64
	Palavras      int
}

func calibrarAlvo404(alvo string, client *http.Client) AssinaturaSoft404 {
	var assinatura AssinaturaSoft404
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/gohunt_fantasma_%d", alvo, time.Now().UnixNano()), nil)
	resp, err := client.Do(req)
	if err != nil {
		return assinatura
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)

	assinatura.StatusCode = resp.StatusCode
	assinatura.ContentLength = int64(len(bodyBytes))
	assinatura.Palavras = len(strings.Fields(string(bodyBytes)))
	return assinatura
}

func analise_vulns(lista_arq_laudo []string, inputs []string) []string {
	jobs := make(chan Tiro, 10000)
	results := make(chan Laudo_Vuln, 500)
	workers := 5

	var arsenal_vulns []Arsenal_vulns
	nome_arsenal := filepath.Join("Db", "arsenal_v6.json")
	arsenal_bytes, err := os.ReadFile(nome_arsenal)
	if err != nil {
		fmt.Printf("%s", momento(tempo)+" - [ERRO] Falha ao ler bytes do arquivo arsenal.json. ... \n")
	}
	json.Unmarshal(arsenal_bytes, &arsenal_vulns)

	taxa := 1000 * time.Millisecond
	ticket := time.NewTicker(taxa)
	defer ticket.Stop()

	var lista_laudos []Laudo
	var laudo_rec Laudo
	for _, laudo_arq := range lista_arq_laudo {
		conteudo, err := os.ReadFile(laudo_arq)
		if err != nil {
			continue
		}
		json.Unmarshal(conteudo, &laudo_rec)
		lista_laudos = append(lista_laudos, laudo_rec)
	}

	totalTiros := uint64(len(arsenal_vulns) * len(lista_laudos))
	rastreador := NovoETA(totalTiros)

	fmt.Printf("%s - [INFO] Calibrando %d alvos contra Soft-404 e Falsos Positivos...\n", momento(tempo), len(lista_laudos))
	mapa404 := make(map[string]AssinaturaSoft404)
	client_calibracao := &http.Client{Timeout: 5 * time.Second}
	for _, alvo := range lista_laudos {
		mapa404[alvo.URL] = calibrarAlvo404(alvo.URL, client_calibracao)
	}

	var wg sync.WaitGroup
	client := &http.Client{Timeout: 10 * time.Second}
	for w := 1; w <= workers; w++ {
		wg.Add(1)
		go analise_vulns_work(jobs, results, &wg, client, ticket.C, rastreador, mapa404)
	}

	go func() {
		for _, vuln := range arsenal_vulns {
			for _, alvo := range lista_laudos {
				jobs <- Tiro{Laudo: alvo, Vuln: vuln}
			}

		}

		close(jobs)

	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var dirs_arqs_vulns []string

	dir_compilado := filepath.Join("Alvos", "Compilado")
	os.MkdirAll(dir_compilado, 0644)
	nome_arq_compilado := filepath.Join(dir_compilado, momento_2(tempo))
	os.Create(nome_arq_compilado)

	arq_compilado, err := os.Open(nome_arq_compilado)
	if err != nil {
		fmt.Printf("%s - [ERRO] Falha ao criar o arquivo de laudos compilado ... \n", momento(tempo))
	}

	for laudo_vuln := range results {
		telegram(laudo_vuln)

		nome_arq_vuln := fmt.Sprintf("%s_%s.json", momento_2(tempo), laudo_vuln.ID)

		alvo_limpo := strings.TrimPrefix(laudo_vuln.URL, "http://")
		alvo_limpo = strings.TrimPrefix(alvo_limpo, "https://")
		alvo_limpo = strings.ReplaceAll(alvo_limpo, ":", "_")
		dir_arq_vulns := filepath.Join("Alvos", alvo_limpo)
		dir_arq_vulns = filepath.Join(dir_arq_vulns, "vuln")

		err := os.MkdirAll(dir_arq_vulns, 0755)
		if err != nil {
			fmt.Printf("%s - [ERRO] Falha ao criar o diretório %s: %v\n", momento(tempo), dir_arq_vulns, err)
			continue
		}

		arq_laudo_vuln := filepath.Join(dir_arq_vulns, nome_arq_vuln)

		laudo, err := os.Create(arq_laudo_vuln)
		if err != nil {
			fmt.Printf("%s - [ERRO] Falha ao criar arquivo de laudo %s: %v\n", momento(tempo), arq_laudo_vuln, err)
			continue
		}

		fmt.Printf("%s - [VULNERABILIDADE %s] Foi encontrada a vulnerabilidade [%s] de criticidade [%s] no alvo [%s] ... \n", momento(tempo), laudo_vuln.Nome, laudo_vuln.ID, laudo_vuln.Severidade, laudo_vuln.URL)

		json_bytes, _ := json.Marshal(laudo_vuln)
		laudo.Write(append(json_bytes, '\n'))
		arq_compilado.Write(append(json_bytes, '\n'))
		laudo.Close()

		fmt.Printf("%s - [SUCESSO] Laudos de vulnerabilidades gerados no arquivo [%s] ... \n", momento(tempo), arq_laudo_vuln)
		dirs_arqs_vulns = append(dirs_arqs_vulns, arq_laudo_vuln)
	}

	return dirs_arqs_vulns

}

func momento(agora string) string { 
	agora = time.Now().Format("2006-01-02 15:04:05")
	return agora
}

func momento_2(agora string) string { 
	agora = time.Now().Format("2006-01-02")
	return agora
}

func IniciarVulnChecker(lista_arq_laudo []string, inputs []string) []string {
	nome_arqs_vulns := analise_vulns(lista_arq_laudo, inputs)

	return nome_arqs_vulns
}
