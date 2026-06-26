package bypass

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type TarefaBypass struct {
	URL           string
	StatusOrigial int
}

type ResultadoBypass struct {
	Alvo      string `json:"alvo_original"`
	Status    int    `json:"status_original"`
	Tecnica   string `json:"tecnica_utilizada"`
	Sucesso   string `json:"payload_sucesso"`
	Timestamp string `json:"timestamp"`
}

func telegram(mensagem string) {
	var telegram_key string = "<INSIRA_SUA_CHAVE_API_DO_TELEGRAM_AQUI>"
	var chat_id string = "<INSIRA_ID_DO_SEU_CHAT_TELEGRAM_AQUI>"

	api_url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", telegram_key)

	dados := url.Values{}
	dados.Set("chat_id", chat_id)
	dados.Set("text", mensagem)
	dados.Set("parse_mode", "Markdown")

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

var tempo string
var muBypass sync.Mutex

func registrarEstadoBypass(dominio, urlTestada string) {
	pasta := filepath.Join("Alvos", dominio, "Fuzzing")
	os.MkdirAll(pasta, 0755)
	caminhoEstado := filepath.Join(pasta, "estado_bypass.txt")

	muBypass.Lock()
	defer muBypass.Unlock()
	f, err := os.OpenFile(caminhoEstado, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		f.WriteString(urlTestada + "\n")
		f.Close()
	}

}

func salvarAchadoBypass(dominio string, resultado ResultadoBypass) {
	pasta := filepath.Join("Alvos", dominio, "Fuzzing")
	os.MkdirAll(pasta, 0755)
	caminhoResultados := filepath.Join(pasta, "resultados_bypass.jsonl")

	linhaJSON, _ := json.Marshal(resultado)

	muBypass.Lock()
	defer muBypass.Unlock()
	f, err := os.OpenFile(caminhoResultados, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		f.WriteString(string(linhaJSON) + "\n")
		f.Close()
	}
	muBypass.Unlock()

}

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

var HeadersBypass = map[string]string{
	"X-Forwarded-For":           "127.0.0.1",
	"X-Forwarded-Host":          "127.0.0.1",
	"X-Client-IP":               "127.0.0.1",
	"X-Remote-IP":               "127.0.0.1",
	"X-Originating-IP":          "127.0.0.1",
	"X-Custom-IP-Authorization": "127.0.0.1",
	"True-Client-IP":            "127.0.0.1",
	"Cluster-Client-IP":         "127.0.0.1",
}

var SufixosBypass = []string{
	"", "/", "..;/", "/..;/", "%20", "%09", "%00", 
	".json", ".css", ".html", ".js", 
	";.json", ";.css", ";.html", 
	"?", "??", "&", "#", 
}

var PrefixosBypass = []string{
	"/", "/*/", "//", "///", "/\\/", "/%5c/", 
	"/%2e/", "/%252e/", "/%ef%bc%8f/", 
	"/;/;/../", "/.;/", "/..;/", "/...;/", 
	"/%00/", 
}

func alternarCaixa(caminho string) []string {
	var variacoes []string
	if caminho == "" || caminho == "/" {
		return variacoes
	}

	caminhoLimpo := strings.TrimPrefix(caminho, "/")

	variacoes = append(variacoes, strings.ToUpper(caminhoLimpo))
	variacoes = append(variacoes, strings.Title(strings.ToLower(caminhoLimpo)))

	return variacoes
}

func clientBypass() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   2 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse 
		},
	}
}

func Jitter(mindelay int, maxdelay int) {
	delta := maxdelay - mindelay
	rand_time, err := rand.Int(rand.Reader, big.NewInt(int64(delta)))
	if err != nil {
		fmt.Printf("%s - [ERRO] Erro ao gerar o aleatório para o jitter ... \n", momento(tempo))
		time.Sleep(time.Duration(2*mindelay) * time.Millisecond)
		return
	}
	delayfinal := mindelay + int(rand_time.Int64())
	time.Sleep(time.Duration(delayfinal) * time.Millisecond)
}

func WorkerBypass(canalTarefas <-chan TarefaBypass, wg *sync.WaitGroup, telegram func(string)) {
	defer wg.Done()
	client := clientBypass()

	for tarefa := range canalTarefas {
		parsedURL, err := url.Parse(tarefa.URL)
		if err != nil {
			continue
		}

		dominio := parsedURL.Hostname()
		req, err := client.Get(dominio)
		if err != nil {
			continue
		}
		status := req.StatusCode
		if status != 403 {
			continue
		}

		caminhoEstado := filepath.Join("Alvos", dominio, "Fuzzing", "estado_bypass.txt")
		estadoAtual := carregarEstado(caminhoEstado) // Reutiliza a mesma função de ler .txt
		if estadoAtual[tarefa.URL] {
			continue
		}

		caminhoOriginal := parsedURL.Path
		host := parsedURL.Scheme + "://" + parsedURL.Host

		baselineBodyLen := obterBaselines(client, tarefa.URL)

		sucessos := make([]string, 0)

		for nomeHeader, valorHeader := range HeadersBypass {
			req, _ := http.NewRequest("GET", tarefa.URL, nil)
			req.Header.Set(nomeHeader, valorHeader)

			req.Header.Set("X-Original-URL", caminhoOriginal)
			req.Header.Set("X-Rewrite-URL", caminhoOriginal)
			req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0")
			req.Header.Set("X-HackerOne-Research", "h3rm1t0")
			req.Header.Set("X-Bug-Bounty", "h-1h3rm1t0")
			if avaliarTiro(client, req, baselineBodyLen) {
				sucessos = append(sucessos, fmt.Sprintf("Header Spoofing: %s: %s", nomeHeader, valorHeader))
			}
		}

		for _, prefixo := range PrefixosBypass {
			for _, sufixo := range SufixosBypass {
				caminhoMutado := prefixo + strings.TrimPrefix(caminhoOriginal, "/") + sufixo
				urlMutada := host + caminhoMutado

				req, _ := http.NewRequest("GET", urlMutada, nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0")
				req.Header.Set("X-HackerOne-Research", "h3rm1t0")
				if avaliarTiro(client, req, baselineBodyLen) {
					sucessos = append(sucessos, fmt.Sprintf("Path Obfuscation: %s", caminhoMutado))
				}
			}
		}

		for _, prefixo := range PrefixosBypass {
			for _, sufixo := range SufixosBypass {
				caminhoMutado := prefixo + strings.TrimPrefix(caminhoOriginal, "/") + sufixo
				urlMutada := host + caminhoMutado

				req, _ := http.NewRequest("GET", urlMutada, nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0")
				req.Header.Set("X-HackerOne-Research", "h3rm1t0")
				if avaliarTiro(client, req, baselineBodyLen) {
					sucessos = append(sucessos, fmt.Sprintf("Path Obfuscation: %s", caminhoMutado))
				}
			}
		}

		variacoesCaixa := alternarCaixa(caminhoOriginal)
		for _, caminhoMutado := range variacoesCaixa {
			urlsTeste := []string{
				host + "/" + caminhoMutado,
				host + "/" + caminhoMutado + ";.css",
			}

			for _, urlMutada := range urlsTeste {
				req, _ := http.NewRequest("GET", urlMutada, nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0")
				req.Header.Set("X-HackerOne-Research", "h3rm1t0")
				if avaliarTiro(client, req, baselineBodyLen) {
					sucessos = append(sucessos, fmt.Sprintf("Case Toggling Bypass: %s", urlMutada))
				}
			}
		}

		metodos := []string{"POST", "TRACE", "OPTIONS"}
		for _, metodo := range metodos {
			req, _ := http.NewRequest(metodo, tarefa.URL, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0")
			req.Header.Set("X-HackerOne-Research", "h3rm1t0")
			if avaliarTiro(client, req, baselineBodyLen) {
				sucessos = append(sucessos, fmt.Sprintf("Method Tampering: HTTP %s", metodo))
			}
		}

		if len(sucessos) > 0 {
			for _, s := range sucessos {
				resultado := ResultadoBypass{
					Alvo:      tarefa.URL,
					Status:    tarefa.StatusOrigial,
					Tecnica:   strings.Split(s, ": ")[0], 
					Sucesso:   s,
					Timestamp: time.Now().Format(time.RFC3339),
				}
				salvarAchadoBypass(dominio, resultado)
			}
		}

		if len(sucessos) > 0 {
			msg := fmt.Sprintf("*GoHunt [BYPASS 403]* \n*Alvo:* %s\n*Vulnerabilidades de Bypass:*", tarefa.URL)
			for _, s := range sucessos {
				fmt.Printf("\033[35m[BYPASS SUCESSO]\033[0m %s -> Técnica: %s\n", tarefa.URL, s)
				msg += fmt.Sprintf("\n- `%s`", s)
			}
			telegram(msg)
		}
		registrarEstadoBypass(dominio, tarefa.URL)
	}
}

type BaselineHost struct {
	OriginalStatus int
	OriginalLength int
	FantasmaStatus int
	FantasmaLength int
}

func obterBaselines(client *http.Client, alvo string) BaselineHost {
	var base BaselineHost

	req403, _ := http.NewRequest("GET", alvo, nil)
	resp403, err := client.Do(req403)
	if err == nil {
		body, _ := io.ReadAll(resp403.Body)
		base.OriginalStatus = resp403.StatusCode
		base.OriginalLength = len(body)
		resp403.Body.Close()
	}

	req404, _ := http.NewRequest("GET", alvo+"/bypass_check_inexistente_999", nil)
	resp404, err := client.Do(req404)
	if err == nil {
		body404, _ := io.ReadAll(resp404.Body)
		base.FantasmaStatus = resp404.StatusCode
		base.FantasmaLength = len(body404)
		resp404.Body.Close()
	}
	return base
}

func avaliarTiro(client *http.Client, req *http.Request, base BaselineHost) bool {
	Jitter(50, 150)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyLen := len(body)

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return false
	}

	if resp.StatusCode >= 400 {
		return false
	}

	if resp.StatusCode == base.FantasmaStatus {
		diff404 := bodyLen - base.FantasmaLength
		if diff404 < 0 {
			diff404 = -diff404
		}
		if float64(diff404) <= float64(base.FantasmaLength)*0.05 {
			return false 
		}
	}

	return true
}

func momento(agora string) string { 
	agora = time.Now().Format("2006-01-02 15:04:05")
	return agora
}
