package fuzzing

import (
	bypass "GoHunt/Bypass"
	extractor "GoHunt/Extractor"
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func telegram(mensagem string) {
	var telegram_key string = "<INSIRA_SUA_CHAVE_API_DO_TELEGRAM_AQUI>"
	var chat_id string = "<INSIRA_ID_DO_SEU_CHAT_TELEGRAM_AQUI>"
	ritmo := time.NewTicker(time.Millisecond / time.Duration(2000))
	defer ritmo.Stop()

	api_url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", telegram_key)

	dados := url.Values{}
	dados.Set("chat_id", chat_id)
	dados.Set("text", mensagem)
	dados.Set("parse_mode", "Markdown")

	client := &http.Client{Timeout: 2 * time.Second}
	req, _ := http.NewRequest("POST", api_url, strings.NewReader(dados.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	<-ritmo.C
	resp, err := client.Do(req)
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

type Laudo struct {
	URL           string
	StatusCode    int
	Server        []string
	Allow         string
	ContentLength int64
	Tecnologia    []string
	WAF           string
}

type AssinaturaFalsa struct {
	StatusCode    int
	ContentLength int64
	QtdPalavras   int
}

func geraStringAleatoria() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func calibrarAlvo(alvo string, client *http.Client) AssinaturaFalsa {
	urlFantasma := fmt.Sprintf("%s/gohunt_fuzz_%s", alvo, geraStringAleatoria())
	var assinatura AssinaturaFalsa

	req, err := http.NewRequest("GET", urlFantasma, nil)
	if err != nil {
		return assinatura
	}

	resp, err := client.Do(req)
	if err != nil {
		return assinatura
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyString := string(bodyBytes)

	assinatura.StatusCode = resp.StatusCode
	assinatura.ContentLength = int64(len(bodyBytes))
	assinatura.QtdPalavras = len(strings.Fields(bodyString)) 
	return assinatura
}

var extensoesLixo = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
	".bmp": true, ".svg": true, ".css": true, ".ico": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".mp4": true, ".mp3": true, ".avi": true, ".pdf": true,
}

var (
	reUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

	reSlug = regexp.MustCompile(`^[0-9]+-[a-zA-Z0-9-%]+$`)

	reIdioma = regexp.MustCompile(`^(?i)(en|es|pt|fr|de|it|ru|ja|ko|zh|nl|tr|ar|id|[a-z]{2}[-_][a-z]{2})$`)

	reLixoPath = regexp.MustCompile(`(?i)(/careers/|/jobs/|/news/|/events/|/eu-dsa/|/legal/|/privacy|/cookie|/terms/|/assets/|/static/|/css/|/fonts/|/js/)`)

	reOuro = regexp.MustCompile(`(?i)(\.js|\.json|\.xml|\.env|\.conf|\.yml|\.yaml|\.php|\.aspx|\.asp|\.txt|\.sql|\.zip|\.bak|\.swp|/api/|/v1/|/v2/|/v3/|/graphql|/swagger)`)

	reLixoAbsoluto = regexp.MustCompile(`(?i)(^|\.)(careers|jobs|news|blog|investors|events)\.|(/assets/|/static/|/css/|/fonts/|/node_modules/|jquery|bootstrap|owl\.carousel|rocket-loader)`)

	reIDAlfanumerico = regexp.MustCompile(`(?i)^[A-Z0-9]{2,}\.[A-Z0-9]{2,}$`)
)

func classificarRisco(u *url.URL) string {
	if reOuro.MatchString(u.Path) {
		return "ALTO"
	}
	return "INFORMATIVO"
}

func ehNumero(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func gerarAssinaturaURL(u *url.URL) string {
	segmentos := strings.Split(u.Path, "/")

	for i, seg := range segmentos {
		if seg == "" {
			continue
		}

		if ehNumero(seg) {
			segmentos[i] = "{id}"
			continue
		}

		if reIDAlfanumerico.MatchString(seg) {
			segmentos[i] = "{id_misto}"
			continue
		}

		if reUUID.MatchString(seg) {
			segmentos[i] = "{uuid}"
			continue
		}

		if reSlug.MatchString(seg) {
			segmentos[i] = "{slug}"
			continue
		}

		if i <= 3 && reIdioma.MatchString(seg) {
			segmentos[i] = "{lang}"
			continue
		}
	}

	assinatura := strings.Join(segmentos, "/")

	query := u.Query()
	if len(query) > 0 {
		var chaves []string
		for chave := range query {
			chaves = append(chaves, chave)
		}
		sort.Strings(chaves)
		assinatura += "?" + strings.Join(chaves, "&")
	}

	return assinatura
}

func higienizarURL(linha string) (*url.URL, error) {
	if idx := strings.Index(linha, " "); idx != -1 {
		linha = linha[:idx]
	}

	linha = strings.ReplaceAll(linha, "\"", "")
	linha = strings.ReplaceAll(linha, "'", "")
	linha = strings.ReplaceAll(linha, "\\", "")
	linha = strings.ReplaceAll(linha, ">", "")
	linha = strings.ReplaceAll(linha, "<", "")

	u, err := url.Parse(linha)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("esquema inválido")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("host vazio")
	}

	return u, nil
}

func Busca_Wayback_Stream(alvo string, saida chan<- string) {
	ritmo := time.NewTicker(time.Millisecond / time.Duration(2000))
	defer ritmo.Stop()

	alvo_limpo := strings.TrimSpace(alvo)
	alvo_limpo = strings.TrimPrefix(alvo_limpo, "https://")
	alvo_limpo = strings.TrimPrefix(alvo_limpo, "http://")
	alvo_limpo = strings.ToLower(alvo_limpo)
	alvo_limpo = strings.TrimSuffix(alvo_limpo, "/")

	wayback_url := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s&matchType=domain&output=txt&fl=original&collapse=urlkey", alvo_limpo)

	req, err := http.NewRequest(http.MethodGet, wayback_url, nil)
	if err != nil || req == nil {
		fmt.Printf("%s - [ERRO] Falha ao criar a requisição para o Wayback Machine...\n", momento(tempo))
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0")

	client := client_wayback()

	var resp *http.Response
	maxTentativas := 10
	sucesso := false

	for tentativa := 1; tentativa <= maxTentativas; tentativa++ {
		<-ritmo.C
		resp, err = client.Do(req)

		if err == nil && resp.StatusCode == 200 {
			sucesso = true
			break
		}

		if tentativa < maxTentativas {
			fmt.Printf("%s - [AVISO] Timeout no alvo %s. Tentativa %d/%d falhou. Aguardando 15s...\n", momento(tempo), alvo_limpo, tentativa, maxTentativas)
			time.Sleep(15 * time.Second)
		}
	}

	if !sucesso {
		fmt.Printf("%s - [AVISO] Abortando %s após %d tentativas. Servidor do Archive.org sobrecarregado.\n", momento(tempo), alvo_limpo, maxTentativas)
		return
	}
	defer resp.Body.Close()

	mapa_assinaturas := make(map[string]bool)
	scanner := bufio.NewScanner(resp.Body)

	for scanner.Scan() {
		linha := strings.TrimSpace(scanner.Text())
		if linha == "" {
			continue
		}

		u, err := higienizarURL(linha)
		if err != nil {
			continue
		}

		extensao := strings.ToLower(filepath.Ext(u.Path))
		if extensoesLixo[extensao] {
			continue
		}
		hostLower := strings.ToLower(u.Host)
		pathLower := strings.ToLower(u.Path)

		if reLixoAbsoluto.MatchString(hostLower) || reLixoAbsoluto.MatchString(pathLower) {
			continue
		}

		isLixoPath := reLixoPath.MatchString(pathLower)
		isOuro := reOuro.MatchString(pathLower)
		if isLixoPath && !isOuro {
			continue
		}

		if u.Path == "" || u.Path == "/" {
			continue
		}

		assinatura := gerarAssinaturaURL(u)
		if !mapa_assinaturas[assinatura] {
			mapa_assinaturas[assinatura] = true

			caminhoOriginal := u.Path
			if u.RawQuery != "" {
				caminhoOriginal = caminhoOriginal + "?" + u.RawQuery
			}

			saida <- caminhoOriginal
		}
	}
}

var muArquivos sync.Mutex
var CanalExtrator chan extractor.TarefaRegex
var WgExtrator sync.WaitGroup
var CanalBypass chan bypass.TarefaBypass
var WgBypass sync.WaitGroup

func SalvarParaBypass(urlTeste string) {
	dominio := extrairDominio(urlTeste)
	pasta := filepath.Join("Alvos", dominio, "Fuzzing")

	os.MkdirAll(pasta, 0755)

	caminhoArquivo := filepath.Join(pasta, "alvos_bypass.txt")

	muArquivos.Lock()
	defer muArquivos.Unlock()
	f, err := os.OpenFile(caminhoArquivo, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		f.WriteString(urlTeste + "\n")
		f.Close()
	}
}

var assinaturasOAuth = [][]byte{
	[]byte(`type="password"`),
	[]byte(`oauth2/authorize`),
	[]byte(`accounts.google.com/o/oauth2`),
	[]byte(`login.microsoftonline.com`),
	[]byte(`sign in with`),
	[]byte(`forgot password`),
	[]byte(`samlrequest`),
	[]byte(`"isauthenticated":false`),
}

func classificarSoft200(body []byte) bool {
	bodyLower := bytes.ToLower(body)

	for _, assinatura := range assinaturasOAuth {
		if bytes.Contains(bodyLower, assinatura) {
			return true 
		}
	}
	return false
}

func SalvarParaRegex(urlTeste string, body []byte) {
	dominio := extrairDominio(urlTeste)

	pastaFuzzing := filepath.Join("Alvos", dominio, "Fuzzing")
	pastaRespostas := filepath.Join(pastaFuzzing, "Respostas_Raw")
	os.MkdirAll(pastaRespostas, 0755)

	hashMD5 := md5.Sum([]byte(urlTeste))
	nomeArquivoBody := hex.EncodeToString(hashMD5[:]) + ".txt"
	caminhoBody := filepath.Join(pastaRespostas, nomeArquivoBody)

	os.WriteFile(caminhoBody, body, 0644)

	caminhoLista := filepath.Join(pastaFuzzing, "alvos_regex.txt")

	muArquivos.Lock()
	defer muArquivos.Unlock()
	f, err := os.OpenFile(caminhoLista, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		linha := fmt.Sprintf("%s -> Arquivo Local: %s\n", urlTeste, nomeArquivoBody)
		f.WriteString(linha)
		f.Close()
	}

	if CanalExtrator != nil {
		CanalExtrator <- extractor.TarefaRegex{
			Dominio:      dominio,
			URL:          urlTeste,
			CaminhoLocal: caminhoBody,
		}
	}

}

func AvaliarResposta(status int, body []byte, urlTeste string, risco string) {

	if status == 200 || status == 500 || status == 403 || status == 401 {
		if classificarSoft200(body) {
			SalvarParaBypass(urlTeste)
		} else if risco == "ALTO" {
			SalvarParaRegex(urlTeste, body)
		}
		return
	}

	if status == 401 || status == 403 {
		if CanalBypass != nil {
			CanalBypass <- bypass.TarefaBypass{
				URL:           urlTeste,
				StatusOrigial: status,
			}
		}
		return
	}

	if status == 301 || status == 302 {
		return
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

func wayback_work(jobs <-chan string, wg *sync.WaitGroup, ritmoWayback *time.Ticker, totalGlobal *uint64) {
	defer wg.Done()
	client := client_probber()

	for laudo_path := range jobs {
		arq, err := os.ReadFile(laudo_path)
		if err != nil {
			continue
		}

		var alvo Laudo
		if err := json.Unmarshal(arq, &alvo); err != nil {
			continue
		}

		assinaturaLixo := calibrarAlvo(alvo.URL, client)

		var rotasVivas []string
		var logsTelegram []string
		var mu sync.Mutex
		var urlsTestadas uint64
		var wgFuzz sync.WaitGroup

		concorrencia := 3
		sem := make(chan struct{}, concorrencia)

		canalUrls := make(chan string, 1000)

		go func() {
			Busca_Wayback_Stream(alvo.URL, canalUrls)
			close(canalUrls)
		}()
		for caminho := range canalUrls {
			wgFuzz.Add(1)
			sem <- struct{}{}

			go func(c string) {
				defer wgFuzz.Done()
				defer func() { <-sem }()

				urlTeste := alvo.URL + c
				req, err := http.NewRequest("GET", urlTeste, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
				req.Header.Set("X-HackerOne-Research", "h3rm1t0")

				Jitter(300, 700)

				resp, err := client.Do(req)
				if err != nil {
					return
				}

				bodyBytes, _ := io.ReadAll(resp.Body)
				tamanhoResposta := int64(len(bodyBytes))
				qtdPalavras := len(strings.Fields(string(bodyBytes)))
				statusAtual := resp.StatusCode
				resp.Body.Close()

				isFalsoPositivo := false
				if statusAtual == assinaturaLixo.StatusCode {
					margemErro := float64(assinaturaLixo.ContentLength) * 0.05
					diferencaTamanho := float64(tamanhoResposta - assinaturaLixo.ContentLength)
					if diferencaTamanho < 0 {
						diferencaTamanho = -diferencaTamanho
					}
					if diferencaTamanho <= margemErro || qtdPalavras == assinaturaLixo.QtdPalavras {
						isFalsoPositivo = true
					}
				}

				if !isFalsoPositivo {
					parsedUrl, _ := url.Parse(urlTeste)
					risco := classificarRisco(parsedUrl)
					AvaliarResposta(statusAtual, bodyBytes, urlTeste, risco)

					switch statusAtual {
					case 200, 403, 500: 
						resultadoTXT := fmt.Sprintf("[%d] [%s] %s (Tamanho: %d)", statusAtual, risco, urlTeste, tamanhoResposta)
						rotasVivas = append(rotasVivas, resultadoTXT)
						if risco == "ALTO" {
							alertaTelegram := fmt.Sprintf("*GoHunt [ALTO RISCO]*\n*Alvo:* %s\n*URL:* %s", alvo.URL, urlTeste)
							logsTelegram = append(logsTelegram, alertaTelegram)
							fmt.Printf("%s - \033[31m[OURO ENCONTRADO]:\033[0m [%d] %s \n", momento(tempo), statusAtual, urlTeste)
						} else {
							fmt.Printf("%s - \033[32m [INFO] ENCONTRADO:\033[0m [%d] %s \n", momento(tempo), statusAtual, urlTeste)
						}
					case 301, 302:
						destinoRedirect := resp.Header.Get("Location")
						if destinoRedirect != "" && destinoRedirect != "/" && !strings.HasSuffix(destinoRedirect, "/login") {
							resultadoTXT := fmt.Sprintf("[%d] %s -> Apontou para: %s", statusAtual, urlTeste, destinoRedirect)
							rotasVivas = append(rotasVivas, resultadoTXT)
							fmt.Printf("\033[33m[*] REDIRECT:\033[0m [%d] %s -> %s\n", statusAtual, urlTeste, destinoRedirect)
						}
					}
				}

				atual := atomic.AddUint64(&urlsTestadas, 1)
				if atual > 0 && atual%1000 == 0 {
					fmt.Printf("%s - \033[36m[PROGRESSO]\033[0m Alvo %s -> %d URLs disparadas...\n", momento(tempo), alvo.URL, atual)
				}
			}(caminho)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(rotasVivas) > 0 {
			dominio := extrairDominio(alvo.URL)
			pastaDestino := filepath.Join("Alvos", dominio, "Fuzzing")
			os.MkdirAll(pastaDestino, 0755)
			nomeArquivo := fmt.Sprintf("%s_fuzz_wayback.txt", time.Now().Format("2006-01-02"))
			caminhoCompleto := filepath.Join(pastaDestino, nomeArquivo)

			conteudo := strings.Join(rotasVivas, "\n")

			os.WriteFile(caminhoCompleto, []byte(conteudo), 0644)
			atomic.AddUint64(totalGlobal, uint64(len(rotasVivas)))
		}

		wgFuzz.Wait()
	}
}

func Wayback_probber(lista_arq_laudos []string) {
	jobs := make(chan string, len(lista_arq_laudos))
	workers := 10
	var totalAssetsDescobertos uint64
	ritmo := time.NewTicker(time.Millisecond / time.Duration(3000))
	var wg sync.WaitGroup

	for w := 1; w <= workers; w++ {
		wg.Add(1)
		go wayback_work(jobs, &wg, ritmo, &totalAssetsDescobertos)
	}

	defer ritmo.Stop()
	for _, laudo := range lista_arq_laudos {
		if laudo != "" {
			<-ritmo.C
			jobs <- laudo
		}
	}
	close(jobs)

	wg.Wait()

	fmt.Printf("%s - [SUCESSO] Wayback Machine fuzzing finalizado. Arquivos salvos no disco com a descoberta de [%d] assets ... \n", momento(tempo), totalAssetsDescobertos)
	mensagem := fmt.Sprintf("Foram descobertos um total de [%d] durante o fuzzing utilizando o histórico do wayback machine ... \n", totalAssetsDescobertos)
	telegram(mensagem)
}

func client_probber() *http.Client {
	transporte := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 2 * time.Second,
			}
			return dialer.DialContext(ctx, "tcp4", addr)
		},
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       20,
		IdleConnTimeout:       5 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		DisableKeepAlives:     true,
	}

	return &http.Client{
		Transport: transporte,
		Timeout:   10 * time.Second, 
	}
}

func client_wayback() *http.Client {
	transporte := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &http.Client{
		Transport: transporte,
		Timeout:   60 * time.Second, 
	}
}

func extrairDominio(urlBruta string) string {

	if !strings.HasPrefix(urlBruta, "http://") && !strings.HasPrefix(urlBruta, "https://") {
		urlBruta = "https://" + urlBruta
	}

	u, err := url.Parse(urlBruta)

	if err != nil {
		dominio := strings.ReplaceAll(urlBruta, "https://", "")
		dominio = strings.ReplaceAll(dominio, "http://", "")
		dominio = strings.Split(dominio, "/")[0]
		dominio = strings.Split(dominio, ":")[0]
		return dominio
	}

	return u.Hostname()
}

func momento(agora string) string { 
	agora = time.Now().Format("2006-01-02 15:04:05")
	return agora
}

func IniciarFuzzer(lista_arq_laudos []string) {
	CanalExtrator = make(chan extractor.TarefaRegex, 5000)
	CanalBypass = make(chan bypass.TarefaBypass, 500)

	for i := 0; i < 3; i++ {
		WgExtrator.Add(1)
		go extractor.WorkerExtrator(CanalExtrator, &WgExtrator)
	}

	for i := 0; i < 5; i++ {
		WgBypass.Add(1)
		go bypass.WorkerBypass(CanalBypass, &WgBypass, telegram)
	}

	Wayback_probber(lista_arq_laudos)

	close(CanalExtrator)
	close(CanalBypass)

	fmt.Printf("%s - [INFO] Aguardando Workers de Extração e Bypass finalizarem...\n", momento(tempo))
	WgExtrator.Wait()
	WgBypass.Wait()

	fmt.Printf("%s - [SUCESSO] Pipeline completo finalizado!\n", momento(tempo))
}
