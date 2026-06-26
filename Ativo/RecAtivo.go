package ativo

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/twmb/murmur3"
)

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

type Laudo struct {
	URL           string
	StatusCode    int
	Server        []string
	Allow         string
	ContentLength int64
	Tecnologia    []string
	WAF           string
}

var tempo string

func db_hash() (error, map[string]string) {

	mapa_hashes := make(map[string]string)

	nome_json := filepath.Join("Db", "favhashes.json")
	db_json, err := os.ReadFile(nome_json)
	if err != nil {
		return fmt.Errorf("%s", momento(tempo)+" - [ERRO] Falha ao abrir o arquivo favhashes.json no diretório Db ... \n"), nil
	}
	json.Unmarshal(db_json, &mapa_hashes)
	return nil, mapa_hashes
}

func favicon_work(arq_bruto string, results chan<- Laudo, client *http.Client, mapa_hashes map[string]string) error {
	var item Laudo
	arq_bytes, err := os.ReadFile(arq_bruto)
	if err != nil {
		fmt.Printf("%s - [ERRO] Falha ao abrir e ler arquivo do laudo [%s] no reconhecimento favicon ... \n", momento(tempo), arq_bruto)
	}
	json.Unmarshal(arq_bytes, &item)

	sub := item.URL
	favicon := fmt.Sprintf("%s", sub+"/favicon.ico")
	resp, err := client.Get(favicon)
	if err != nil {
		return fmt.Errorf("%s - [INFO] Não foi possível receber uma resposta válida do servidor ao realizar requisição do favicon ... \n", momento(tempo))
	}
	bytesbody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf(momento(tempo)+" - [ERRO] Falha ao tentar ler os bytes da resposta do %s ... \n", favicon)
	}
	defer resp.Body.Close()

	b64body := base64.StdEncoding.EncodeToString(bytesbody)

	var buffer bytes.Buffer
	for i := 0; i < len(b64body); i += 76 {
		f := 76 + i
		if f > len(b64body) {
			f = len(b64body)
		}
		buffer.WriteString(b64body[i:f])
		buffer.WriteString("\n")
	}

	hash_uint32 := murmur3.Sum32(buffer.Bytes())
	hash_int32 := int32(hash_uint32)
	hash_string := fmt.Sprintf("%d", hash_int32)

	if server_encontrado, validacao := mapa_hashes[hash_string]; validacao {
		item.Server = append(item.Server, server_encontrado)
		item.Tecnologia = append(item.Tecnologia, server_encontrado)
	}

	results <- item

	return nil
}

func recon_favicon(brutos []string, vivos []string) (error, []string) {
	jobs := make(chan string, 1000)
	results := make(chan Laudo, 2000)
	workers := 5

	fmt.Printf("%s", momento(tempo)+" - [INFO] Iniciando etapa de reconhecimento favicon.ico ... \n")

	var wg sync.WaitGroup
	client := client_probber()
	err, mapa_hashes := db_hash()
	if err != nil {
		fmt.Printf("%s - [ERRO] Falha ao tentar montar o mapa da função db_hash no reconhecimento favicon ... \n", momento(tempo))
	}
	ritmo := time.NewTicker(time.Millisecond / time.Duration(1))
	defer ritmo.Stop()
	for w := 1; w <= workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for alvo := range jobs {
				<-ritmo.C
				favicon_work(alvo, results, client, mapa_hashes)
			}
		}()
	}

	go func() {
		for _, arq_bruto := range brutos {
			if arq_bruto != "" {
				jobs <- arq_bruto

			}

		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var nomes_arqs_laudos []string
	for sub := range results {

		url := strings.TrimPrefix(sub.URL, "https://")
		nome_arq_laudo := fmt.Sprintf("%s_laudo_final.json", momento_2(tempo))
		nome_arq_laudo = filepath.Join("Alvos", url, "recon_ativo", nome_arq_laudo)
		laudo, err := os.Create(nome_arq_laudo)
		if err != nil {
			fmt.Printf("%s - [ERRO] Falha ao tentar criar arquivo de laudo final de footprint como [%s] ... \n", momento(tempo), nome_arq_laudo)
		}
		json_bytes, _ := json.Marshal(sub)
		laudo.Write(append(json_bytes, '\n'))
		nomes_arqs_laudos = append(nomes_arqs_laudos, nome_arq_laudo)
	}

	fmt.Printf("%s", momento(tempo)+" - [SUCESSO] Finalização do reconhecimento favicon.ico ... \n")
	return nil, nomes_arqs_laudos
}

func client_probber() *http.Client {
	transporte := &http.Transport{
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
		Timeout:   2 * time.Second,
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

func probber_work(alvo string, results chan<- Laudo, client *http.Client, wappalyzer *wappalyzer.Wappalyze) error {
	req_url := "https://" + alvo
	req, err := http.NewRequest(http.MethodGet, req_url, nil)
	if err != nil {
		return fmt.Errorf("%s", momento(tempo)+" - [ERRO] Falha ao tentar montar a requisição na função probber_work ... \n")
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0")
	req.Header.Set("Host", req_url)
	req.Header.Set("X-Bug-Bounty", "True")
	Jitter(300, 800)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}

	if resp.Body == nil {
		resp.Body.Close()
		return nil
	}
	bytesbody, err := io.ReadAll(resp.Body)
	resp.Body.Close()

	resultado := Laudo{
		URL:           req_url,
		StatusCode:    resp.StatusCode,
		Allow:         resp.Header.Get("Allow"),
		ContentLength: int64(len(bytesbody)),
	}

	server := resp.Header.Get("Server")
	resultado.Server = append(resultado.Server, server)

	fingerprints := wappalyzer.Fingerprint(resp.Header, bytesbody)

	for fingerprint := range fingerprints {
		resultado.Tecnologia = append(resultado.Tecnologia, fingerprint)
	}

	resultado.Tecnologia = append(resultado.Tecnologia, server)
	resultado.Tecnologia = append(resultado.Tecnologia, resp.Header.Get("X-Powered-By"))

	results <- resultado

	return nil
}

func http_probing(inputs []string, hoje string) (error, []string, []string) {
	workers := 5
	jobs := make(chan string, 1000)
	results := make(chan Laudo, 2000)
	for _, input := range inputs {
		input_limpo := strings.TrimPrefix(input, "https://")
		dir := filepath.Join("Alvos", input_limpo, "recon_ativo")
		os.MkdirAll(dir, 0755)
	}

	fmt.Printf("%s", momento(tempo)+" - [INFO] Iniciando cliente HTTP e inicializando HTTP Probing ... \n")
	client := client_probber()

	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		return fmt.Errorf(momento(tempo)+" - [ERRO] Falha ao carregar o motor Wappalyzerz: %v ...\n", err), nil, nil
	}

	var wg sync.WaitGroup

	ritmo := time.NewTicker(time.Millisecond / time.Duration(700))
	defer ritmo.Stop()

	for w := 1; w <= workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for alvo := range jobs {
				<-ritmo.C

				probber_work(alvo, results, client, wappalyzerClient)
			}
		}()
	}

	go func() {
		for _, input := range inputs {
			if input != "" {
				jobs <- input
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var lista_dir_bruto []string
	var lista_nome_vivos []string

	for laudo := range results {
		if laudo.StatusCode == 0 {
			continue
		}

		url := strings.TrimPrefix(laudo.URL, "https://")
		dir := filepath.Join("Alvos", url, "recon_ativo")

		err := os.MkdirAll(dir, 0755)
		if err != nil {
			fmt.Printf("%s - [ERRO] Falha ao criar diretório [%s] :\n %v ... \n", momento(tempo), dir, err)
		}
		nome_arq_vivos := filepath.Join(dir, momento_2(tempo)+"_subdominios_vivos.txt")
		vivos, err := os.Create(nome_arq_vivos)
		if err != nil {
			return fmt.Errorf("%s - [ERRO] Falha ao criar arquivo de hosts vivos... \n", momento(tempo)), nil, nil
		}

		nome_lista_bruto := filepath.Join(dir, momento_2(tempo)+"_fingerprint.json")
		bruto, err := os.Create(nome_lista_bruto)
		if err != nil {
			vivos.Close()
			continue
		}

		if laudo.StatusCode == 200 || laudo.StatusCode == 403 || laudo.StatusCode == 500 {
			vivos_string := fmt.Sprintf("%d - %s\n", laudo.StatusCode, laudo.URL)
			vivos.WriteString(vivos_string)
		}

		json_bytes, _ := json.Marshal(laudo)
		bruto.Write(append(json_bytes, '\n'))

		fmt.Printf("%s - [STATUS %d] [SERVER %s] [TECNOLOGIA %s] [CONTENT-LENGHT %d] [ALLOW %s] %s ...\n",
			momento(tempo), laudo.StatusCode, laudo.Server, laudo.Tecnologia, laudo.ContentLength, laudo.Allow, laudo.URL)

		bruto.Close()
		vivos.Close()

		lista_dir_bruto = append(lista_dir_bruto, nome_lista_bruto)
		lista_nome_vivos = append(lista_nome_vivos, nome_arq_vivos)

	}

	fmt.Printf("%s - [SUCESSO] Criação de [%d] laudos finalizada com sucesso ... \n", momento(tempo), len(lista_dir_bruto))
	return nil, lista_nome_vivos, lista_dir_bruto
}

func momento(agora string) string { 
	agora = time.Now().Format("2006-01-02 15:04:05")
	return agora
}

func momento_2(agora string) string { 
	agora = time.Now().Format("2006-01-02")
	return agora
}

func IniciarAtivo(inputs []string, hoje string) (error, []string) {
	fmt.Printf(momento(tempo)+" - [CHECK-POINT] Iniciando reconhecimento ativo nos [%d] alvos ... \n", len(inputs))

	// }
	err, vivos, bruto := http_probing(inputs, hoje)
	if err != nil {
		return fmt.Errorf(momento(tempo)+" - [ERRO] Falha ao processar o reconhecimento via http prober: %s ...\n", err), nil
	}
	err, laudo := recon_favicon(bruto, vivos)
	if err != nil {
		return fmt.Errorf(momento(tempo)+" - [ERRO] Falha ao processar o reconhecimento favicon: %s ... \n", err), nil
	}

	return nil, laudo
}
