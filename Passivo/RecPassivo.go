package passivo

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json" 
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var tempo string

var servidoresDNS = []string{
	"8.8.8.8:53",         // Google
	"8.8.4.4:53",         // Google Secundário
	"1.1.1.1:53",         // Cloudflare
	"1.0.0.1:53",         // Cloudflare Secundário
	"9.9.9.9:53",         // Quad9
	"149.112.112.112:53", // Quad9 Secundário
	"208.67.222.222:53",  // OpenDNS
	"208.67.220.220:53",  // OpenDNS Secundário
}

var contadorDNS uint64

func ProxDNS() string {
	dnsatual := atomic.AddUint64(&contadorDNS, 1)
	indice := dnsatual % uint64(len(servidoresDNS))
	return servidoresDNS[indice]
}

type CrtShResult struct {
	IssuerCaID     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"` 
	ID             int64  `json:"id"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
}

func resolvedorDNS(jobs <-chan string, results chan<- string, wg *sync.WaitGroup) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{
				Timeout: 5 * time.Second,
			}

			ProxDns := ProxDNS()

			return dialer.DialContext(ctx, "udp", ProxDns)
		},
	}

	defer wg.Done()
	for subdominio := range jobs {
		ips, err := resolver.LookupHost(context.Background(), subdominio)
		if err == nil {
			for _, ip := range ips {
				fmt.Printf(momento(tempo)+" - [INFO] Host %s --> %s ... \n", subdominio, ip)
				resultado := fmt.Sprintf("%s", ip)
				results <- resultado
			}
		}
	}
}

func gerar_arquivo_bruto(input string, dir string) (string, error) {
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return "", fmt.Errorf("%s - [ERRO] Falha ao criar diretório: %v\n", momento(tempo), err)
	}

	nome_arq := fmt.Sprintf("%s_subdominios_bruto.txt", momento_2(tempo))
	dir_lista := filepath.Join(dir, nome_arq)
	arquivo, err := os.Create(dir_lista)
	if err != nil {
		return "", fmt.Errorf("%s - [ERRO] Falha ao criar o arquivo bruto", momento(tempo))
	}
	defer arquivo.Close()

	fmt.Printf("%s - [INFO] Consultando crt.sh...\n", momento(tempo))
	subs_crt := Busca_CRT(input)
	fmt.Printf("%s - [INFO] crt.sh retornou %d registros.\n", momento(tempo), len(subs_crt))

	// fmt.Printf("%s - [INFO] Consultando AlienVault OTX (Max 10s)...\n", momento(tempo))
	// subs_otx := Busca_OTX(input)
	// fmt.Printf("%s - [INFO] AlienVault retornou %d registros.\n", momento(tempo), len(subs_otx))

	// todas_fontes := append(subs_crt, subs_otx...)

	todas_fontes := subs_crt

	if len(todas_fontes) == 0 {
		return "", fmt.Errorf("%s - [ERRO FATAL] Nenhuma fonte retornou dados para o alvo", momento(tempo))
	}

	for _, sub := range todas_fontes {
		arquivo.WriteString(sub + "\n")
	}

	return dir_lista, nil
}

type OTXResponse struct {
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
}

func Busca_OTX(dominio string) []string {
	var subdominios []string
	urlOTX := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", dominio)
	client := &http.Client{Timeout: 15 * time.Second}
	maxTentativas := 5
	delayAtraso := 2 * time.Second

	for tentativa := 1; tentativa <= maxTentativas; tentativa++ {
		req, _ := http.NewRequest(http.MethodGet, urlOTX, nil)
		req.Header.Set("User-Agent", "GoHunt-Recon/1.0")

		if apiKey := os.Getenv("OTX_API_KEY"); apiKey != "" {
			req.Header.Set("X-OTX-API-KEY", apiKey)
		}

		resp, err := client.Do(req)

		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			fmt.Printf("%s - [AVISO] OTX Rate Limit ou Erro (Tentativa %d/%d). Aguardando %v...\n", momento(tempo), tentativa, maxTentativas, delayAtraso)

			time.Sleep(delayAtraso)
			delayAtraso *= 2
			continue
		}

		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		var dados OTXResponse
		json.Unmarshal(bodyBytes, &dados)

		for _, registro := range dados.PassiveDNS {
			host := strings.ToLower(strings.TrimSpace(registro.Hostname))
			if strings.HasSuffix(host, dominio) {
				subdominios = append(subdominios, host)
			}
		}
		return subdominios
	}
	return subdominios
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

func Busca_CRT(dominio string) []string {
	var subdominios []string
	url := "http://crt.sh/?q=" + dominio + "&output=json"
	client := &http.Client{Timeout: 50 * time.Second}
	maxTentativas := 5
	delayAtraso := 3 * time.Second

	for tentativa := 1; tentativa <= maxTentativas; tentativa++ {
		Jitter(700, 800)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
		resp, err := client.Do(req)

		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			fmt.Printf("%s - [AVISO] crt.sh Rate Limit ou Erro (Tentativa %d/%d). Aguardando %v...\n", momento(tempo), tentativa, maxTentativas, delayAtraso)

			time.Sleep(delayAtraso)
			delayAtraso *= 2
			continue
		}

		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		var resultados []CrtShResult
		if err := json.Unmarshal(body, &resultados); err != nil {
			fmt.Printf("%s - [ERRO] O crt.sh enviou um JSON corrompido ou uma página HTML de erro.\n", momento(tempo))
			return subdominios
		}

		for _, r := range resultados {
			nomes := strings.Split(r.NameValue, "\n")
			for _, nome := range nomes {
				sanitizado := strings.TrimPrefix(strings.TrimSpace(nome), "*.")
				if sanitizado != "" {
					subdominios = append(subdominios, sanitizado)
				}
			}
		}
		if len(subdominios) == 0 {
			continue
		}
		return subdominios
	}

	return subdominios
}

func dns_recon(dir_subdominios string, dir string) (string, error) {
	jobs := make(chan string, 100)
	results := make(chan string, 100)
	workers := 10

	subdominios, err := os.Open(dir_subdominios)
	if err != nil {
		return "", fmt.Errorf("%s", momento(tempo)+" - [ERRO] Falha ao atribuir subdomínios para recon DNS ... ")
	}

	scanner := bufio.NewScanner(subdominios)
	nome_arq := fmt.Sprintf("%s", momento_2(tempo)+"_subdominios_ips_bruto.txt")
	dir_lista := filepath.Join(dir, nome_arq)
	arquivo, err := os.Create(dir_lista)
	if err != nil {
		return "", fmt.Errorf("%s", momento(tempo)+" - [ERRO] Falha ao criar o arquivo de texto com os ips dos subdomínios ... ")
	}

	go func() {
		for scanner.Scan() {
			sub := scanner.Text()
			sub_limpa := strings.TrimSpace(strings.ToLower(sub))
			jobs <- sub_limpa
		}
		close(jobs)
	}()

	fmt.Println(momento(tempo) + " - [INFO] Iniciando resolução DNS de subdomínios ... ")
	var wg sync.WaitGroup
	for w := 1; w <= workers; w++ {
		wg.Add(1)
		go resolvedorDNS(jobs, results, &wg)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for resultado := range results {
		arquivo.WriteString(resultado + "\n")
	}

	return dir_lista, nil
}

func recon_passivo(input string, dir string) (error, string) {
	bruto, err := gerar_arquivo_bruto(input, dir)
	if err != nil {
		return err, ""
	}
	limpa, err := deduplicação(dir, input, bruto)
	if err != nil {
		return err, ""
	}
	subs_limpa := limpa

	bruto_dns, err := dns_recon(limpa, dir)
	if err != nil {
		return err, subs_limpa
	}

	_, err = deduplicação(dir, input, bruto_dns)

	return nil, subs_limpa
}

func momento(agora string) string {
	agora = time.Now().Format("2006-01-02 15:04:05")
	return agora
}

func momento_2(agora string) string {
	agora = time.Now().Format("2006-01-02")
	return agora
}

func deduplicação(dir string, input string, bruto string) (string, error) {
	o := "bruto"
	n := "limpo"
	nome_arq_limpo := strings.ReplaceAll(bruto, o, n)
	limpa, err := os.Create(nome_arq_limpo)
	if err != nil {
		return "", fmt.Errorf(momento_2(tempo), " - [ERRO] Falha ao tentar criar o arquivo de lista limpa ...")
	}

	mapaUnicos := make(map[string]struct{})
	og, err := os.Open(bruto)
	if err != nil {
		return "", fmt.Errorf(momento(tempo)+" - [ERRO] Falha ao abrir arquivo %s ...", bruto)
	}
	scanner := bufio.NewScanner(og)
	for scanner.Scan() {
		linha := scanner.Text()
		linha_limpa := strings.TrimSpace(strings.ToLower(linha))
		if linha_limpa != "" {
			mapaUnicos[linha_limpa] = struct{}{}
		}
	}
	for sub, _ := range mapaUnicos {
		string := sub + "\n"
		limpa.WriteString(string)
	}
	fmt.Printf(momento(tempo)+" - [SUCESSO] Lista %s limpa gerada como %s ... \n", bruto, nome_arq_limpo)
	return nome_arq_limpo, nil
}

func IniciarPassivo(input string, hoje string) (error, string) {
	input = strings.TrimSpace(input)
	dir := filepath.Join("Alvos", input)
	dir = filepath.Join(dir, "recon_passivo")
	fmt.Printf(momento(tempo)+" - [CHECK-POINT] Iniciando reconhecimento passivo no alvo: [%s] ... \n", input)
	err, subs_limpa := recon_passivo(input, dir)
	if err != nil {
		return fmt.Errorf(momento(tempo)+" - [ERRO] Falha ao tentar executar a varredura de reconhecimento passivo na semente [%s] ... \n", input), ""
	}
	return nil, subs_limpa
}
