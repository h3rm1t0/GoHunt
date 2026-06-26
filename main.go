package main

import (
	ativo "GoHunt/Ativo"
	diffing "GoHunt/Diffing"
	escopo "GoHunt/Escopo"
	fuzzing "GoHunt/Fuzzing"
	passivo "GoHunt/Passivo"
	vuln "GoHunt/Vuln"
	"bufio"
	_ "embed"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Estado struct {
	Pass struct {
		UltPass string `json:"ult_pass"`
		Fin     bool   `json:"fin"`
	} `json:"pass"`
	Act struct {
		UltAct string `json:"ult_act"`
		Fin    bool   `json:"fin"`
	} `json:"act"`
	Dif struct {
		UltDif string `json:"ult_dif"`
		Fin    bool   `json:"fin"`
	} `json:"dif"`
	Fuz struct {
		UltFuz string `json:"ult_fuz"`
		Fin    bool   `json:"fin"`
	} `json:"fuz"`
	Ext struct {
		UltExt string `json:"ult_ext"`
		Fin    bool   `json:"fin"`
	} `json:"ext"`
	Byp struct {
		UltByp string `json:"ult_byp"`
		Fin    bool   `json:"fin"`
	} `json:"byp"`
	Vuln struct {
		UltVuln string `json:"ult_vuln"`
		Fin     bool   `json:"fin"`
	} `json:"vuln"`
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

type Laudo struct {
	URL           string
	StatusCode    int
	Server        []string
	Allow         string
	ContentLength int64
	Tecnologia    []string
	WAF           string
}

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

type Tiro struct {
	Laudo Laudo
	Vuln  Arsenal_vulns
}

var tempo string

func SalvarEstado(x int) {
	if x == 1 {

	}
}

func ExibirBanner() {
	banner, err := os.ReadFile("banner.txt")
	if err != nil {
		return
	}

	fmt.Println(string(banner))
}

func leitura_rec_passivo(caminhoArquivo string) []string {
	var subdominios []string

	file, err := os.Open(caminhoArquivo)
	if err != nil {
		fmt.Printf("[ERRO] Não foi possível abrir os resultados em: %s\n", caminhoArquivo)
		return subdominios
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		linha := strings.TrimSpace(scanner.Text())
		if linha != "" {
			subdominios = append(subdominios, linha)
		}
	}

	return subdominios
}

func momento(agora string) string {
	agora = time.Now().Format("2006-01-02 15:04:05")
	return agora
}

func momento_2(agora string) string {
	agora = time.Now().Format("2006-01-02")
	return agora
}

func main() {

	ExibirBanner()

	var hoje string = momento_2(tempo)

	fmt.Printf("%s", momento(tempo)+" - [INFO] Extraindo sementes e inicializando rotina de varredura ... \n")
	escopo_do_dia := escopo.CarregarEscopo("escopo.txt")
	sementes := escopo_do_dia.GerarSementes()
	fmt.Printf(momento(tempo)+" - [INFO] Extração de %d domínios a partir do escopo ... \n", len(sementes))

	var listaBruta []string
	for _, semente := range sementes {
		fmt.Printf(momento(tempo)+" - [INFO] Iniciando coleta de subdomínios na semente [%s] ... \n", semente)
		err, subs_limpa := passivo.IniciarPassivo(semente, hoje)
		if err != nil {
			fmt.Printf("%s", err)
			continue
		}
		subs_da_semente := leitura_rec_passivo(subs_limpa)
		listaBruta = append(listaBruta, subs_da_semente...)

	}

	mensagem := fmt.Sprintf("ETAPA 1 - Reconhecimento passivo concluído com [%d] subdomínios ... ", len(listaBruta))
	telegram(mensagem)

	fmt.Printf(momento(tempo)+" - [INFO] Tamanho da listaBruta antes do filtro: %d\n", len(listaBruta))
	var listaValida []string

	for _, sub := range listaBruta {
		subLimpo := strings.TrimSpace(sub)

		if len(listaValida) == 0 && len(listaBruta) > 0 {
			fmt.Printf(momento(tempo)+" - [INFO] O que a esteira está tentando validar: %q\n", subLimpo)
		}
		if escopo_do_dia.Permitido(sub) {
			listaValida = append(listaValida, sub)
		}
	}

	SalvarEstado(1)

	N_diff_passivo := diffing.DiffingPassivo(listaValida)
	mensagem = fmt.Sprintf("ETAPA 2 - Diffing de subdomínios do escopo finalizada com [%d] novidades ... \n", N_diff_passivo)
	telegram(mensagem)

	fmt.Printf(momento(tempo)+" - [INFO] Tamanho da listaLimpa antes do filtro: %d\n", len(listaValida))

	arq_subs_validas, err := os.Create("escopo_válido_limpo.txt")
	if err != nil {
		fmt.Printf("%s", momento(tempo)+" - [ERRO] Falha ao criar arquivo de subdomínios limpos e válidos para seguir com reconhecimento ativo ... \n")
	}
	for _, sub := range listaValida {
		arq_subs_validas.WriteString(sub + "\n")
	}
	defer arq_subs_validas.Close()

	var lista_arq_laudo []string
	err, laudo := ativo.IniciarAtivo(listaValida, hoje)
	if err != nil {
		fmt.Printf("%s", err)
	}
	lista_arq_laudo = append(lista_arq_laudo, laudo...)
	fmt.Printf(momento(tempo)+" - [INFO] Laudo do subdominio [%s] foi criado com [%d] ... \n", laudo, len(laudo))

	mensagem = fmt.Sprintf("ETAPA 3 - Reconhecimento ativo concluído com [%d] subdomínios vivos ... ", len(listaValida))
	telegram(mensagem)

	N_diff_ativo := diffing.DiffingAtivo(lista_arq_laudo, listaValida)
	mensagem = fmt.Sprintf("ETAPA 4 - Diffing de laudos do escopo finalizada com [%d] novidades ... \n", N_diff_ativo)

	fuzzing.IniciarFuzzer(lista_arq_laudo)

	fmt.Printf("%s - [INFO] Iniciando varredura de vulnerabilidades ... \n", momento(tempo))
	vuln.IniciarVulnChecker(lista_arq_laudo, listaValida)

	fmt.Printf(momento(tempo)+" - [INFO] Iniciando varredura de vulnerabilidades do laudo [%s] do alvo [%v] ... \n", lista_arq_laudo, listaValida)
	vuln.IniciarVulnChecker(lista_arq_laudo, listaValida)
	fmt.Printf(momento(tempo)+" - [INFO] Finalizando varredura de vulnerabilidades do laudo [%s] do alvo [%v] ... \n", lista_arq_laudo, listaValida)
	mensagem = fmt.Sprintf("ETAPA 6 - Varreadura de vulnerabilidades concluída com [%d] subdomínios vivos ... ", len(lista_arq_laudo))

	fmt.Printf("%s", momento(tempo)+" - [CHECK-POINT] Laudos de análise de vulnerabilidades criados. Rotina sendo finalida ... \n")
}
