package diffing

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Diff_Passivo struct {
	Data_ontem string
	Data_hoje  string
	Alvo       string
	Novidades  []string
}

type DiffAtivo struct {
	URL        string
	Alteracoes []string
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

func diff_passivo_work(semente string, results chan<- Diff_Passivo, hoje time.Time, ontem time.Time) {
	mapa_ontem := make(map[string]struct{})
	var novidades []string

	subs_ontem := fmt.Sprintf("%s__subdominios_limpo.txt", ontem.Format("2006-01-02"))
	dir_ontem := filepath.Join("Alvos", semente, "recon_passivo", subs_ontem)

	arq_subs_ontem, err := os.Open(dir_ontem)
	if err == nil {
		scanner := bufio.NewScanner(arq_subs_ontem)
		for scanner.Scan() {
			linha := scanner.Text()
			if linha != "" {
				mapa_ontem[linha] = struct{}{}
			}
		}
		arq_subs_ontem.Close()
	}

	subs_hoje := fmt.Sprintf("%s__subdominios_limpo.txt", hoje.Format("2006-01-02"))
	dir_hoje := filepath.Join("Alvos", semente, "recon_passivo", subs_hoje)

	arq_subs_hoje, err := os.Open(dir_hoje)
	if err != nil {
		fmt.Printf("%s - [AVISO] Semente %s não tem arquivo de hoje. Pulando...\n", momento(), semente)
		return
	}
	defer arq_subs_hoje.Close()

	scanner := bufio.NewScanner(arq_subs_hoje)
	for scanner.Scan() {
		linha := scanner.Text()
		if linha != "" {
			if _, existia := mapa_ontem[linha]; !existia {
				novidades = append(novidades, linha)
			}
		}
	}

	if len(novidades) == 0 {
		return
	}

	dir_diff := filepath.Join("Alvos", semente, "Diff")
	os.MkdirAll(dir_diff, 0644)
	nome_arq_diff := fmt.Sprintf("%s_diff_passivo.txt", hoje.Format("2006-01-02"))
	caminho_final_diff := filepath.Join(dir_diff, nome_arq_diff)

	arq_saida, err := os.Create(caminho_final_diff)
	if err == nil {
		for _, novo := range novidades {
			arq_saida.WriteString(novo + "\n")
		}
		arq_saida.Close()
	}

	results <- Diff_Passivo{
		Data_ontem: ontem.Format("2006-01-02"),
		Data_hoje:  hoje.Format("2006-01-02"),
		Alvo:       semente,
		Novidades:  novidades,
	}
}

func DiffingPassivo(lista_sementes []string) int {
	jobs := make(chan string, len(lista_sementes))
	results := make(chan Diff_Passivo, len(lista_sementes))
	workers := 5

	hoje := time.Now()
	ontem := hoje.AddDate(0, 0, -1)

	var wg sync.WaitGroup

	for w := 1; w <= workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for semente := range jobs {
				diff_passivo_work(semente, results, hoje, ontem)
			}
		}()
	}

	for _, semente := range lista_sementes {
		jobs <- semente
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	fmt.Printf("%s - [INFO] Iniciando análise de Diffing Passivo para %d sementes...\n", momento(), len(lista_sementes))

	total_novidades := 0
	for diff := range results {
		fmt.Printf("%s - [INFO] NOVIDADE na semente %s: %d novos subdomínios detectados!\n", momento(), diff.Alvo, len(diff.Novidades))
		total_novidades += len(diff.Novidades)
	}

	fmt.Printf("%s - [SUCESSO] Diffing finalizado. Total de %d novos alvos encontrados na infraestrutura global.\n", momento(), total_novidades)

	return total_novidades
}

func calcularDiffArrays(ontem, hoje []string) (adicionados []string, removidos []string) {
	mapOntem := make(map[string]bool)
	mapHoje := make(map[string]bool)

	for _, item := range ontem {
		mapOntem[item] = true
	}
	for _, item := range hoje {
		mapHoje[item] = true
	}

	for _, item := range hoje {
		if !mapOntem[item] {
			adicionados = append(adicionados, item)
		}
	}

	for _, item := range ontem {
		if !mapHoje[item] {
			removidos = append(removidos, item)
		}
	}

	return adicionados, removidos
}

func diff_ativo_work(arq_laudo_hoje string, results chan<- DiffAtivo, ontem time.Time, wg *sync.WaitGroup) {
	defer wg.Done()

	laudosHoje := carregarLaudos(arq_laudo_hoje)

	if len(laudosHoje) == 0 {
		return
	}

	hojeStr := time.Now().Format("2006-01-02")
	ontemStr := ontem.Format("2006-01-02")
	arq_laudo_ontem := strings.Replace(arq_laudo_hoje, hojeStr, ontemStr, 1)

	laudosOntem := carregarLaudos(arq_laudo_ontem)
	if laudosOntem == nil {
		fmt.Printf("%s - [INFO] Não há laudo do dia anterior para diffing, encerrando diff do arquivo [%s]. Pulando ... \n", momento(), arq_laudo_hoje)
		return
	}
	mapaOntem := make(map[string]Laudo)
	for _, l := range laudosOntem {
		mapaOntem[l.URL] = l
	}

	var diffsEncontrados []DiffAtivo

	for _, hoje := range laudosHoje {
		ontemAlvo, existia := mapaOntem[hoje.URL]

		if !existia {
			diffsEncontrados = append(diffsEncontrados, DiffAtivo{
				URL:        hoje.URL,
				Alteracoes: []string{"[NOVO ALVO] O endpoint não existia ontem."},
			})
			continue
		}

		var mudancas []string

		if hoje.StatusCode != ontemAlvo.StatusCode {
			mudancas = append(mudancas, fmt.Sprintf("[STATUS] %d -> %d", ontemAlvo.StatusCode, hoje.StatusCode))
		}
		if hoje.ContentLength != ontemAlvo.ContentLength {
			mudancas = append(mudancas, fmt.Sprintf("[CONTENT-LENGTH] %d -> %d", ontemAlvo.ContentLength, hoje.ContentLength))
		}
		if hoje.WAF != ontemAlvo.WAF {
			mudancas = append(mudancas, fmt.Sprintf("[WAF] '%s' -> '%s'", ontemAlvo.WAF, hoje.WAF))
		}
		if hoje.Allow != ontemAlvo.Allow {
			mudancas = append(mudancas, fmt.Sprintf("[ALLOW HEADERS] '%s' -> '%s'", ontemAlvo.Allow, hoje.Allow))
		}

		addServers, remServers := calcularDiffArrays(ontemAlvo.Server, hoje.Server)
		if len(addServers) > 0 || len(remServers) > 0 {
			alerta := "[SERVERS]"
			if len(addServers) > 0 {
				alerta += fmt.Sprintf(" Adicionados: %v.", addServers)
			}
			if len(remServers) > 0 {
				alerta += fmt.Sprintf(" Removidos: %v.", remServers)
			}
			mudancas = append(mudancas, alerta)
		}

		addTechs, remTechs := calcularDiffArrays(ontemAlvo.Tecnologia, hoje.Tecnologia)
		if len(addTechs) > 0 || len(remTechs) > 0 {
			alerta := "[TECNOLOGIAS]"
			if len(addTechs) > 0 {
				alerta += fmt.Sprintf(" ++ NOVAS: %v.", addTechs)
			}
			if len(remTechs) > 0 {
				alerta += fmt.Sprintf(" -- REMOVIDAS: %v.", remTechs)
			}
			mudancas = append(mudancas, alerta)
		}

		if len(mudancas) > 0 {
			diff := DiffAtivo{URL: hoje.URL, Alteracoes: mudancas}
			diffsEncontrados = append(diffsEncontrados, diff)

			results <- diff
		}
	}

	if len(diffsEncontrados) > 0 {
		hojeStr := time.Now().Format("2006-01-02")
		pastaDoAlvo := filepath.Dir(arq_laudo_hoje)
		caminhoAlvoDiff := filepath.Join(pastaDoAlvo, "Diff", fmt.Sprintf("diff_ativo_%s.json", hojeStr))
		salvarEmArquivo(caminhoAlvoDiff, diffsEncontrados)
	}
}

func DiffingAtivo(lista_arq_laudos_hoje []string, lista_urls []string) int {
	jobs := make(chan string, len(lista_arq_laudos_hoje))
	results := make(chan DiffAtivo, 5000) 
	workers := 5

	hoje := time.Now()
	ontem := hoje.AddDate(0, 0, -1)

	var wgWorkers sync.WaitGroup

	for w := 1; w <= workers; w++ {
		wgWorkers.Add(1)
		go func() {
			for arq := range jobs {
				wgTrab := &sync.WaitGroup{}
				wgTrab.Add(1)
				diff_ativo_work(arq, results, ontem, wgTrab)
				wgTrab.Wait()
			}
			wgWorkers.Done()
		}()
	}

	for _, arq := range lista_arq_laudos_hoje {
		if arq != "" {
			jobs <- arq
		}
	}
	close(jobs) 

	go func() {
		wgWorkers.Wait() 
		close(results)   
	}()

	var compiladoFinal []DiffAtivo
	for diff := range results {
		compiladoFinal = append(compiladoFinal, diff)
	}

	if len(compiladoFinal) > 0 {
		caminhoCompilado := filepath.Join("Alvos", "Diff", fmt.Sprintf("diff_global_%s.json", hoje.Format("2006-01-02")))
		dados, _ := json.MarshalIndent(compiladoFinal, "", "  ")
		os.WriteFile(caminhoCompilado, dados, 0644)
	}

	return len(compiladoFinal)
}

func carregarLaudos(caminhoArquivo string) []Laudo {
	var laudos []Laudo

	arquivo, err := os.Open(caminhoArquivo)
	if err != nil {
		return laudos
	}
	defer arquivo.Close()

	decoder := json.NewDecoder(arquivo)

	for {
		var laudoAtual Laudo

		err := decoder.Decode(&laudoAtual)

		if err == io.EOF {
			break
		}

		if err != nil {
			fmt.Printf("%s - [AVISO] Falha ao decodificar uma linha do JSON: %v .. \n", momento(), err)
			continue
		}

		laudos = append(laudos, laudoAtual)
	}

	return laudos
}

func salvarEmArquivo(caminho string, dados interface{}) {
	diretorio := filepath.Dir(caminho)
	if err := os.MkdirAll(diretorio, 0755); err != nil {
		fmt.Printf("%s - [ERRO] Não foi possível criar o diretório %s: %v\n", momento(), diretorio, err)
		return
	}

	bytesJSON, err := json.MarshalIndent(dados, "", "  ")
	if err != nil {
		fmt.Printf("%s - [ERRO] Falha ao converter dados para JSON: %v\n", momento(), err)
		return
	}

	if err := os.WriteFile(caminho, bytesJSON, 0644); err != nil {
		fmt.Printf("%s - [ERRO] Falha ao salvar arquivo %s: %v\n", momento(), caminho, err)
	}
}

func momento() string {
	return time.Now().Format("2006-01-02 15:04:05")
}
