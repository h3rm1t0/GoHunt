package escopo

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

var tempo string

func momento(agora string) string { 
		agora = time.Now().Format("2006-01-02 15:04:05")
	return agora
}

type Escopo struct {
	regras_exatas  map[string]bool
	regras_curinga []string
}

func CarregarEscopo(caminho string) *Escopo {
	e := &Escopo{
		regras_exatas:  make(map[string]bool),
		regras_curinga: make([]string, 0),
	}

	file, err := os.Open(caminho)
	if err != nil {
		fmt.Printf(momento(tempo)+" - [ERRO] Arquivo de escopo não encontrado: %s\n", caminho)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		linha := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if linha == "" || strings.HasPrefix(linha, "#") {
			continue 
		}

		if strings.HasPrefix(linha, "*.") {
			e.regras_curinga = append(e.regras_curinga, linha[1:])
		} else {
			e.regras_exatas[linha] = true
		}
	}

	fmt.Printf(momento(tempo)+" - [INFO] Escopo carregado com sucesso: %d regras exatas, %d curingas ... \n", len(e.regras_exatas), len(e.regras_curinga))
	return e
}

func (e *Escopo) Permitido(alvo string) bool {
	alvoLimpo := strings.TrimSpace(strings.ToLower(alvo))

	alvoLimpo = strings.TrimPrefix(alvoLimpo, "http://")
	alvoLimpo = strings.TrimPrefix(alvoLimpo, "https://")
	alvoLimpo = strings.Split(alvoLimpo, "/")[0]

	if e.regras_exatas[alvoLimpo] {
		return true
	}

	for _, curinga := range e.regras_curinga {
		if strings.HasSuffix(alvoLimpo, curinga) {
			return true
		}
	}

	return false
}

func (e *Escopo) GerarSementes() []string {
	sementes_unicas := make(map[string]bool)

	for alvoExato := range e.regras_exatas {
		sementes_unicas[alvoExato] = true
	}

	for _, curinga := range e.regras_curinga {
		raiz := strings.TrimPrefix(curinga, ".")
		sementes_unicas[raiz] = true
	}

	var listaSementes []string
	for semente := range sementes_unicas {
		listaSementes = append(listaSementes, semente)
	}

	return listaSementes
}
