package templates

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

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
	Tipo     string   `json:"tipo"`     // "status", "word", "regex"
	Alvo     string   `json:"alvo"`     // "body", "header", "all"
	Valores  []string `json:"valores"`  // Os dados esperados
	Condicao string   `json:"condicao"` // "AND", "OR" interno
	Negativo bool     `json:"negativo"` // Se true, inverte a lógica
}

type ValidacaoPrecisa struct {
	OperadorGlobal string         `json:"operador_global"` // "AND", "OR" global
	Regras         []RegraMatcher `json:"regras"`
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

func Match(body string, headers map[string][]string, status int, template Arsenal_vulns) bool {
	for _, rule := range template.Validacao.Regras {
		if len(rule.Valores) == 0 {
			return false
		}
		if rule.Tipo != "status" && rule.Tipo != "word" && rule.Tipo != "regex" {
			return false
		}
		if rule.Tipo == "regex" {
			for _, pattern := range rule.Valores {
				if _, err := regexp.Compile(pattern); err != nil {
					return false
				}
			}
		}
	}
	return validacao_vuln(body, headers, status, template)
}

func Eligible(technologies, targets []string) bool { return alvo_elegível(technologies, targets) }
