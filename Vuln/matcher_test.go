package vuln

import "testing"

func TestMatchRejectsUnsupportedAndEmptyRules(t *testing.T) {
	for _, rule := range []RegraMatcher{{Tipo: "word", Condicao: "AND"}, {Tipo: "dsl", Valores: []string{"true"}, Negativo: true}, {Tipo: "regex", Valores: []string{"["}, Negativo: true}} {
		template := Arsenal_vulns{Validacao: ValidacaoPrecisa{OperadorGlobal: "AND", Regras: []RegraMatcher{rule}}}
		if Match("anything", nil, 200, template) {
			t.Fatalf("invalid rule matched: %+v", rule)
		}
	}
}
