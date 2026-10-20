package modelo

type Component struct {
	SourceType string                       `json:"source_type,omitempty"`
	Facts      map[string]ConditionEvidence `json:"facts,omitempty"`
	URL        string                       `json:"url"`
	Product    string                       `json:"product,omitempty"`
	Name       string                       `json:"name,omitempty"`
	Ecosystem  string                       `json:"ecosystem,omitempty"`
	Version    string                       `json:"version"`
	Evidence   string                       `json:"evidence"`
}

type ConditionEvidence struct {
	Present  bool   `json:"present"`
	Evidence string `json:"evidence"`
}

func ComponentRecord(c Component) Record {
	confidence := "declarada"
	if c.SourceType == "inventory" {
		confidence = "informada pelo responsável; não atestada pelo GoHunt"
	}
	status := "desconhecida"
	if c.Version != "" {
		status = "declarada"
	}
	return Record{Kind: "component", URL: c.URL, Priority: 5, Summary: "Produto observado; versão e confiança disponíveis nas evidências", Evidence: map[string]string{"product": c.Product, "package": c.Name, "ecosystem": c.Ecosystem, "version": c.Version, "version_status": status, "source_type": c.SourceType, "signal": c.Evidence, "confidence": confidence, "assessment": "observed"}}
}
