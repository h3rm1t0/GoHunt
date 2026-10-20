package testes

import (
	"GoHunt/Configuracao"
	"GoHunt/Estado"
	"GoHunt/Modelo"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Fixtures produced by the previous implementation, using only synthetic data.
// They protect resume fingerprints, record identities, and journal compatibility.
func TestCompatibilidadeComEstadoAnterior(t *testing.T) {
	var fixture struct {
		Config      configuracao.Config `json:"config"`
		Fingerprint string              `json:"fingerprint"`
		Record      modelo.Record       `json:"record"`
		RecordID    string              `json:"record_id"`
		GroupID     string              `json:"group_id"`
		Task        modelo.Task         `json:"task"`
		TaskID      string              `json:"task_id"`
	}
	data, err := os.ReadFile("testdata/contrato-anterior.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	fp, err := configuracao.Fingerprint(fixture.Config)
	if err != nil {
		t.Fatal(err)
	}
	if fp != fixture.Fingerprint {
		t.Fatal("fingerprint incompatível com a versão anterior")
	}
	if fixture.Task.ID() != fixture.TaskID || modelo.RecordID(fixture.Record) != fixture.RecordID || modelo.DisplayID(fixture.Record) != fixture.GroupID {
		t.Fatal("identidades alteradas durante a reorganização")
	}
	journal, err := os.ReadFile("testdata/estado-anterior.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "state.jsonl")
	if err = os.WriteFile(state, journal, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := estado.OpenStore(state, fp, true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if len(store.Tasks) != 1 || store.Tasks[0].ID() != fixture.TaskID || !store.RecordKeys[fixture.RecordID] {
		t.Fatal("retomada não preservou tarefa e registro anteriores")
	}
}
