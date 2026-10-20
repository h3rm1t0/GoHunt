package estado

import (
	"GoHunt/Modelo"
)

func (s *Store) UniqueRecords(records []modelo.Record) []modelo.Record {
	seen := map[string]bool{}
	var out []modelo.Record
	for _, r := range records {
		id := modelo.RecordID(r)
		if !s.RecordKeys[id] && !seen[id] {
			seen[id] = true
			out = append(out, r)
		}
	}
	return out
}
