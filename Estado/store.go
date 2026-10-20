package estado

import (
	"GoHunt/Escopo"
	"GoHunt/Modelo"
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func (s *Store) Close() error { return s.file.Close() }

type Event struct {
	Version     int             `json:"version,omitempty"`
	Fingerprint string          `json:"fingerprint,omitempty"`
	Done        string          `json:"done,omitempty"`
	Tasks       []modelo.Task   `json:"tasks,omitempty"`
	Records     []modelo.Record `json:"records,omitempty"`
}

type Store struct {
	PageRoutes       map[string]int
	PageHosts        map[string]int
	RecordKeys       map[string]bool
	HistoricalRoutes map[string]bool
	KindTotal        map[string]int
	KindDone         map[string]int
	TaskKinds        map[string]string
	file             *os.File
	Tasks            []modelo.Task
	Known            map[string]bool
	Done             map[string]bool
	Count            int
	Completed        int
	RecordCount      int
	RecordCounts     [6]int
}

func (s *Store) Append(ev Event) error {
	ev.Records = s.UniqueRecords(ev.Records)
	now := time.Now().UTC().Format(time.RFC3339)
	for i := range ev.Records {
		if ev.Records[i].ObservedAt == "" {
			ev.Records[i].ObservedAt = now
		}
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	n, err := s.file.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	if err = s.file.Sync(); err != nil {
		return err
	}
	s.apply(ev)
	return nil
}

func (s *Store) apply(ev Event) {
	if s.RecordKeys == nil {
		s.RecordKeys = map[string]bool{}
		s.PageHosts = map[string]int{}
		s.PageRoutes = map[string]int{}
		s.HistoricalRoutes = map[string]bool{}
	}
	if s.KindTotal == nil {
		s.KindTotal = map[string]int{}
		s.KindDone = map[string]int{}
		s.TaskKinds = map[string]string{}
	}

	for _, t := range ev.Tasks {
		if modelo.Historical(t) {
			s.HistoricalRoutes[escopo.RouteKey(t.URL)] = true
		}
		if !s.Known[t.ID()] {
			s.Known[t.ID()] = true
			s.Tasks = append(s.Tasks, t)
			s.Count++
			if t.Kind == "page" {
				s.PageHosts[escopo.RecordHost(t.URL)]++
				s.PageRoutes[escopo.RouteKey(t.URL)]++
			}
			s.KindTotal[t.Kind]++
			s.TaskKinds[t.ID()] = t.Kind
		}
	}
	if ev.Done != "" {
		if s.Known[ev.Done] && !s.Done[ev.Done] {
			s.Completed++
			s.KindDone[s.TaskKinds[ev.Done]]++
		}
		s.Done[ev.Done] = true
	}
	for _, r := range ev.Records {
		id := modelo.RecordID(r)
		if s.RecordKeys[id] {
			continue
		}
		s.RecordKeys[id] = true
		s.RecordCount++
		if r.Priority >= 1 && r.Priority <= 5 {
			s.RecordCounts[r.Priority]++
		}
	}
}

func (s *Store) Commit(t modelo.Task, children []modelo.Task, records []modelo.Record, max int) error {
	var fresh []modelo.Task
	seen := map[string]bool{}
	routes := map[string]bool{}
	for _, x := range children {
		if modelo.Historical(x) {
			key := escopo.RouteKey(x.URL)
			if s.HistoricalRoutes[key] || routes[key] {
				continue
			}
			routes[key] = true
		}
		id := x.ID()
		if !s.Known[id] && !seen[id] {
			fresh = append(fresh, x)
			seen[id] = true
		}
	}
	if s.Count+len(fresh) > max {
		return fmt.Errorf("limite de %d tarefas atingido; tarefa atual continua pendente; retome com --resume --max-tasks maior", max)
	}
	return s.Append(Event{Done: t.ID(), Tasks: fresh, Records: records})
}

func OpenStore(path, fingerprint string, resume bool) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	flags := os.O_RDWR | os.O_CREATE
	if !resume {
		flags |= os.O_EXCL
	}
	if resume {
		flags = os.O_RDWR
	}
	f, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return nil, fmt.Errorf("estado (use --resume para continuar): %w", err)
	}
	fail := func(e error) (*Store, error) { f.Close(); return nil, e }
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail(errors.New("outra execução já está usando este estado"))
	}
	s := &Store{file: f, Known: map[string]bool{}, Done: map[string]bool{}}
	if !resume {
		if err = s.Append(Event{Version: 1, Fingerprint: fingerprint}); err != nil {
			return fail(err)
		}
		return s, nil
	}
	rd := bufio.NewReader(f)
	var offset int64
	first := true
	for {
		line, readErr := readLine(rd)
		if readErr == io.EOF {
			if len(line) > 0 {
				if err = f.Truncate(offset); err != nil {
					return fail(err)
				}
			}
			break
		}
		if readErr != nil {
			return fail(readErr)
		}
		var ev Event
		if err = json.Unmarshal(line, &ev); err != nil {
			return fail(fmt.Errorf("estado corrompido no byte %d: %w", offset, err))
		}
		if first {
			if ev.Version != 1 || ev.Fingerprint != fingerprint {
				return fail(errors.New("estado incompatível: escopo, wordlists ou opções de exploração mudaram"))
			}
			first = false
		}
		s.apply(ev)
		offset += int64(len(line))
	}
	if first {
		return fail(errors.New("estado vazio/incompleto; utilize novo arquivo"))
	}
	_, err = f.Seek(0, io.SeekEnd)
	if err != nil {
		return fail(err)
	}
	return s, nil
}

// Each line is one durable transaction: result + next tasks + completion marker.
// A torn final line can be discarded; its task remains pending for at-least-once execution.
// Limit malformed journal lines to avoid unbounded allocations during replay.
func readLine(reader *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		if len(line)+len(chunk) > 32<<20 {
			return nil, errors.New("linha de estado excede 32MiB")
		}
		line = append(line, chunk...)
		if err != bufio.ErrBufferFull {
			return line, err
		}
	}
}

func WalkRecords(path string, fn func(modelo.Record)) error { return WalkRecordsAt(path, -1, fn) }

func WalkRecordsAt(path string, size int64, fn func(modelo.Record)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	// Snapshot prevents an active writer from extending a report indefinitely.
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if size < 0 {
		size = info.Size()
	}
	rd := bufio.NewReader(io.LimitReader(f, size))
	seenRecords := map[string]bool{}
	for {
		line, e := readLine(rd)
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		var ev Event
		if e = json.Unmarshal(line, &ev); e != nil {
			return e
		}
		for _, r := range ev.Records {
			id := modelo.RecordID(r)
			if !seenRecords[id] {
				seenRecords[id] = true
				fn(r)
			}
		}
	}
}
