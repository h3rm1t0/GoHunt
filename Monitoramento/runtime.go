package monitoramento

import (
	"GoHunt/Estado"
	"fmt"
	"sync"
	"time"
)

type Runtime struct {
	activeKind  string
	ActiveSince time.Time `json:"-"`
	stopped     time.Time
	started     time.Time
	durations   map[string]time.Duration
	samples     map[string]int

	Mu   sync.RWMutex `json:"-"`
	info RuntimeInfo
}

func minutesSeconds(d time.Duration) string {
	seconds := int(d.Seconds())
	return fmt.Sprintf("%02dm %02ds", seconds/60, seconds%60)
}

func (r *Runtime) Observe(kind string, d time.Duration) {
	r.Mu.Lock()
	defer r.Mu.Unlock()
	if r.samples == nil {
		r.samples = map[string]int{}
		r.durations = map[string]time.Duration{}
	}
	r.activeKind = ""
	r.ActiveSince = time.Time{}
	r.samples[kind]++
	r.durations[kind] += d
}

type RuntimeInfo struct {
	ActiveElapsed string               `json:"active_elapsed,omitempty"`
	SampledAt     string               `json:"sampled_at"`
	Percent       float64              `json:"percent"`
	Timing        string               `json:"timing"`
	Stages        map[string]StageInfo `json:"stages,omitempty"`

	State     string `json:"state"`
	Phase     string `json:"phase"`
	Target    string `json:"target,omitempty"`
	Running   bool   `json:"running"`
	Total     int    `json:"total_tasks"`
	Completed int    `json:"completed_tasks"`
	Pending   int    `json:"pending_tasks"`
	Failures  int    `json:"failures"`
	Records   int    `json:"records"`
	Counts    [6]int `json:"counts"`
	UpdatedAt string `json:"updated_at"`
}

func (r *Runtime) Snapshot() RuntimeInfo {
	if r == nil {
		return RuntimeInfo{State: "consulta", Phase: "Consulta a resultados existentes"}
	}
	r.Mu.RLock()
	defer r.Mu.RUnlock()
	info := r.info
	info.Stages = make(map[string]StageInfo, len(r.info.Stages))
	now := time.Now()
	info.SampledAt = now.UTC().Format(time.RFC3339)
	elapsedEnd := now
	if !r.stopped.IsZero() {
		elapsedEnd = r.stopped
	}
	var remaining time.Duration
	known := true
	for kind, stage := range r.info.Stages {
		pending := stage.Total - stage.Completed
		stage.Status = "aguardando"
		if pending == 0 {
			stage.Status = "concluída"
			stage.Remaining = "00m 00s"
		} else if !info.Running {
			stage.Status = "pendente"
			stage.Remaining = "retomada necessária"
			known = false
		} else if r.samples[kind] > 0 {
			avg := r.durations[kind] / time.Duration(r.samples[kind])
			eta := avg * time.Duration(pending)
			if kind == r.activeKind && !r.ActiveSince.IsZero() {
				active := now.Sub(r.ActiveSince)
				stage.Status = "em execução"
				stage.ActiveElapsed = minutesSeconds(active)
				info.ActiveElapsed = stage.ActiveElapsed
				if active >= avg {
					stage.Remaining = "recalculando: tarefa acima da média"
					known = false
				} else {
					eta -= active
					stage.Remaining = minutesSeconds(eta)
					remaining += eta
				}
			} else {
				stage.Remaining = minutesSeconds(eta)
				remaining += eta
			}
		} else {
			known = false
			stage.Remaining = "calculando"
			if kind == r.activeKind && !r.ActiveSince.IsZero() {
				stage.Status = "em execução"
				stage.ActiveElapsed = minutesSeconds(now.Sub(r.ActiveSince))
				info.ActiveElapsed = stage.ActiveElapsed
			}
		}
		info.Stages[kind] = stage
	}
	eta := "calculando"
	if known {
		eta = minutesSeconds(remaining)
	}
	if info.Running {
		info.Timing = fmt.Sprintf("%.1f%% | decorrido %s | restante ~%s (fila conhecida; pode crescer)", info.Percent, minutesSeconds(elapsedEnd.Sub(r.started)), eta)
	} else {
		info.Timing = fmt.Sprintf("%.1f%% | duração %s | pendentes %d", info.Percent, minutesSeconds(elapsedEnd.Sub(r.started)), info.Pending)
	}
	return info
}

type StageInfo struct {
	Status        string  `json:"status"`
	ActiveElapsed string  `json:"active_elapsed,omitempty"`
	Total         int     `json:"total"`
	Completed     int     `json:"completed"`
	Percent       float64 `json:"percent"`
	Remaining     string  `json:"remaining"`
}

func (r *Runtime) StartTask(kind string) {
	r.Mu.Lock()
	defer r.Mu.Unlock()
	r.activeKind = kind
	r.ActiveSince = time.Now()
}

func (r *Runtime) Update(state, phase, target string, running bool, s *estado.Store, failures int) {
	info := RuntimeInfo{State: state, Phase: phase, Target: target, Running: running, Failures: failures, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	if s != nil {
		info.Total = s.Count
		info.Completed = s.Completed
		info.Pending = s.Count - s.Completed
		info.Records = s.RecordCount
		info.Counts = s.RecordCounts
	}
	r.Mu.Lock()
	if running {
		r.stopped = time.Time{}
	} else {
		r.stopped = time.Now()
		r.activeKind = ""
		r.ActiveSince = time.Time{}
	}
	if r.started.IsZero() {
		r.started = time.Now()
	}
	info.Stages = map[string]StageInfo{}
	if s != nil {
		if s.Count > 0 {
			info.Percent = 100 * float64(s.Completed) / float64(s.Count)
		}
		for kind, total := range s.KindTotal {
			stage := StageInfo{Total: total, Completed: s.KindDone[kind]}
			if total > 0 {
				stage.Percent = 100 * float64(stage.Completed) / float64(total)
			}
			info.Stages[kind] = stage
		}
	}
	r.info = info
	r.Mu.Unlock()
}
