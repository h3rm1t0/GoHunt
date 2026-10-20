package modelo

import (
	"fmt"
	"net/http"
	"time"
)

func (r *RetryStatus) Error() string {
	return fmt.Sprintf("HTTP %d; tarefa pendente para --resume", r.Status)
}

type Response struct {
	Status int
	Body   []byte
	Header http.Header
}

type RetryStatus struct {
	Status int           `json:"-"`
	Delay  time.Duration `json:"-"`
}
