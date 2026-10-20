package rede

import (
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func Pace(e *nucleo.Engine, ctx context.Context) error {
	d := e.Config.JitterMin
	if delta := e.Config.JitterMax - d; delta > 0 {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(delta)+1))
		if err != nil {
			return err
		}
		d += time.Duration(n.Int64())
	}
	return wait(ctx, d)
}

func Request(e *nucleo.Engine, ctx context.Context, raw, method string, headers map[string]string, body string, external bool) (modelo.Response, error) {
	for attempt := 0; ; attempt++ {
		response, err := RequestOnce(e, ctx, raw, method, headers, body, external)
		var retry *modelo.RetryStatus
		if method != "GET" || attempt >= 2 || !errors.As(err, &retry) {
			return response, err
		}
		delay := time.Second * time.Duration(1<<attempt)
		if retry.Delay > delay {
			delay = retry.Delay
		}
		// Long provider cooldowns remain pending instead of blocking the entire run.
		if delay > 30*time.Second {
			e.Log.Detail("HTTP %d | espera solicitada pelo provedor excede 30s; preservando tarefa | %s", retry.Status, raw)
			return response, err
		}
		e.Log.Detail("HTTP %d | nova tentativa %d/3 após %s | %s", retry.Status, attempt+2, delay, raw)
		if err = wait(ctx, delay); err != nil {
			return modelo.Response{}, err
		}
	}
}

func RequestOnce(e *nucleo.Engine, ctx context.Context, raw, method string, headers map[string]string, body string, external bool) (modelo.Response, error) {
	var zero modelo.Response
	if !external && !e.Scope.Allows(raw) {
		return zero, fmt.Errorf("URL fora de escopo: %s", raw)
	}
	if err := Pace(e, ctx); err != nil {
		return zero, err
	}
	req, err := http.NewRequestWithContext(ctx, method, raw, strings.NewReader(body))
	if err != nil {
		return zero, err
	}
	req.Header.Set("User-Agent", "GoHunt/2.0 (authorized security research)")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	e.Log.Detail("Requisição HTTP | método=%s | URL=%s | fonte externa=%t", method, raw, external)
	resp, err := e.Client.Do(req)
	if err != nil {
		e.Log.Detail("Requisição HTTP falhou | URL=%s | detalhe=%v", raw, err)
		return zero, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, e.Config.MaxBody+1))
	if err != nil {
		return zero, err
	}
	if int64(len(data)) > e.Config.MaxBody {
		return zero, fmt.Errorf("resposta excede --max-body (%d)", e.Config.MaxBody)
	}
	response := modelo.Response{Status: resp.StatusCode, Body: data, Header: resp.Header}
	e.Log.Detail("Resposta HTTP | código=%d | bytes=%d | URL=%s", resp.StatusCode, len(data), raw)
	if resp.StatusCode == 429 || resp.StatusCode >= 500 {
		delay := time.Duration(0)
		if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
			if seconds > 30 {
				delay = time.Hour
			} else if seconds > 0 {
				delay = time.Duration(seconds) * time.Second
			}
		} else if date, err := http.ParseTime(resp.Header.Get("Retry-After")); err == nil {
			delay = time.Until(date)
		}
		return response, &modelo.RetryStatus{Status: resp.StatusCode, Delay: delay}
	}
	return response, nil
}

func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
