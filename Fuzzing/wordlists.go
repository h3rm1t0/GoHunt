package fuzzing

import (
	"GoHunt/Diffing"
	"GoHunt/Escopo"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"GoHunt/Rede"
	"GoHunt/Util"
	"bufio"
	"context"
	"errors"
	"io"
	"net/url"
	"os"
	"strings"
)

func Brute(e *nucleo.Engine, ctx context.Context, t modelo.Task) ([]modelo.Task, []modelo.Record, error) {
	resp, err := rede.Request(e, ctx, t.URL, "GET", nil, "", false)
	if err != nil {
		return nil, nil, err
	}
	if resp.Status == 404 || resp.Status == 410 {
		return nil, nil, nil
	}
	if resp.Status >= 200 && resp.Status < 300 {
		for i := 0; i < 2; i++ {
			control := escopo.Origin(t.URL) + "gohunt-missing-" + util.RandomID()
			if t.Source == "dir" {
				control += "/"
			}
			r, err := rede.Request(e, ctx, control, "GET", nil, "", false)
			if err != nil {
				return nil, nil, err
			}
			if diffing.Similar(resp, r) {
				return nil, []modelo.Record{{Kind: "filtered", URL: t.URL, Priority: 5, Summary: "Possível soft-404/catch-all; excluído do crawler"}}, nil
			}
		}
	}
	return []modelo.Task{{Kind: "page", URL: t.URL, Source: "wordlist-" + t.Source}}, nil, nil
}

func Wordlist(e *nucleo.Engine, t modelo.Task) ([]modelo.Task, []modelo.Record, error) {
	f, err := os.Open(t.Path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	if _, err = f.Seek(t.Offset, io.SeekStart); err != nil {
		return nil, nil, err
	}
	reader := bufio.NewReaderSize(f, 65536)
	offset := t.Offset
	for {
		bytes, err := reader.ReadSlice('\n')
		line := string(bytes)
		offset += int64(len(line))
		if err != nil && err != io.EOF {
			return nil, nil, err
		}
		if len(line) > 65536 {
			return nil, nil, errors.New("entrada de wordlist excede 64KiB")
		}
		word := strings.TrimSpace(line)
		if word == "" || strings.HasPrefix(word, "#") {
			if err == io.EOF {
				return nil, nil, nil
			}
			continue
		}
		next := t
		next.Offset = offset
		var tasks []modelo.Task
		if err != io.EOF {
			tasks = append(tasks, next)
		}
		if t.Source == "sub" {
			host := strings.ToLower(word) + "." + t.URL
			if escopo.ValidHost(host) && e.Scope.Allows("https://"+host+"/") {
				tasks = append(tasks, modelo.Task{Kind: "dns", URL: host, Source: t.URL})
			}
		} else {
			base, _ := url.Parse(t.URL)
			ref, x := url.Parse(word)
			if x != nil || ref.IsAbs() || ref.Host != "" || ref.User != nil {
				return tasks, []modelo.Record{{Kind: "wordlist", URL: t.URL, Priority: 5, Summary: "Entrada ignorada: deve ser caminho relativo", Source: t.Path}}, nil
			}
			raw := base.ResolveReference(ref).String()
			if t.Source == "dir" {
				u, _ := url.Parse(raw)
				u.Path = strings.TrimSuffix(u.Path, "/") + "/"
				raw = u.String()
			}
			raw, normErr := escopo.Normalize(raw)
			if normErr == nil && e.Scope.Allows(raw) {
				tasks = append(tasks, modelo.Task{Kind: "brute", URL: raw, Source: t.Source})
			}
		}
		return tasks, nil, nil
	}
}
