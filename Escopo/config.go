package escopo

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

func (s *Scope) Allows(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	h := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if s.Exact[h] {
		return true
	}
	for _, w := range s.Wild {
		if strings.HasSuffix(h, "."+w) {
			return true
		}
	}
	return false
}

type Scope struct {
	Exact map[string]bool
	Wild  []string
	Seeds []string
	URLs  []string
}

func LoadScope(path string) (*Scope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := &Scope{Exact: map[string]bool{}}
	seen := map[string]bool{}
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		wildcard := strings.HasPrefix(line, "*.")
		raw := strings.TrimPrefix(line, "*.")
		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			return nil, fmt.Errorf("escopo inválido: %q", line)
		}
		host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		if !ValidHost(host) {
			return nil, fmt.Errorf("host inválido: %q", host)
		}
		if wildcard {
			if net.ParseIP(host) != nil || u.Port() != "" || u.Path != "" {
				return nil, fmt.Errorf("curinga inválido: %s", line)
			}
			s.Wild = append(s.Wild, host)
		} else {
			s.Exact[host] = true
			canonical, _ := Normalize(raw)
			s.URLs = append(s.URLs, canonical)
		}
		if !seen[host] {
			s.Seeds = append(s.Seeds, host)
			seen[host] = true
		}
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}
	if len(s.Seeds) == 0 {
		return nil, errors.New("escopo vazio")
	}
	return s, nil
}

func Normalize(raw string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil {
		return "", e
	}
	if u.User != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", errors.New("URL inválida")
	}
	u.Fragment = ""
	u.Host = strings.ToLower(u.Host)
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

func ValidHost(h string) bool {
	if net.ParseIP(h) != nil {
		return true
	}
	if len(h) > 253 {
		return false
	}
	for _, p := range strings.Split(h, ".") {
		if len(p) == 0 || len(p) > 63 || p[0] == '-' || p[len(p)-1] == '-' {
			return false
		}
		for _, c := range p {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
