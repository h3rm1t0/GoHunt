package diffing

import (
	"GoHunt/Modelo"
	"net/url"
	"path"
	"strings"
)

func BlockPage(r modelo.Response) bool {
	// Login forms remain useful attack-surface records, not WAF noise.
	body := strings.ToLower(string(r.Body))
	for _, marker := range []string{"access denied", "request blocked", "verify you are human", "cf-chl-", "permission denied", "the request could not be satisfied"} {
		if strings.Contains(body, marker) {
			return true
		}
	}
	return false
}

// Keep scripts, APIs, parameters and unknown extensions; skip only known media.
func EndpointRank(raw string) int {
	u, err := url.Parse(raw)
	if err != nil {
		return 1
	}
	if u.RawQuery != "" {
		return 4
	}
	p := strings.ToLower(u.Path)
	for _, part := range []string{"/api", "/admin", "/login", "/auth", "/upload", "/graphql", "/debug", "/config"} {
		if strings.Contains(p, part) {
			return 3
		}
	}
	switch path.Ext(p) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".mp4", ".mp3", ".css":
		return 0
	}
	return 1
}
