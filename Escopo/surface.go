package escopo

import (
	"net/url"
	"strings"
)

func RecordHost(raw string) string {
	u, err := url.Parse(raw)
	if err == nil && u.Hostname() != "" {
		return strings.ToLower(u.Hostname())
	}
	if ValidHost(raw) {
		return strings.ToLower(raw)
	}
	return ""
}
