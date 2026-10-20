package diffing

import (
	"GoHunt/Modelo"
	"GoHunt/Util"
	"regexp"
	"strings"
)

func Denied(status int) bool { return status == 401 || status == 403 }

var dynamic = regexp.MustCompile(`(?i)\b[0-9a-f]{12,}\b|\b[0-9]+\b`)

func LoginOrChallenge(r modelo.Response) bool {
	if passwordField.Match(r.Body) {
		return true
	}
	s := strings.ToLower(string(r.Body))
	for _, marker := range []string{"type=\"password\"", "type='password'", "access denied", "verify you are human", "cf-chl-", "captcha", "unauthorized", "permission denied"} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

var markup = regexp.MustCompile(`<[^>]*>`)

var passwordField = regexp.MustCompile(`(?i)type\s*=\s*["']?password\b`)

func Similar(a, b modelo.Response) bool {
	if a.Status != b.Status {
		return false
	}
	if util.Digest(string(a.Body)) == util.Digest(string(b.Body)) {
		return true
	}
	aa, bb := tokens(a.Body), tokens(b.Body)
	intersection := 0
	for key := range aa {
		if bb[key] {
			intersection++
		}
	}
	union := len(aa) + len(bb) - intersection
	return union > 0 && float64(intersection)/float64(union) >= 0.90
}

func tokens(body []byte) map[string]bool {
	text := strings.ToLower(string(body))
	text = markup.ReplaceAllString(text, " ")
	text = dynamic.ReplaceAllString(text, "#")
	set := map[string]bool{}
	for _, word := range strings.Fields(text) {
		set[word] = true
	}
	return set
}
