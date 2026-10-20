package util

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func Digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func SplitSources(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, x := range strings.Split(s, ",") {
		x = strings.TrimSpace(x)
		if x != "" && !seen[x] {
			out = append(out, x)
			seen[x] = true
		}
	}
	return out
}
