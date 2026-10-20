package db

import (
	"GoHunt/Modelo"
	"strings"
)

func MissingRequirements(a Advisory, c modelo.Component) []string {
	var missing []string
	for _, r := range a.Requires {
		if !c.Facts[r].Present || strings.TrimSpace(c.Facts[r].Evidence) == "" {
			missing = append(missing, r)
		}
	}
	return missing
}
