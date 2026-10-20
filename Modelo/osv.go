package modelo

import (
	"time"
)

type OsvAdvisory struct {
	ID        string        `json:"id"`
	Aliases   []string      `json:"aliases"`
	Withdrawn string        `json:"withdrawn"`
	Modified  string        `json:"modified"`
	Affected  []osvAffected `json:"affected"`
}

type osvAffected struct {
	Package  OsvPackage `json:"package"`
	Versions []string   `json:"versions"`
	Ranges   []struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	} `json:"ranges"`
}

type OsvCache map[string]OsvCacheEntry

type OsvCacheEntry struct {
	Fetched time.Time     `json:"fetched"`
	Vulns   []OsvAdvisory `json:"vulns"`
}

type OsvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}
