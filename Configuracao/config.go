package configuracao

import (
	"GoHunt/Db"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"time"
)

type Config struct {
	CVEVerifiers         string `json:",omitempty"`
	CVEMode              string `json:",omitempty"`
	CVEDB                string `json:",omitempty"`
	Components           string `json:",omitempty"`
	OSV                  bool   `json:",omitempty"`
	AllowLegacyTemplates bool   `json:",omitempty"`
	CrawlMode            string `json:",omitempty"`
	MaxPagesPerHost      int    `json:",omitempty"`
	History              string `json:"-"`
	Scope                string
	State                string
	Resume               bool
	JitterMin            time.Duration
	JitterMax            time.Duration
	Timeout              time.Duration
	DirWords             string
	FileWords            string
	SubWords             string
	Sources              string
	Depth                int
	MaxTasks             int
	MaxBody              int64
	SourceLimit          int
	FormGET              bool
	FormValues           string
	Templates            string
	Listen               string `json:"-"`
	Debug                bool   `json:"-"`
}

func Fingerprint(c Config) (string, error) {
	// Performance limits can change on resume; inputs and exploration semantics cannot.
	c.State = ""
	c.Resume = false
	c.JitterMin = 0
	c.JitterMax = 0
	c.Timeout = 0
	c.MaxTasks = 0
	b, _ := json.Marshal(c)
	h := sha256.New()
	h.Write(b)
	if c.CVEMode != "" && c.CVEMode != "off" {
		cat, err := db.LoadCatalog(c.CVEDB)
		if err != nil {
			return "", err
		}
		data, _ := json.Marshal(cat)
		h.Write(data)
		h.Write([]byte("cve-pipeline-v2"))
	}
	for _, path := range []string{c.Scope, c.DirWords, c.FileWords, c.SubWords, c.FormValues, c.Templates, c.CVEDB, c.Components} {
		if path == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
