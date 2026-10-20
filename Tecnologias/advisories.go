package tecnologias

import (
	"GoHunt/Diffing"
	"GoHunt/Escopo"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"GoHunt/Vuln"
	"net/url"
	"regexp"
	"strings"
)

var generatorVersion = regexp.MustCompile(`(?i)^(Joomla!?|WordPress)[ /]+([0-9]+\.[0-9]+\.[0-9]+)$`)

func ObservedComponents(e *nucleo.Engine, t modelo.Task, r modelo.Response) ([]modelo.Task, []modelo.Record) {
	if e.Config.CVEMode == "" || e.Config.CVEMode == "off" || r.Status < 200 || r.Status >= 300 || diffing.BlockPage(r) {
		return nil, nil
	}
	var components []modelo.Component
	for _, h := range []string{"Server", "X-Powered-By"} {
		m := serverVersion.FindStringSubmatch(r.Header.Get(h))
		if m == nil {
			continue
		}
		product := map[string]string{"apache": "apache-httpd", "nginx": "nginx", "php": "php", "node.js": "nodejs", "nodejs": "nodejs", "next.js": "nextjs"}[strings.ToLower(m[1])]
		components = append(components, modelo.Component{URL: escopo.Origin(t.URL), Product: product, Version: m[2], SourceType: "http-header", Evidence: h + ": " + r.Header.Get(h)})
	}
	// Only generator metadata is a version signal; arbitrary page text is not.
	for _, g := range generators(r) {
		m := generatorVersion.FindStringSubmatch(g)
		if m != nil {
			u, _ := url.Parse(t.URL)
			u.RawQuery = ""
			u.Path = u.Path[:strings.LastIndex(u.Path, "/")+1]
			components = append(components, modelo.Component{URL: u.String(), Product: strings.TrimSuffix(strings.ToLower(m[1]), "!"), Version: m[2], SourceType: "html-generator", Evidence: "meta generator: " + g})
		}
	}
	var tasks []modelo.Task
	var records []modelo.Record
	for _, c := range components {
		tasks = append(tasks, vuln.ComponentTasks(e, c)...)
		records = append(records, modelo.ComponentRecord(c))
	}
	return tasks, records
}

var serverVersion = regexp.MustCompile(`(?i)^(Apache|nginx|PHP|Node\.js|NodeJS|Next\.js)/([0-9]+\.[0-9]+\.[0-9]+)(?:$|[ ;(])`)
