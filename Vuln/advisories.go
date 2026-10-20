package vuln

import (
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"encoding/json"
)

func ComponentTasks(e *nucleo.Engine, c modelo.Component) []modelo.Task {
	var tasks []modelo.Task
	if e.Config.CVEMode == "" || e.Config.CVEMode == "off" {
		return tasks
	}
	data, _ := json.Marshal(c)
	if e.Catalog != nil {
		for _, a := range e.Catalog.Candidates(c.Product, c.Version) {
			if a.Affects(c.Version) {
				tasks = append(tasks, modelo.Task{Kind: "cve", URL: c.URL, Source: a.ID, Path: string(data)})
			}
		}
	}
	if e.Config.OSV && c.Name != "" && c.Ecosystem != "" {
		tasks = append(tasks, modelo.Task{Kind: "osv", URL: c.URL, Path: string(data)})
	}
	return tasks
}
