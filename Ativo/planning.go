package ativo

import (
	"GoHunt/Diffing"
	"GoHunt/Escopo"
	"GoHunt/Estado"
	"GoHunt/Modelo"
	"GoHunt/Nucleo"
	"fmt"
	"sort"
)

func SchedulePages(e *nucleo.Engine, s *estado.Store, tasks []modelo.Task, records []modelo.Record) ([]modelo.Task, []modelo.Record) {
	// Prioritize input-bearing endpoints before generic pages within each discovery batch.
	tasks = append([]modelo.Task(nil), tasks...)
	sort.SliceStable(tasks, func(i, j int) bool {
		rank := func(t modelo.Task) int {
			if t.Kind != "page" {
				return 10
			}
			if t.Source == "scope" || t.Source == "form-get" {
				return 9
			}
			return diffing.EndpointRank(t.URL)
		}
		return rank(tasks[i]) > rank(tasks[j])
	})
	added := map[string]int{}
	variants := map[string]int{}
	seen := map[string]bool{}
	var planned []modelo.Task
	for _, t := range tasks {
		if t.Kind != "page" {
			planned = append(planned, t)
			continue
		}
		if s.Known[t.ID()] || seen[t.ID()] {
			continue
		}
		seen[t.ID()] = true
		// Historical variants already represented do not consume the budget again.
		if modelo.Historical(t) && s.HistoricalRoutes[escopo.RouteKey(t.URL)] {
			continue
		}
		route := escopo.RouteKey(t.URL)
		variantLimit := 2
		if e.Config.CrawlMode == "reduced" {
			variantLimit = 1
		} else if e.Config.CrawlMode == "deep" {
			variantLimit = 10
		}
		if t.Source != "scope" && t.Source != "form-get" && s.PageRoutes[route]+variants[route] >= variantLimit {
			records = append(records, modelo.UnmappedRecord(t, "amostragem de valores GET do perfil"))
			continue
		}
		host := escopo.RecordHost(t.URL)
		if s.PageHosts[host]+added[host] >= e.Config.PageBudget() {
			records = append(records, modelo.UnmappedRecord(t, fmt.Sprintf("limite de %d páginas por host", e.Config.PageBudget())))
			continue
		}
		if e.Config.CrawlMode == "reduced" && diffing.EndpointRank(t.URL) == 0 && t.Source != "scope" {
			records = append(records, modelo.UnmappedRecord(t, "asset estático no modo reduzido"))
			continue
		}
		added[host]++
		variants[route]++
		planned = append(planned, t)
	}
	return planned, records
}
