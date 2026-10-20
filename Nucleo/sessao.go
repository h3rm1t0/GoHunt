package nucleo

import (
	"GoHunt/Configuracao"
	"GoHunt/DNS"
	"GoHunt/Db"
	"GoHunt/Escopo"
	"GoHunt/Modelo"
	"GoHunt/Monitoramento"
	origvuln "GoHunt/Vuln/Templates"
	"context"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"net/http"
)

type Engine struct {
	Catalog      *db.Catalog
	Components   []modelo.Component
	OSVCache     modelo.OsvCache
	DeniedBodies map[string]string
	Resolver     hostResolver
	CNAME        dns.CnameInspector
	Log          *monitoramento.Console
	Config       configuracao.Config
	Scope        *escopo.Scope
	Client       *http.Client
	Forms        map[string]string
	Templates    []origvuln.Arsenal_vulns
	Wapp         *wappalyzer.Wappalyze
}

type hostResolver interface {
	LookupHost(context.Context, string) ([]string, error)
}
