package padroes

import (
	"regexp"
)

var RegexSegredos = map[string]*regexp.Regexp{
	"AWS Access Key":           regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"AWS Temporário (Session)": regexp.MustCompile(`ASIA[0-9A-Z]{16}`),
	"Google API Key":           regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	"GitHub PAT":               regexp.MustCompile(`(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}`),
	"JWT Token":                regexp.MustCompile(`eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`),
	"Chave Privada":            regexp.MustCompile(`(?s)-----BEGIN [ A-Z]+PRIVATE KEY-----.*?-----END [ A-Z]+PRIVATE KEY-----`),
	"Slack Token":              regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`),
	"Stripe API":               regexp.MustCompile(`(?i)sk_live_[0-9a-zA-Z]{24}`),

	"Potencial IDOR":             regexp.MustCompile(`(?i)(user_id|account_id|router_id|profile_id|order_id)\s*=\s*["']?[0-9a-zA-Z_-]+["']?`),
	"Esquema Custom (Deep Link)": regexp.MustCompile(`(?i)["']((?:[a-z0-9-]+\.)+[a-z0-9-]+:\/\/[^"']+)["']`),
	"jsonpRegex":                 regexp.MustCompile(`(?i)[?&](callback|cb|jsonp|jsonpcallback)=([a-zA-Z0-9_.-]+)`),
	"Pacote Android Interno":     regexp.MustCompile(`(?i)package_name["\s:]+["']?com\.[a-zA-Z0-9_\.]*\.(dev|stg|test|qa|sandbox|internal|beta)["']?`),
	"Credencial de Banco (URI)":  regexp.MustCompile(`(?i)(postgres|mysql|mongodb)://[a-zA-Z0-9_-]+:[^@]+@[a-zA-Z0-9_\.\-]+:[0-9]+`),
	"Android Intent":             regexp.MustCompile(`(?i)["'](intent:\/\/[^"']+)["']`),

	"Firebase Database":   regexp.MustCompile(`(?i)https?://[a-z0-9-]+\.firebaseio\.com`),
	"Bucket S3 Potencial": regexp.MustCompile(`(?i)[a-z0-9-\.]+\.s3\.amazonaws\.com`),

	"Credencial Twilio (SID+Token)": regexp.MustCompile(`(?i)(AC[a-zA-Z0-9]{32})["'\s:,]+([a-zA-Z0-9]{32})`),
	"Chave SendGrid (Email)":        regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`),
	"Chave Mailgun (Email)":         regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),

	"Endpoint GraphQL":       regexp.MustCompile(`(?i)(/graphql|/graphiql|/graphql/console)`),
	"Telegram Bot Token":     regexp.MustCompile(`[0-9]{9,10}:[a-zA-Z0-9_-]{35}`),
	"Discord Webhook":        regexp.MustCompile(`(?i)https:\/\/discord\.com\/api\/webhooks\/[0-9]{17,19}\/[a-zA-Z0-9_-]{68}`),
	"Mercado Pago Token":     regexp.MustCompile(`(?i)(?:TEST|APP_USR)-[0-9]{10,15}-[a-zA-Z0-9]+-[0-9a-zA-Z]{32}-[0-9]{10}`),
	"Braintree Access Token": regexp.MustCompile(`access_token\$production\$[0-9a-zA-Z]+\$[0-9a-zA-Z]{32}`),
}
