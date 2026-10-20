package escopo

import (
	"net/url"
	"strings"
)

// Parameter names and multiplicity matter; values do not define historical routes.
// Invalid queries remain distinct so malformed inputs are never silently merged.
func RouteKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return raw
	}
	for k, values := range q {
		for i := range values {
			values[i] = ""
		}
		q[k] = values
	}
	u.RawQuery = q.Encode()
	u.Fragment = ""
	u.Host = strings.ToLower(u.Host)
	return u.String()
}
