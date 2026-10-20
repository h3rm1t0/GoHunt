package escopo

import (
	"net/url"
)

func Origin(raw string) string { u, _ := url.Parse(raw); return u.Scheme + "://" + u.Host + "/" }
