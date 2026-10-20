// Package catalog holds the reviewed, versioned advisory catalog.
package catalog

import _ "embed"

//go:embed advisories.json
var Advisories []byte
