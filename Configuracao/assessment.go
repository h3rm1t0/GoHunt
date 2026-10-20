package configuracao

import (
	"GoHunt/Util"
	"fmt"
)

func SelectedVerifier(c Config, id string) bool {
	for _, v := range util.SplitSources(c.CVEVerifiers) {
		if id == v {
			return true
		}
	}
	return false
}

func ValidateVerifiers(c Config) error {
	ids := util.SplitSources(c.CVEVerifiers)
	if c.CVEMode == "verify" && len(ids) == 0 {
		return fmt.Errorf("--cve-mode verify exige --cve-verifiers joomla-public-users-v1")
	}
	if c.CVEMode != "verify" && len(ids) > 0 {
		return fmt.Errorf("--cve-verifiers exige --cve-mode verify")
	}
	for _, id := range ids {
		if id != "joomla-public-users-v1" {
			return fmt.Errorf("verificador não reconhecido: %s", id)
		}
	}
	return nil
}
