package util

func AddUnique(list []string, value string) []string {
	if value == "" {
		return list
	}
	for _, v := range list {
		if v == value {
			return list
		}
	}
	return append(list, value)
}
