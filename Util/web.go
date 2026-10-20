package util

func DefaultValue(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
