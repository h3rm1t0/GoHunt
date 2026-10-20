package configuracao

func (c Config) LinkBudget() int {
	switch c.CrawlMode {
	case "reduced":
		return 32
	case "deep":
		return 512
	default:
		return 128
	}
}

func (c Config) PageBudget() int {
	if c.MaxPagesPerHost > 0 {
		return c.MaxPagesPerHost
	}
	switch c.CrawlMode {
	case "reduced":
		return 25
	case "deep":
		return 2000
	default:
		return 200
	}
}
