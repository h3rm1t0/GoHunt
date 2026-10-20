package painel

import (
	"GoHunt/Modelo"
)

// These are reviewable conclusions, never a numeric probability of exploitation.
func AssessmentState(r modelo.Record, review modelo.ManualReview) string {
	if review.Disposition == "confirmed" {
		return "manual-confirmed"
	}
	if review.Disposition == "discarded" {
		return "discarded"
	}
	switch r.Kind {
	case "technology", "component":
		return "observed"
	case "cve-verified":
		return "reproduced"
	case "cve-inconclusive":
		return "inconclusive"
	case "cve-correlation":
		if r.Evidence["assessment"] == "preconditions-met" {
			return "preconditions-met"
		}
		return "possible"
	}
	return ""
}

func isCVE(r modelo.Record) bool {
	return r.Kind == "cve-correlation" || r.Kind == "cve-inconclusive" || r.Kind == "cve-verified"
}

func reviewEligible(r modelo.Record) bool { return (r.Priority >= 1 && r.Priority <= 3) || isCVE(r) }
