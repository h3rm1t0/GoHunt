package painel

import (
	"GoHunt/Escopo"
	"GoHunt/Estado"
	"GoHunt/Modelo"
	"GoHunt/Util"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func groupHandler(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		id := q.Get("id")
		offset, err := strconv.Atoi(util.DefaultValue(q.Get("offset"), "0"))
		if err != nil || offset < 0 || offset > 10000000 || len(id) != 64 {
			http.Error(w, "grupo ou página inválida", 400)
			return
		}
		reviews, err := ReadReviews(path)
		if err != nil {
			http.Error(w, "revisões indisponíveis", 500)
			return
		}
		result := PageResult{Offset: offset, Limit: 25, Items: []modelo.Record{}}
		err = estado.WalkRecords(path, func(rec modelo.Record) {
			if !modelo.IsEntry(rec) || modelo.DisplayID(rec) != id || !matchesResult(rec, q, reviews) {
				return
			}
			position := result.Total
			result.Total++
			if position < offset || len(result.Items) >= 25 {
				return
			}
			rec.ID = modelo.RecordID(rec)
			if review, ok := reviews[rec.ID]; ok {
				rec.Review = &review
			}
			result.Items = append(result.Items, rec)
		})
		if err != nil {
			http.Error(w, "estado indisponível", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func matchesResult(record modelo.Record, q url.Values, reviews map[string]modelo.ManualReview) bool {
	kind := q.Get("kind")
	source := q.Get("source")
	search := strings.ToLower(q.Get("q"))
	priority, _ := strconv.Atoi(q.Get("priority"))
	review := reviews[modelo.RecordID(record)]
	if state := q.Get("assessment"); state != "" && AssessmentState(record, review) != state {
		return false
	}
	if q.Get("review") == "discarded" && review.Disposition != "discarded" {
		return false
	}
	verified := review.Verified
	if q.Get("review") == "verified" && !verified {
		return false
	}
	if q.Get("review") == "pending" && (verified || review.Disposition == "discarded") {
		return false
	}
	if host := q.Get("host"); host != "" && escopo.RecordHost(record.URL) != strings.ToLower(host) {
		return false
	}
	if record.Priority < 1 || record.Priority > 5 || (priority != 0 && record.Priority != priority) || (kind != "" && kind != record.Kind) || (source != "" && source != record.Source) {
		return false
	}
	if search == "" {
		return true
	}
	haystack := record.URL + " " + record.Summary + " " + record.Source
	for _, key := range []string{"provider", "dns_destination", "cname_chain", "http_marker", "technologies", "technology", "parameter_names", "route_signature", "product", "version", "package", "cve", "advisory"} {
		haystack += " " + record.Evidence[key]
	}
	for _, field := range record.Fields {
		haystack += " " + field.Name
	}
	return strings.Contains(strings.ToLower(haystack), search)
}
