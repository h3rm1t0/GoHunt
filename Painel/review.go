package painel

import (
	"GoHunt/Estado"
	"GoHunt/Modelo"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var errReviewConflict = errors.New("revisão alterada em outra aba; atualize antes de salvar")

func mustReviewJSON(r modelo.ManualReview) []byte { b, _ := json.Marshal(r); return b }

func ReadReviews(path string) (map[string]modelo.ManualReview, error) {
	reviews := map[string]modelo.ManualReview{}
	f, err := os.Open(path + ".reviews.json")
	if os.IsNotExist(err) {
		return reviews, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	if err = dec.Decode(&reviews); err != nil {
		return nil, err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, errors.New("anotações corrompidas")
	}
	if reviews == nil {
		reviews = map[string]modelo.ManualReview{}
	}
	return reviews, nil
}

func reviewHandler(path, token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "método não permitido", 405)
			return
		}
		if r.Header.Get("X-GoHunt-Token") != token || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != "http://"+r.Host) || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "origem ou token inválido", 403)
			return
		}
		var input struct {
			ID          string `json:"id"`
			Disposition string `json:"disposition"`
			Verified    bool   `json:"verified"`
			Comment     string `json:"comment"`
			Revision    int    `json:"revision"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&input); err != nil {
			http.Error(w, "anotação inválida", 400)
			return
		}
		var extra any
		if dec.Decode(&extra) != io.EOF || len(input.Comment) > 8000 || len(input.ID) != 64 || input.Revision < 0 {
			http.Error(w, "comentário deve ter até 8000 bytes e revisão válida", 400)
			return
		}
		if input.Disposition != "" && input.Disposition != "pending" && input.Disposition != "confirmed" && input.Disposition != "discarded" {
			http.Error(w, "conclusão inválida", 400)
			return
		}
		if (input.Disposition == "confirmed" || input.Disposition == "discarded") && strings.TrimSpace(input.Comment) == "" {
			http.Error(w, "confirmação ou descarte exige comentário com evidência", 400)
			return
		}
		eligible := false
		cve := false
		if err := estado.WalkRecords(path, func(rec modelo.Record) {
			if modelo.RecordID(rec) == input.ID && reviewEligible(rec) {
				eligible = true
				cve = isCVE(rec)
			}
		}); err != nil {
			http.Error(w, "estado indisponível", 500)
			return
		}
		if !eligible {
			http.Error(w, "registro revisável não encontrado", 404)
			return
		}
		if input.Disposition != "" && !cve {
			http.Error(w, "conclusão CVE não se aplica a este registro", 400)
			return
		}
		if cve && input.Disposition != "" {
			input.Verified = input.Disposition == "confirmed"
		}
		result, err := SaveReview(path, input.ID, input.Revision, modelo.ManualReview{Verified: input.Verified, Comment: input.Comment, Disposition: input.Disposition})
		if errors.Is(err, errReviewConflict) {
			http.Error(w, err.Error(), 409)
			return
		}
		if err != nil {
			http.Error(w, "não foi possível persistir a revisão", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, string(mustReviewJSON(result)))
	}
}

func SaveReview(path, id string, expected int, review modelo.ManualReview) (modelo.ManualReview, error) {
	lock, err := os.OpenFile(path+".reviews.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return review, err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return review, err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	reviews, err := ReadReviews(path)
	if err != nil {
		return review, err
	}
	if reviews[id].Revision != expected {
		return review, errReviewConflict
	}
	review.Revision = expected + 1
	review.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	reviews[id] = review
	data, err := json.Marshal(reviews)
	if err != nil {
		return review, err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".gohunt-reviews-*")
	if err != nil {
		return review, err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	defer file.Close()
	if _, err = file.Write(data); err != nil {
		return review, err
	}
	if err = file.Sync(); err != nil {
		return review, err
	}
	if err = file.Close(); err != nil {
		return review, err
	}
	if err = os.Rename(tmp, path+".reviews.json"); err != nil {
		return review, err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return review, err
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return review, err
	}
	return review, nil
}
