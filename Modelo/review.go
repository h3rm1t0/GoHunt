package modelo

type ManualReview struct {
	Disposition string `json:"disposition,omitempty"`
	Verified    bool   `json:"verified"`
	Comment     string `json:"comment"`
	Revision    int    `json:"revision"`
	UpdatedAt   string `json:"updated_at"`
}
