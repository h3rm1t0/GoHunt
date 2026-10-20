package util

import (
	"crypto/rand"
	"encoding/hex"
)

func RandomID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
