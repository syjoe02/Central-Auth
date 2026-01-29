package token

import (
	"crypto/sha256"
	"encoding/hex"
)

func Hash(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
