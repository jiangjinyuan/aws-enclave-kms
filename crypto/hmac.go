package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

func HMacSha256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}
