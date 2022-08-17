package crypto

import "crypto/sha256"

func Sha256(data []byte) []byte {
	sign := sha256.Sum256(data)
	return sign[:]
}
