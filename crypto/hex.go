package crypto

import (
	"encoding/hex"
)

func HexEncodeToString(data []byte) string {
	return hex.EncodeToString(data) // 全小写
}
