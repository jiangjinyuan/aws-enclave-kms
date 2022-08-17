//go:build !linux
// +build !linux

package randseed

import (
	"github.com/brodyxchen/aws-enclave-kms/log"
)

func init() {
	log.Info("randseed() init() not in linux")
}
