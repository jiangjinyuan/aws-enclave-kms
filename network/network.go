//go:build !linux
// +build !linux

package network

import "github.com/brodyxchen/aws-enclave-kms/log"

func AssignLoAddr() error {
	log.Info("AssignLoAddr() not in linux")
	return nil
}
