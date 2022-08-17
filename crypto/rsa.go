package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"github.com/brodyxchen/aws-enclave-kms/env"
	"github.com/brodyxchen/aws-enclave-kms/log"
)

func GenerateRsaKey(bits int) (*rsa.PrivateKey, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Error("GenerateRsaKey() rsa.GenerateKey err : ", err)
		return nil, nil, err
	}

	if env.IsLocal() {
		x509PriKey := x509.MarshalPKCS1PrivateKey(privateKey)
		if err != nil {
			return nil, nil, err
		}
		x509PriKeyB64 := base64.StdEncoding.EncodeToString(x509PriKey)
		log.Info("x509PriKeyB64 : ", x509PriKeyB64)
	}

	x509PubKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Error("GenerateRsaKey() x509.MarshalPKIXPublicKey err : ", err)
		return nil, nil, err
	}

	return privateKey, x509PubKey, nil
}
