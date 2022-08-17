package crypto

import (
	"crypto"
	"encoding/base64"
	"github.com/brodyxchen/aws-enclave-kms/log"
	"github.com/brodyxchen/aws-enclave-kms/pkcs7"
)

func DecryptEnvelopedRecipient(priKey crypto.PrivateKey, data string) ([]byte, error) {
	//log.Debug("EnvelopedRecipient.data : ", data)

	recipient, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	pkcs, err := pkcs7.Parse(recipient)
	if err != nil {
		log.Error("DecryptEnvelopedRecipient() pkcs7.Parse err : ", err)
		return nil, err
	}

	outBytes, err := pkcs.DecryptWithNoCert(priKey) // plain  not b64
	if err != nil {
		log.Error("DecryptEnvelopedRecipient() pkcs.DecryptWithNoCert err : ", err)
		return nil, err
	}
	return outBytes, nil
}
