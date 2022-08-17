package nitro

import (
	"errors"
	"github.com/brodyxchen/aws-enclave-kms/log"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

// Attest takes as input a nonce, user-provided data and a public key, and then
// asks the Nitro hypervisor to return a signed attestation document that
// contains all three values.
func Attest(nonce, data, publicKey []byte) ([]byte, error) {
	s, err := nsm.OpenDefaultSession()
	if err != nil {
		log.Error("attest() nsm.OpenDefaultSession : ", err)
		return nil, err
	}
	defer func() {
		if err = s.Close(); err != nil {
			log.Errorf("Attestation: Failed to close default NSM session: %s", err)
		}
	}()

	res, err := s.Send(&request.Attestation{
		Nonce:     nonce,
		UserData:  data, //certFingerprint,
		PublicKey: publicKey,
	})
	if err != nil {
		log.Error("attest() nsm.Send : ", err)
		return nil, err
	}

	if res.Attestation == nil || res.Attestation.Document == nil {
		err = errors.New("NSM device did not return an attestation")
		return nil, err
	}

	return res.Attestation.Document, nil
}
