package models

import (
	"github.com/brodyxchen/aws-enclave-kms/types"
)

type ErrorResponse struct {
	ErrType    string `json:"__type"`
	ErrMessage string `json:"message"`
}

// RecipientInfo https://docs.aws.amazon.com/zh_cn/kms/latest/developerguide/services-nitro-enclaves.html
type RecipientInfo struct {
	AttestationDocument    string `json:"AttestationDocument"`
	KeyEncryptionAlgorithm string `json:"KeyEncryptionAlgorithm"` // 固定值 RSAES_OAEP_SHA_256
}

// 使用 AWS Nitro Enclaves 支持 AWS KMS Decrypt、GenerateDataKey 和 GenerateRandom 操作
// https://docs.aws.amazon.com/zh_cn/kms/latest/developerguide/services-nitro-enclaves.html

type GenerateRandomRequest struct {
	NumberOfBytes int `json:"NumberOfBytes"`

	Recipient *RecipientInfo `json:"Recipient,omitempty"`
}

type GenerateRandomResponse struct {
	Plaintext              string
	CiphertextForRecipient string
}

type GenerateDataKeyRequest struct {
	KeyId         string
	GrantTokens   []string
	NumberOfBytes int `json:"NumberOfBytes"`
	KeySpec       types.DataKeySpec
	Recipient     *RecipientInfo `json:"Recipient,omitempty"`
}
type GenerateDataKeyResponse struct {
	CiphertextBlob string
	KeyId          string

	Plaintext              string
	CiphertextForRecipient string
}

type DecryptRequest struct {
	CiphertextBlob      []byte
	EncryptionAlgorithm types.EncryptionAlgorithmSpec
	GrantTokens         []string
	KeyId               string
	Recipient           *RecipientInfo `json:"Recipient,omitempty"`
}
type DecryptResponse struct {
	EncryptionAlgorithm types.EncryptionAlgorithmSpec
	KeyId               string

	Plaintext              string
	CiphertextForRecipient string
}
