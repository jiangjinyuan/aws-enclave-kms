package types

type DataKeySpec string

type EncryptionAlgorithmSpec string

const (
	EncryptionAlgorithmSpecSymmetricDefault EncryptionAlgorithmSpec = "SYMMETRIC_DEFAULT"
	EncryptionAlgorithmSpecRsaesOaepSha1    EncryptionAlgorithmSpec = "RSAES_OAEP_SHA_1"
	EncryptionAlgorithmSpecRsaesOaepSha256  EncryptionAlgorithmSpec = "RSAES_OAEP_SHA_256"
)
