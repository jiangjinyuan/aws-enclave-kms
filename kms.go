package kms

import (
	crypto2 "crypto"
	"encoding/base64"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/brodyxchen/aws-enclave-kms/crypto"
	"github.com/brodyxchen/aws-enclave-kms/env"
	"github.com/brodyxchen/aws-enclave-kms/log"
	"github.com/brodyxchen/aws-enclave-kms/models"
	"github.com/brodyxchen/aws-enclave-kms/network"
	"github.com/brodyxchen/aws-enclave-kms/nitro"
	_ "github.com/brodyxchen/aws-enclave-kms/randseed"
	"github.com/brodyxchen/aws-enclave-kms/types"
	"github.com/brodyxchen/aws-enclave-kms/viproxy"
	"github.com/mdlayher/vsock"
	"net"
	"net/http"
	"strconv"
	"time"
)

const (
	// parentCID determines the CID (analogous to an IP address) of the parent
	// EC2 instance.  According to the AWS docs, it is always 3:
	// https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html
	parentCID = 3

	httpTimeout       = 180 * time.Second
	amzDateTimeFormat = "20060102T150405Z"
	amzDateFormat     = "20060102"

	DataKeySpecAes256 types.DataKeySpec = "AES_256"
	DataKeySpecAes128 types.DataKeySpec = "AES_128"

	LocalEnv   = env.LocalEnv
	ReleaseEnv = env.ReleaseEnv
)

func NewClient(inEnv env.Env, inPort, outPort int) (*Client, error) {
	env.Set(inEnv)

	cli := &Client{
		inTcpPort: inPort,
		outVPort:  outPort,
	}

	err := cli.init()
	if err != nil {
		return nil, err
	}

	log.Info("NewClient() init() success")
	return cli, nil
}

type Client struct {
	region string

	credential *aws.Credentials

	//accessKeyId     string
	//accessSecretKey string
	//sessionToken    string

	rsaKey    crypto2.PrivateKey
	rsaPubKey []byte // PKIXPublicKey

	httpCli *http.Client

	inTcpPort int // "443"
	outVPort  int // "1443"
}

func (cli *Client) withHttpProxy() (*http.Client, error) {
	return &http.Client{
		Timeout: httpTimeout,
	}, nil
}

func (cli *Client) init() error {
	httpCli, _ := cli.withHttpProxy()
	cli.httpCli = httpCli

	if err := cli.initLoopback(); err != nil {
		return err
	}

	if err := cli.initProxy(); err != nil {
		return err
	}

	priKey, pubKey, err := crypto.GenerateRsaKey(2048)
	if err != nil {
		return err
	}

	cli.rsaKey = priKey
	cli.rsaPubKey = pubKey
	return nil
}

func (cli *Client) initLoopback() error {
	return network.AssignLoAddr()
}

func (cli *Client) initProxy() error {
	if env.IsLocal() {
		return nil
	}

	inAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:"+strconv.Itoa(cli.inTcpPort)) // tcp://127.0.0.1:443
	if err != nil {
		return errors.New("failed to resolve proxy from config: " + err.Error())
	}

	tuple := &viproxy.Tuple{
		InAddr:  inAddr,                                                                // tcp://127.0.0.1:443
		OutAddr: &vsock.Addr{ContextID: uint32(parentCID), Port: uint32(cli.outVPort)}, // vsock://3:1443
	}
	log.Infof("proxy service: inAddr := %+v, outAddr := %+v", tuple.InAddr, tuple.OutAddr)
	proxyCli := viproxy.NewVIProxy([]*viproxy.Tuple{tuple})
	if err := proxyCli.Start(); err != nil { // 监听tcp://127.0.0.1:443,  转发到  vsock://3:1443
		return errors.New("failed to start VIProxy: " + err.Error())
	}
	return nil
}

func (cli *Client) SetRegion(region string) {
	cli.region = region
}
func (cli *Client) SetCredential(credential *aws.Credentials) {
	cli.credential = credential
}

func (cli *Client) GenerateRandom(byteCount int) ([]byte, error) {
	if byteCount < 1 || byteCount > 1024 {
		return nil, errors.New("invalid random byte count " + strconv.FormatInt(int64(byteCount), 10))
	}

	awsTarget := "TrentService.GenerateRandom"

	recipient, err := cli.withRecipientInfo()
	if err != nil {
		return nil, err
	}
	req := &models.GenerateRandomRequest{
		NumberOfBytes: byteCount,
		Recipient:     recipient,
	}

	var rsp models.GenerateRandomResponse
	err = cli.callKms(awsTarget, req, &rsp)
	if err != nil {
		return nil, err
	}

	if env.IsLocal() {
		log.Info("GenerateRandom.rsp : ", rsp)
		plainBytes, err := base64.StdEncoding.DecodeString(rsp.Plaintext)
		if err != nil {
			return nil, err
		}
		return plainBytes, nil
	}

	// enveloped_data  by pkcs asn.1
	plainBytes, err := crypto.DecryptEnvelopedRecipient(cli.rsaKey, rsp.CiphertextForRecipient)
	if err != nil {
		return nil, err
	}

	return plainBytes, nil
}

func (cli *Client) GenerateDataKey(keySpec types.DataKeySpec, kmsKeyId string) ([]byte, []byte, error) {
	awsTarget := "TrentService.GenerateDataKey"

	recipient, err := cli.withRecipientInfo()
	if err != nil {
		return nil, nil, err
	}
	req := &models.GenerateDataKeyRequest{
		KeyId: kmsKeyId,
		//GrantTokens: []string{cli.sessionToken},
		KeySpec:   keySpec,
		Recipient: recipient,
	}
	if len(cli.credential.SessionToken) > 0 {
		req.GrantTokens = []string{cli.credential.SessionToken}
	}

	var rsp models.GenerateDataKeyResponse
	err = cli.callKms(awsTarget, req, &rsp)
	if err != nil {
		return nil, nil, err
	}

	cipherBytes, err := base64.StdEncoding.DecodeString(rsp.CiphertextBlob)
	if err != nil {
		return nil, nil, err
	}

	if env.IsLocal() {
		log.Info("GenerateDataKey.rsp : ", rsp)
		plainBytes, err := base64.StdEncoding.DecodeString(rsp.Plaintext)
		if err != nil {
			return nil, nil, err
		}

		return plainBytes, cipherBytes, nil
	}

	// enveloped_data  by pkcs asn.1
	plainBytes, err := crypto.DecryptEnvelopedRecipient(cli.rsaKey, rsp.CiphertextForRecipient)
	if err != nil {
		return nil, nil, err
	}

	return plainBytes, cipherBytes, nil
}

func (cli *Client) Decrypt(ciphertextBlob []byte, kmsKeyId string) ([]byte, error) {
	awsTarget := "TrentService.Decrypt"

	recipient, err := cli.withRecipientInfo()
	if err != nil {
		return nil, err
	}
	req := &models.DecryptRequest{
		CiphertextBlob:      ciphertextBlob,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		//GrantTokens:         []string{cli.sessionToken},
		KeyId:     kmsKeyId,
		Recipient: recipient,
	}
	if len(cli.credential.SessionToken) > 0 {
		req.GrantTokens = []string{cli.credential.SessionToken}
	}

	var rsp models.DecryptResponse
	err = cli.callKms(awsTarget, req, &rsp)
	if err != nil {
		return nil, err
	}

	if env.IsLocal() {
		log.Info("Decrypt.rsp : ", rsp)
		plainBytes, err := base64.StdEncoding.DecodeString(rsp.Plaintext)
		if err != nil {
			return nil, err
		}
		return plainBytes, nil
	}

	// enveloped_data  by pkcs asn.1
	plainBytes, err := crypto.DecryptEnvelopedRecipient(cli.rsaKey, rsp.CiphertextForRecipient)
	if err != nil {
		return nil, err
	}

	return plainBytes, nil
}

func (cli *Client) withRecipientInfo() (*models.RecipientInfo, error) {
	if env.IsLocal() {
		return nil, nil
	}

	nonceStr := strconv.Itoa(int(time.Now().UnixNano() / 1e6))
	attest, err := nitro.Attest([]byte(nonceStr), []byte("key-creator"), cli.rsaPubKey)
	if err != nil {
		return nil, err
	}

	attestB64 := base64.StdEncoding.EncodeToString(attest)
	return &models.RecipientInfo{
		KeyEncryptionAlgorithm: "RSAES_OAEP_SHA_1",
		AttestationDocument:    attestB64,
	}, nil
}
