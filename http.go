package kms

import (
	"errors"
	"fmt"
	"github.com/brodyxchen/aws-enclave-kms/crypto"
	"github.com/brodyxchen/aws-enclave-kms/log"
	"github.com/brodyxchen/aws-enclave-kms/models"
	jsoniter "github.com/json-iterator/go"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var (
	ErrTokenExpired = errors.New("security token expired")
	json            = jsoniter.ConfigCompatibleWithStandardLibrary
)

// https://docs.aws.amazon.com/zh_cn/general/latest/gr/sigv4-create-canonical-request.html

func (cli *Client) callKms(target string, reqPtr interface{}, rspPtr interface{}) error {
	log.Info("kms.callKms target : ", target)
	// url := fmt.Sprintf("https://kms.%s.amazonaws.com/", cli.region)
	url := cli.endpoint

	reqData, err := json.Marshal(reqPtr)
	if err != nil {
		return err
	}

	headers := cli.withHeaders(target, reqData)

	// post
	rspData, err := cli.httpPost(url, reqData, headers)
	if err != nil {
		return err
	}

	err = json.Unmarshal(rspData, rspPtr)
	if err != nil {
		log.Error("json.Unmarshal rsp err : ", err)
		return err
	}

	log.Debugf("%v.rspBody : %+v\n", target, rspPtr)
	return nil
}

func (cli *Client) withHeaders(target string, reqData []byte) map[string]string {
	reqHash := crypto.HexEncodeToString(crypto.Sha256(reqData))

	awsService := "kms"
	host := fmt.Sprintf("kms.%s.amazonaws.com", cli.region)
	contentType := "application/x-amz-json-1.1"

	nowUtc := time.Now().UTC()
	amzDateTime := nowUtc.Format(amzDateTimeFormat)

	// 创建规范请求
	httpMethod := "POST"
	canonicalURI := "/"
	CanonicalQueryString := ""

	var sb strings.Builder
	sb.WriteString("content-type:" + contentType + "\n")
	sb.WriteString("host:" + host + "\n")
	sb.WriteString("x-amz-date:" + amzDateTime + "\n")
	sb.WriteString("x-amz-target:" + target + "\n")
	CanonicalHeaders := sb.String()

	signedHeaders := "content-type;host;x-amz-date;x-amz-target"

	// 规范的请求字符串
	var reqBuilder strings.Builder
	reqBuilder.WriteString(httpMethod + "\n")
	reqBuilder.WriteString(canonicalURI + "\n")
	reqBuilder.WriteString(CanonicalQueryString + "\n")
	reqBuilder.WriteString(CanonicalHeaders + "\n")
	reqBuilder.WriteString(signedHeaders + "\n")
	reqBuilder.WriteString(reqHash) // 最后没有\n

	CanonicalRequest := reqBuilder.String()
	dateStamp := nowUtc.Format(amzDateFormat)

	// 创建待签字符串
	algorithm := "AWS4-HMAC-SHA256"
	credentialScope := dateStamp + "/" + cli.region + "/" + awsService + "/" + "aws4_request"
	canonicalReqHash := crypto.HexEncodeToString(crypto.Sha256([]byte(CanonicalRequest)))

	var signBuilder strings.Builder
	signBuilder.WriteString(algorithm + "\n")
	signBuilder.WriteString(amzDateTime + "\n")
	signBuilder.WriteString(credentialScope + "\n")
	signBuilder.WriteString(canonicalReqHash)
	unsignedString := signBuilder.String()

	// 计算签名
	sign := cli.signatureKms(dateStamp, cli.region, awsService, unsignedString)

	// header-Authorization: algorithm Credential=access key ID/credential scope, SignedHeaders=SignedHeaders, Signature=signature
	var authBuilder strings.Builder
	authBuilder.WriteString(algorithm + " ")
	authBuilder.WriteString("Credential=" + cli.credential.AccessKeyID + "/" + credentialScope + ", ")
	authBuilder.WriteString("SignedHeaders=" + signedHeaders + ", ")
	authBuilder.WriteString("Signature=" + sign)
	authHeader := authBuilder.String()

	headers := make(map[string]string, 0)
	headers["Content-Type"] = contentType
	headers["X-Amz-Date"] = amzDateTime
	headers["X-Amz-Target"] = target
	headers["Authorization"] = authHeader
	if len(cli.credential.SessionToken) > 0 {
		headers["X-Amz-Security-Token"] = cli.credential.SessionToken
	}

	return headers
}

func (cli *Client) httpPost(url string, reqBody []byte, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(string(reqBody)))
	if err != nil {
		log.Error("NewRequest() err : ", err)
		return nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	rsp, err := cli.httpCli.Do(req)
	if err != nil {
		log.Error("httpCli.Do() err : ", err)
		return nil, err
	}
	defer rsp.Body.Close()

	log.Info("httpCli.Do StatusCode : ", rsp.StatusCode)

	if rsp.StatusCode != http.StatusOK {
		if rsp.Body == nil {
			err = errors.New(fmt.Sprintf("http(%v) fail without rsp body", rsp.StatusCode))
			return nil, err
		}
		body, err := ioutil.ReadAll(rsp.Body)
		if err != nil {
			log.Error("ioutil.ReadAll rsp.ErrBody err : ", err)
			return nil, err
		}
		var errRsp models.ErrorResponse
		err = json.Unmarshal(body, &errRsp)
		if err != nil {
			log.Error("json.Unmarshal errorRsp err : ", err)
			return nil, err
		}

		if errRsp.ErrType == "ExpiredTokenException" {
			return nil, ErrTokenExpired
		}

		log.Errorf("code: %v err_type: %v err_msg: %v", rsp.StatusCode, errRsp.ErrType, errRsp.ErrMessage)
		return nil, errors.New(fmt.Sprintf("code: %v err_type: %v err_msg: %v", rsp.StatusCode, errRsp.ErrType, errRsp.ErrMessage))
	}

	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		log.Error("ioutil.ReadAll rsp.Body : ", err)
		return nil, err
	}

	return body, nil
}

func (cli *Client) signatureKms(dateStamp, region, service string, unsignedString string) string {
	key := cli.credential.SecretAccessKey

	dateHash := crypto.HMacSha256([]byte("AWS4"+key), dateStamp)
	regionHash := crypto.HMacSha256(dateHash, region)
	serviceHash := crypto.HMacSha256(regionHash, service)
	signing := crypto.HMacSha256(serviceHash, "aws4_request")

	sign := crypto.HMacSha256(signing, unsignedString)
	return crypto.HexEncodeToString(sign)
}
