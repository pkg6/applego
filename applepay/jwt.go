package applepay

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	jwt2 "github.com/golang-jwt/jwt"
	"github.com/pkg6/applego/jwt"
	"github.com/pkg6/applego/utility"
	"reflect"
	"strings"
	"time"
)

//https://www.apple.com/certificateauthority/
//https://www.apple.com/certificateauthority/AppleRootCA-G3.cer
//openssl x509 -inform der -in AppleRootCA-G3.cer -out apple_root.pem
const rootPEM = `
-----BEGIN CERTIFICATE-----
MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwS
QXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9u
IEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcN
MTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBS
b290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9y
aXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49
AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtf
TjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517
IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySr
MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gA
MGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4
at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM
6BgD56KyKA==
-----END CERTIFICATE-----
`

// DefaultGenerateJWTToken 生成token
func DefaultGenerateJWTToken(privateKey *ecdsa.PrivateKey, iss, bid, keyID string) (string, error) {
	return jwt.Encode(privateKey, jwt2.SigningMethodES256, CustomClaims{
		Iss: iss,
		Iat: time.Now().Unix(),
		Exp: time.Now().Add(5 * time.Minute).Unix(),
		Aud: "appstoreconnect-v1",
		Bid: bid,
	}, map[string]any{
		"alg": "ES256",
		"kid": keyID,
		"typ": "JWT",
	})
}

// ExtractClaims 解析jws格式数据
// signedPayload：jws格式数据
// tran：指针类型的结构体，用于接收解析后的数据
func ExtractClaims(signedPayload string, tran jwt2.Claims) (err error) {
	valueOf := reflect.ValueOf(tran)
	if valueOf.Kind() != reflect.Ptr {
		return errors.New("tran must be ptr struct")
	}
	tokenStr := signedPayload
	rootCertStr, err := extractHeaderByIndex(tokenStr, 2)
	if err != nil {
		return err
	}
	intermediaCertStr, err := extractHeaderByIndex(tokenStr, 1)
	if err != nil {
		return err
	}
	if err = utility.VerifyCert([]byte(rootPEM), rootCertStr, intermediaCertStr); err != nil {
		return err
	}
	_, err = jwt2.ParseWithClaims(tokenStr, tran, func(token *jwt2.Token) (any, error) {
		return extractPublicKeyFromToken(tokenStr)
	})
	if err != nil {
		return err
	}
	return nil
}

// Per doc: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6
func extractPublicKeyFromToken(tokenStr string) (*ecdsa.PublicKey, error) {
	certStr, err := extractHeaderByIndex(tokenStr, 0)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certStr)
	if err != nil {
		return nil, err
	}
	switch pk := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return pk, nil
	default:
		return nil, errors.New("appstore public key must be of type ecdsa.PublicKey")
	}
}

func extractHeaderByIndex(tokenStr string, index int) ([]byte, error) {
	if index > 2 {
		return nil, errors.New("invalid index")
	}
	tokenArr := strings.Split(tokenStr, ".")
	headerByte, err := base64.RawStdEncoding.DecodeString(tokenArr[0])
	if err != nil {
		return nil, err
	}
	type Header struct {
		Alg string   `json:"alg"`
		X5c []string `json:"x5c"`
	}
	header := &Header{}
	err = json.Unmarshal(headerByte, header)
	if err != nil {
		return nil, err
	}
	if len(header.X5c) < index {
		return nil, fmt.Errorf("index[%d] > header.x5c slice len(%d)", index, len(header.X5c))
	}
	certByte, err := base64.StdEncoding.DecodeString(header.X5c[index])
	if err != nil {
		return nil, err
	}
	return certByte, nil
}
