package utility

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func EcdsaPrivateKey(key []byte) (*ecdsa.PrivateKey, error) {
	var err error
	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New("decode private key error")
	}
	// Parse the key
	var parsedKey any
	if parsedKey, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}
	pkey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key must be ECP private key")
	}
	return pkey, nil
}

func VerifyCert(rootPEM, certByte, intermediaCertStr []byte) error {
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(rootPEM)
	if !ok {
		return errors.New("failed to parse root certificate")
	}
	interCert, err := x509.ParseCertificate(intermediaCertStr)
	if err != nil {
		return errors.New("failed to parse intermedia certificate")
	}
	intermedia := x509.NewCertPool()
	intermedia.AddCert(interCert)
	cert, err := x509.ParseCertificate(certByte)
	if err != nil {
		return err
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermedia,
	}
	_, err = cert.Verify(opts)
	return err
}
