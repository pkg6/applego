package utility

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func EcdsaPrivateKey(key []byte) (*ecdsa.PrivateKey, error) {
	var err error
	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, fmt.Errorf("decode private key error")
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
		return nil, fmt.Errorf("private key must be ECP private key")
	}
	return pkey, nil
}
