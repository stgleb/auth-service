package main

import (
	"crypto/rsa"
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"
)

func ReadKeys(publicKeyFilePath, privateKeyFilePath string) (*rsa.PublicKey, *rsa.PrivateKey) {
	var (
		publicKey  *rsa.PublicKey
		privateKey *rsa.PrivateKey
	)

	publicKeyData, err := ioutil.ReadFile(publicKeyFilePath)

	if err != nil {
		panic(err)
	}

	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicKeyData)
	if err != nil {
		panic(err)
	}

	privateKeyData, err := ioutil.ReadFile(privateKeyFilePath)
	if err != nil {
		panic(err)
	}

	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
	if err != nil {
		panic(err)
	}

	return publicKey, privateKey
}
