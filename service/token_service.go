package service

import (
	"time"

	"crypto/rsa"
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"
)

type TokenService interface {
	Issue() (string, error)
}

type TokenServiceImpl struct {
	tokenTTL int64

	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey

	tokens map[string]*jwt.Token
}

func NewTokenService(tokenTTL int64, privateKeyFilePath, publicKeyFilePath string) TokenService {
	var (
		publicKey  *rsa.PublicKey
		privateKey *rsa.PrivateKey
	)

	privateKeyData, err := ioutil.ReadFile(privateKeyFilePath)
	if err != nil {
		panic(err)
	}

	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
	if err != nil {
		panic(err)
	}

	publicKeyData, err := ioutil.ReadFile(publicKeyFilePath)

	if err != nil {
		panic(err)
	}

	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicKeyData)
	if err != nil {
		panic(err)
	}

	return TokenServiceImpl{
		tokenTTL:   tokenTTL,
		privateKey: privateKey,
		publicKey:  publicKey,
		tokens:     make(map[string]*jwt.Token),
	}
}

func (tokenService TokenServiceImpl) Issue() (string, error) {
	t := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"),
		jwt.MapClaims{
			"accesses":   []string{"edit", "view"},
			"issued_at":  time.Now().Unix(),
			"expires_at": time.Now().Unix() + tokenService.tokenTTL,
		})

	tokenStr, err := t.SignedString(tokenService.privateKey)

	if err != nil {
		panic(err)
	}

	// Save token
	tokenService.tokens[tokenStr] = t

	return tokenStr, nil
}

func (tokenService TokenServiceImpl) VerifyToken(tokenString string) (bool, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return tokenService.publicKey, nil
	})

	if err != nil {
		return false, err
	}

	if !token.Valid {
		return false, nil
	}

	return true, nil
}
