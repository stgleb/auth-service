package service

import (
	"time"

	"crypto/rsa"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

type TokenService interface {
	Issue() (string, error)
	Authenticate(string, string) (bool, error)
	Login(string, string) (string, error)
	VerifyToken(string) error
}

type TokenServiceImpl struct {
	tokenTTL int64

	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey

	tokens map[string]*jwt.Token
}

func NewTokenService(tokenTTL int64, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) TokenService {
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

func (tokenService TokenServiceImpl) VerifyToken(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return tokenService.publicKey, nil
	})

	if err != nil {
		return err
	}

	if !token.Valid {
		return errors.New("Token is not valid")
	}

	return nil
}

func (tokenService TokenServiceImpl) Authenticate(login, password string) (bool, error) {
	return true, nil
}

func (tokenService TokenServiceImpl) Login(login, password string) (string, error) {
	if isAuthenticated, err := tokenService.Authenticate(login, password); err != nil || isAuthenticated {
		return "", err
	}

	token, err := tokenService.Issue()

	if err != nil {
		return "", err
	}

	return token, nil
}
