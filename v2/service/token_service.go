package service

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

type TokenService interface {
	Issue() (string, error)
}

type TokenServiceImpl struct {
	tokenTTL  int64
	secretKey []byte

	tokens map[string]*jwt.Token
}

func NewTokenService(tokenTTL int64, secretKey []byte) TokenService {
	return TokenServiceImpl{
		tokenTTL:  tokenTTL,
		secretKey: secretKey,
		tokens:    make(map[string]*jwt.Token),
	}
}

func (tokenService TokenServiceImpl) Issue() (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"accesses":   []string{"edit", "view"},
		"issued_at":  time.Now().Unix(),
		"expires_at": time.Now().Unix() + tokenService.tokenTTL,
	})

	tokenString, err := token.SignedString([]byte(tokenService.secretKey))

	if err != nil {
		return "", err
	}

	// Save token
	tokenService.tokens[tokenString] = token

	return tokenString, nil
}
