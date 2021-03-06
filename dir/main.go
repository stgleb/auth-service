package main

import (
	"crypto/rsa"

	"fmt"
	"io/ioutil"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
)

func ReadKeys(publicKeyFilePath, privateKeyFilePath string) {
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
}

func main() {
	ReadKeys("dir/public.pem", "dir/private.pem")

	userInfo := struct {
		UserName  string
		IssuedAt  int64
		ExpiresIn int64
	}{
		"Mike",
		time.Now().Unix(),
		time.Now().Add(time.Minute * 10).Unix(),
	}

	t := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"),
		jwt.MapClaims{
			"accesses":   []string{"edit", "view"},
			"issued_at":  time.Now().Unix(),
			"expires_at": time.Now().Add(time.Minute * 10).Unix(),
			"user_info":  userInfo,
		})

	tokenStr, err := t.SignedString(privateKey)

	if err != nil {
		panic(err)
	}

	fmt.Println(tokenStr)

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})

	switch err.(type) {
	case nil:
		if !token.Valid {
			panic("Token is not valid")
		}

		fmt.Println("Access has been granted")
	case *jwt.ValidationError:
		panic(err)
	default:
		panic(fmt.Sprintf("Unknown errir %s", err.Error()))
	}
}
