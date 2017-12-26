package auth_service

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	if data, err := ioutil.ReadAll(r.Body); err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
	} else {
		credentials := &Credentials{}

		if err := json.Unmarshal(data, credentials); err != nil {
			http.Error(w, "Error unmarshalling request body", http.StatusBadRequest)
		} else {
			log.Printf("Authenticate user with login %s", credentials.Login)
			if AuthenticationService.Authenticate(credentials.Login, credentials.Password) {
				if token, err := AuthenticationService.Issue(); err == nil {
					log.Printf("Issue token for %s user %s", token[len(token)-8:], credentials.Login)
					w.Header().Add("Authorization", fmt.Sprintf("Bearer %s", token))
					return
				} else {
					log.Printf("Error while issuing token to user %s", credentials.Login)
					http.Error(w, fmt.Sprintf("Error while generating token %s", err.Error()), http.StatusInternalServerError)
					return
				}
			}
		}
	}
}

func Validate(w http.ResponseWriter, r *http.Request) {
	tokenString := strings.Split(r.Header.Get("Authorization"), " ")[1]
	log.Printf("Token value is %s\n", tokenString)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return AuthenticationService.SecretKey, nil
	})

	if err != nil {
		http.Error(w, fmt.Sprintf("Error while parsing token %s", err.Error()), http.StatusBadRequest)
		return
	}

	log.Printf("Parsed token with method %v claims %v", token.Method.Alg(), token.Claims)

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		e, ok := claims["expires_at"].(float64)
		expiresAt := int64(e)

		if !ok {
			http.Error(w, "Wrong token content %s", http.StatusBadRequest)
		}

		if int64(expiresAt) < time.Now().Unix() {
			http.Error(w, "Token has been expired", http.StatusForbidden)
			return
		}

		w.Write([]byte("Token is valid"))
	} else {
		http.Error(w, "Error while converting to jwt claims map", http.StatusBadRequest)
		return
	}
}
