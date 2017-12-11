package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

type AuthServiceImpl struct {
	storage map[string]string
}

type Credentials struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type TokenService struct {
	tokens map[string]*jwt.Token
}

type Config struct {
	ListenStr string
	SecretKey string
	TokenTTL  int64
}

var (
	configFile   string
	config       *Config
	tokenService = TokenService{make(map[string]*jwt.Token)}
	authService  = AuthServiceImpl{make(map[string]string)}
)

func (tokenService TokenService) GenerateToken() (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"accesses":   []string{"edit", "view"},
		"issued_at":  time.Now().Unix(),
		"expires_at": time.Now().Unix() + config.TokenTTL,
	})

	tokenString, err := token.SignedString([]byte(config.SecretKey))

	if err != nil {
		return "", err
	}

	// Save token
	tokenService.tokens[tokenString] = token

	return tokenString, nil
}

func (authenticator AuthServiceImpl) Authenticate(login, password string) bool {
	//_, ok := authenticator.storage[login+password]
	return true
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	if data, err := ioutil.ReadAll(r.Body); err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
	} else {
		credentials := &Credentials{}

		if err := json.Unmarshal(data, credentials); err != nil {
			http.Error(w, "Error unmarshalling request body", http.StatusBadRequest)
		} else {
			log.Printf("Authenticate user with login %s", credentials.Login)
			if authService.Authenticate(credentials.Login, credentials.Password) {
				if token, err := tokenService.GenerateToken(); err == nil {
					log.Printf("Issue token for %s user %s", token, credentials.Login)
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

		return []byte(config.SecretKey), nil
	})

	log.Printf("Parsed token %v", token)

	if err != nil {
		http.Error(w, fmt.Sprintf("Error while parsing token %s", err.Error()), http.StatusBadRequest)
		return
	}

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

func ReadConfig() {
	flag.StringVar(&configFile, "config", "config.toml", "config file name")
	flag.Parse()

	config = &Config{}

	if _, err := toml.DecodeFile(configFile, config); err != nil {
		panic(err)
	}
}

func main() {
	ReadConfig()

	router := mux.NewRouter()

	router.HandleFunc("/login", AuthHandler).Methods(http.MethodPost)
	router.HandleFunc("/validate", Validate)

	log.Printf("Listen and serve on %s\n", config.ListenStr)

	if err := http.ListenAndServe(config.ListenStr, router); err != nil {
		log.Fatal(err)
	}
}
