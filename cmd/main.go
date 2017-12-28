package main

import (
	. "auth-service/endpoint"
	. "auth-service/service"
	. "auth-service/transport"
	"flag"
	"log"
	"net/http"

	"github.com/BurntSushi/toml"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
)

type Config struct {
	ListenStr          string
	PublicKeyFilePath  string
	PrivateKeyFilePath string
	TokenTTL           int64
}

var (
	configFile string
	config     *Config
)

func ReadConfig() {
	flag.StringVar(&configFile, "config", "cmd/config.toml", "config file name")
	flag.Parse()

	config = &Config{}

	if _, err := toml.DecodeFile(configFile, config); err != nil {
		panic(err)
	}
}

func main() {
	ReadConfig()

	router := mux.NewRouter()
	// TODO(stgleb): Get keys from vault
	publicKey, privateKey := ReadKeys(config.PrivateKeyFilePath, config.PublicKeyFilePath)

	service := NewTokenService(config.TokenTTL, publicKey, privateKey)

	loginHandler := httptransport.NewServer(
		MakeLoginEndpoint(service),
		DecodeLoginRequest,
		EncodeLogin,
	)

	verifyTokenHandler := httptransport.NewServer(
		MakeVerifyTokenEndpoint(service),
		DecodeVerifyTokenRequest,
		EncodeVerifyTokenResponse,
	)

	router.Handle("/login", loginHandler)
	router.Handle("/verify", verifyTokenHandler)

	log.Printf("Listen and serve on %s\n", config.ListenStr)

	if err := http.ListenAndServe(config.ListenStr, router); err != nil {
		log.Fatal(err)
	}
}
