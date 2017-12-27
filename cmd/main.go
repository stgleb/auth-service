package main

import (
	. "auth-service"
	"auth-service/service"
	"flag"
	"log"
	"net/http"

	"github.com/BurntSushi/toml"
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
	service.InitAuthService(config.TokenTTL, config.PrivateKeyFilePath, config.PublicKeyFilePath)

	log.Printf("Listen and serve on %s\n", config.ListenStr)

	if err := http.ListenAndServe(config.ListenStr, router); err != nil {
		log.Fatal(err)
	}
}
