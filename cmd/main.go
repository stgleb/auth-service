package main

import (
	. "auth-service"
	"flag"
	"github.com/BurntSushi/toml"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

type Config struct {
	ListenStr string
	SecretKey string
	TokenTTL  int64
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
	authService := NewAuthService(config.TokenTTL, []byte(config.SecretKey))

	router.HandleFunc("/login", authService.AuthHandler).Methods(http.MethodPost)
	router.HandleFunc("/validate", authService.Validate)

	log.Printf("Listen and serve on %s\n", config.ListenStr)

	if err := http.ListenAndServe(config.ListenStr, router); err != nil {
		log.Fatal(err)
	}
}
