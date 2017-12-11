package auth_service

type Credentials struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}
