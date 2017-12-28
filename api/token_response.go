package data

type TokenResponse struct {
	Token string `json:"token,omitempty"`
	Error string `json:"error,omitempty"`
}

type LoginResponse struct {
	TokenResponse
}

type VerifyTokenResponse struct {
	TokenResponse
}

type RevokeTokenResponse struct {
	TokenResponse
}
