package service

type AuthService struct {
	TokenService
	storage map[string]string
}

var (
	AuthenticationService AuthService
)

func InitAuthService(tokenTTL int64, privateKeyFilePath, publicKeyFilePath string) {
	AuthenticationService = AuthService{
		NewTokenService(tokenTTL, privateKeyFilePath, publicKeyFilePath),
		make(map[string]string),
	}
}

func (authService AuthService) Authenticate(login, password string) bool {
	return true
}
