package auth_service

type AuthService struct {
	TokenService
	SecretKey []byte
	storage   map[string]string
}

var (
	AuthenticationService AuthService
)

func InitAuthService(tokenTTL int64, secretKey []byte) {
	AuthenticationService = AuthService{
		NewTokenService(tokenTTL, secretKey),
		secretKey,
		make(map[string]string),
	}
}

func (authService AuthService) Authenticate(login, password string) bool {
	return true
}
