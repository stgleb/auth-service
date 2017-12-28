package endpoint

import (
	"auth-service/service"
	"context"

	"auth-service/api"

	"github.com/go-kit/kit/endpoint"
)

func MakeVerifyTokenEndpoint(tokenService service.TokenService) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		verifyRequest := req.(data.VerifyTokenRequest)
		err := tokenService.VerifyToken(verifyRequest.Token)

		if err != nil {
			return data.VerifyTokenResponse{data.TokenResponse{Error: err.Error()}}, err
		}

		return data.VerifyTokenResponse{}, nil
	}
}
