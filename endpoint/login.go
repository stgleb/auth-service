package endpoint

import (
	"auth-service/service"

	"auth-service/api"
	"context"

	"github.com/go-kit/kit/endpoint"
)

func MakeLoginEndpoint(tokenService service.TokenService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(data.LoginRequest)
		result, err := tokenService.Login(req.Login, req.Password)

		if err != nil {
			return data.LoginResponse{data.TokenResponse{Error: err.Error()}}, err
		}

		return data.LoginResponse{data.TokenResponse{result, ""}}, nil
	}
}
