package endpoint

import (
	"auth-service/service"

	"auth-service/api"
	"context"

	"github.com/go-kit/kit/endpoint"
)

func MakeIssueTokenEndpoint(authService service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(data.IssueTokenRequest)
		result, err := authService.Authenticate(req.Login, req.Password)

		if err != nil {
			return data.IssueTokenResponse{err.Error()}, err
		}

		return data.IssueTokenResponse{data.TokenResponse{result, nil}}, nil
	}
}
