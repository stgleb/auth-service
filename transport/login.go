package transports

import (
	. "auth-service/api"
	"context"
	"encoding/json"
	"net/http"
)

func DecodeLoginRequest(_ context.Context, r *http.Request) (interface{}, error) {
	var loginRequest LoginRequest

	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		return nil, err
	}

	return loginRequest, nil
}

func EncodeLogin(_ context.Context, w http.ResponseWriter, response interface{}) error {
	loginResp := response.(LoginResponse)

	if len(loginResp.Error) > 0 {
		w.WriteHeader(http.StatusUnauthorized)
	}

	return json.NewEncoder(w).Encode(response)
}
