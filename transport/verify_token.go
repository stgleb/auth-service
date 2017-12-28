package transports

import (
	. "auth-service/api"
	"context"
	"encoding/json"
	"net/http"
)

func DecodeVerifyTokenRequest(_ context.Context, r *http.Request) (interface{}, error) {
	var verifyTokenRequest VerifyTokenRequest

	if err := json.NewDecoder(r.Body).Decode(&verifyTokenRequest); err != nil {
		return nil, err
	}

	return verifyTokenRequest, nil
}

func EncodeVerifyTokenResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	verifyTokenResponse := response.(VerifyTokenResponse)

	if len(verifyTokenResponse.Error) > 0 {
		w.WriteHeader(http.StatusUnauthorized)
	}

	return json.NewEncoder(w).Encode(response)
}
