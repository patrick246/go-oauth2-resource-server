package middleware

import (
	"context"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/patrick246/go-oauth2-resource-server/pkg/verifier"
	"log"
	"net/http"
	"strings"
)

const TokenKey = "token"

type ErrorMessage struct {
	Message string `json:"message"`
}

func VerifyOpenIdConnectJwtToken(issuer, signingAlgorithm string, next http.Handler) http.Handler {
	verifierService, err := verifier.New(verifier.Config{
		Issuer:      issuer,
		ExpectedAlg: signingAlgorithm,
	})
	if err != nil {
		log.Fatalf("could not create openid connect token verifier: %v", err)
	}

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authHeader := request.Header.Get(http.CanonicalHeaderKey("Authorization"))
		if authHeader == "" {
			handleError(writer, 401, "invalid_request", "missing or empty Authorization header, expected Bearer token", issuer)
			return
		}

		tokenOnly := strings.TrimPrefix(authHeader, "Bearer ")
		if authHeader == tokenOnly {
			handleError(writer, 401, "invalid_request", "invalid auth header type, expected Bearer", issuer)
			return
		}

		token, err := verifierService.VerifyAndParse(tokenOnly)
		if err != nil {
			handleError(writer, 401, "invalid_token", err.Error(), issuer)
			return
		}

		ctx := context.WithValue(request.Context(), TokenKey, token)

		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func handleError(writer http.ResponseWriter, code int, errorType, description, issuer string) {
	writer.Header().Set("WWW-Authenticate", `Bearer realm="`+issuer+`", error="`+errorType+`", error_description="`+description+`"`)
	writer.WriteHeader(code)
	_ = json.NewEncoder(writer).Encode(ErrorMessage{description})
}

func GetToken(ctx context.Context) (*jwt.Token, bool) {
	token, ok := ctx.Value(TokenKey).(*jwt.Token)
	return token, ok
}
