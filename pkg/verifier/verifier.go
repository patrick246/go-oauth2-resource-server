package verifier

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/patrick246/go-oauth2-resource-server/pkg/discovery"
	"github.com/s12v/go-jwks"
	"time"
)

type Config struct {
	Issuer      string
	ExpectedAlg string
}

type Verifier struct {
	config     Config
	jwksClient jwks.JWKSClient
}

func New(c Config) (Verifier, error) {
	discoveryDoc, err := discovery.GetDiscoveryDocument(c.Issuer)
	if err != nil {
		return Verifier{}, err
	}

	jwksClient := jwks.NewDefaultClient(
		jwks.NewWebSource(discoveryDoc.JwksUri),
		time.Hour,
		24*time.Hour,
	)

	return Verifier{
		config:     c,
		jwksClient: jwksClient,
	}, nil
}

func (v *Verifier) VerifyAndParse(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if !v.checkSigningMethod(token) {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kidVal, ok := token.Header["kid"]
		if !ok {
			return nil, errors.New("no kid present in token")
		}
		kid, ok := kidVal.(string)
		if !ok {
			return nil, errors.New("expected kid header claim to be a string")
		}

		jwk, err := v.jwksClient.GetSignatureKey(kid)
		if err != nil {
			return nil, err
		}
		return jwk.Key, nil
	})
}

func (v *Verifier) checkSigningMethod(token *jwt.Token) bool {
	switch token.Method.(type) {
	case *jwt.SigningMethodECDSA:
		return v.config.ExpectedAlg == jwt.SigningMethodES256.Name ||
			v.config.ExpectedAlg == jwt.SigningMethodES384.Name ||
			v.config.ExpectedAlg == jwt.SigningMethodES512.Name
	case *jwt.SigningMethodHMAC:
		return v.config.ExpectedAlg == jwt.SigningMethodHS256.Name ||
			v.config.ExpectedAlg == jwt.SigningMethodHS384.Name ||
			v.config.ExpectedAlg == jwt.SigningMethodHS512.Name
	case *jwt.SigningMethodRSA:
		return v.config.ExpectedAlg == jwt.SigningMethodRS256.Name ||
			v.config.ExpectedAlg == jwt.SigningMethodRS384.Name ||
			v.config.ExpectedAlg == jwt.SigningMethodRS512.Name
	case *jwt.SigningMethodRSAPSS:
		return v.config.ExpectedAlg == jwt.SigningMethodPS256.Name ||
			v.config.ExpectedAlg == jwt.SigningMethodPS384.Name ||
			v.config.ExpectedAlg == jwt.SigningMethodPS512.Name
	default:
		return false
	}
}
