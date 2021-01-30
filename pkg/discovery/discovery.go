package discovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

type OpenIdDiscoveryDocument struct {
	Issuer                                    string   `json:"issuer"`
	AuthorizationEndpoint                     string   `json:"authorization_endpoint"`
	TokenEndpoint                             string   `json:"token_endpoint,omitempty"`
	UserinfoEndpoint                          string   `json:"userinfo_endpoint,omitempty"`
	JwksUri                                   string   `json:"jwks_uri"`
	RegistrationEndpoint                      string   `json:"registration_endpoint"`
	ScopesSupported                           []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                    []string `json:"response_types_supported,omitempty"`
	ResponseModesSupported                    []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                       []string `json:"grant_types_supported,omitempty"`
	AcrValuesSupported                        []string `json:"acr_values_supported"`
	SubjectTypesSupported                     []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported          []string `json:"id_token_signing_alg_values_supported"`
	IdTokenEncryptionAlgValuesSupported       []string `json:"id_token_encryption_alg_values_supported"`
	IdTokenEncryptionEncValuesSupported       []string `json:"id_token_encryption_enc_values_supported"`
	UserinfoSigningAlgValuesSupported         []string `json:"userinfo_signing_alg_values_supported"`
	UserinfoEncryptionAlgValuesSupported      []string `json:"userinfo_encryption_alg_values_supported"`
	UserinfoEncryptionEncValuesSupported      []string `json:"userinfo_encryption_enc_values_supported"`
	RequestObjectSigningAlgValuesSupported    []string `json:"request_object_signing_alg_values_supported"`
	RequestObjectEncryptionAlgValuesSupported []string `json:"request_object_encryption_alg_values_supported"`
	RequestObjectEncryptionEncValuesSupported []string `json:"request_object_encryption_enc_values_supported"`
	TokenEndpointAuthMethodsSupported         []string `json:"token_endpoint_auth_methods_supported"`
	DisplayValuesSupported                    []string `json:"display_values_supported"`
	ClaimsSupported                           []string `json:"claims_supported"`
	ServiceDocumentation                      string   `json:"service_documentation"`
	ClaimLocalesSupported                     []string `json:"claim_locales_supported"`
	UiLocalesSupported                        []string `json:"ui_locales_supported"`
	ClaimsParameterSupported                  bool     `json:"claims_parameter_supported"`
	RequestParameterSupported                 bool     `json:"request_parameter_supported"`
	RequestUriParameterSupported              bool     `json:"request_uri_parameter_supported"`
	RequireRequestUriRegistration             bool     `json:"require_request_uri_registration"`
	OpPolicyUri                               string   `json:"op_policy_uri"`
	OpTosUri                                  string   `json:"op_tos_uri"`
}

func GetDiscoveryDocument(issuer string) (OpenIdDiscoveryDocument, error) {
	return GetDiscoveryDocumentCustomClient(issuer, http.DefaultClient)
}

func GetDiscoveryDocumentCustomClient(issuer string, client *http.Client) (OpenIdDiscoveryDocument, error) {
	req, err := http.NewRequest(http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return OpenIdDiscoveryDocument{}, err
	}

	res, err := client.Do(req)
	if err != nil {
		return OpenIdDiscoveryDocument{}, err
	}

	if res.StatusCode != http.StatusOK {
		return OpenIdDiscoveryDocument{}, errors.New(fmt.Sprintf("wrong response code: %d", res.StatusCode))
	}

	var discoveryDoc OpenIdDiscoveryDocument
	err = json.NewDecoder(res.Body).Decode(&discoveryDoc)
	if err != nil {
		return OpenIdDiscoveryDocument{}, err
	}

	return discoveryDoc, nil
}
