package discovery

import (
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_GetDiscoveryDocumentSuccessCase(t *testing.T) {
	const exampleDiscoveryDoc = `{"issuer":"https://sso.k8s.patrick246.de/auth/realms/patrick246","authorization_endpoint":"https://sso.k8s.patrick246.de/auth/realms/patrick246/protocol/openid-connect/auth","token_endpoint":"https://sso.k8s.patrick246.de/auth/realms/patrick246/protocol/openid-connect/token","introspection_endpoint":"https://sso.k8s.patrick246.de/auth/realms/patrick246/protocol/openid-connect/token/introspect","userinfo_endpoint":"https://sso.k8s.patrick246.de/auth/realms/patrick246/protocol/openid-connect/userinfo","end_session_endpoint":"https://sso.k8s.patrick246.de/auth/realms/patrick246/protocol/openid-connect/logout","jwks_uri":"https://sso.k8s.patrick246.de/auth/realms/patrick246/protocol/openid-connect/certs","check_session_iframe":"https://sso.k8s.patrick246.de/auth/realms/patrick246/protocol/openid-connect/login-status-iframe.html","grant_types_supported":["authorization_code","implicit","refresh_token","password","client_credentials"],"response_types_supported":["code","none","id_token","token","id_token token","code id_token","code token","code id_token token"],"subject_types_supported":["public","pairwise"],"id_token_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"id_token_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"id_token_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"userinfo_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],"request_object_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],"response_modes_supported":["query","fragment","form_post"],"registration_endpoint":"https://sso.k8s.patrick246.de/auth/realms/patrick246/clients-registrations/openid-connect","token_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"token_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"claims_supported":["aud","sub","iss","auth_time","name","given_name","family_name","preferred_username","email","acr"],"claim_types_supported":["normal"],"claims_parameter_supported":true,"scopes_supported":["openid","offline_access","profile","email","address","phone","roles","web-origins","microprofile-jwt"],"request_parameter_supported":true,"request_uri_parameter_supported":true,"require_request_uri_registration":true,"code_challenge_methods_supported":["plain","S256"],"tls_client_certificate_bound_access_tokens":true,"revocation_endpoint":"https://sso.k8s.patrick246.de/auth/realms/patrick246/protocol/openid-connect/revoke","revocation_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"revocation_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"backchannel_logout_supported":true,"backchannel_logout_session_supported":true}`

	testHandler := http.NewServeMux()
	testHandler.HandleFunc("/.well-known/openid-configuration", func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(exampleDiscoveryDoc))
	})

	testServer := httptest.NewServer(testHandler)

	doc, err := GetDiscoveryDocument(testServer.URL)
	require.NoError(t, err)

	require.Equal(t, "https://sso.k8s.patrick246.de/auth/realms/patrick246", doc.Issuer)
	require.Equal(t, "https://sso.k8s.patrick246.de/auth/realms/patrick246/protocol/openid-connect/auth", doc.AuthorizationEndpoint)
	require.Equal(t, "https://sso.k8s.patrick246.de/auth/realms/patrick246/protocol/openid-connect/token", doc.TokenEndpoint)
	require.Equal(t, "https://sso.k8s.patrick246.de/auth/realms/patrick246/protocol/openid-connect/certs", doc.JwksUri)
	require.Equal(t, []string{"authorization_code", "implicit", "refresh_token", "password", "client_credentials"}, doc.GrantTypesSupported)
	require.Equal(t, true, doc.ClaimsParameterSupported)
}

func Test_GetDiscoveryDocumentServerErrorCase(t *testing.T) {
	testHandler := http.NewServeMux()
	testHandler.HandleFunc("/.well-known/openid-configuration", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(500)
	})

	testServer := httptest.NewServer(testHandler)

	doc, err := GetDiscoveryDocument(testServer.URL)
	require.Equal(t, doc, OpenIdDiscoveryDocument{})
	require.NotNil(t, err)
	require.Equal(t, err.Error(), "wrong response code: 500")
}
