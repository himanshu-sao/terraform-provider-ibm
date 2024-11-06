package util

// Constants for token URL and grant type
const (
	TokenEndpointPath    = "/v1.0/endpoint/default/token"
	GrantTypeClientCreds = "client_credentials"

	// JSON Response Fields
	AccessTokenField = "access_token"
	GrantIDField     = "grant_id"
	TokenTypeField   = "token_type"
	ExpiresInField   = "expires_in"

	// Schema Keys
	TenantURLKey               = "tenant_url"
	ServiceCredClientIDKey     = "service_cred_client_id"
	ServiceCredClientSecretKey = "service_cred_client_secret"
	AccessTokenKey             = "access_token"
	GrantIDKey                 = "grant_id"
	TokenTypeKey               = "token_type"
	ExpiresInKey               = "expires_in"
	JsonConfigPathKey          = "json_config_path"

	ClientIDKey     = "client_id"
	ClientSecretKey = "client_secret"
	GrantTypeKey    = "grant_type"

	OauthClientEndpoint = "/oauth2/register"
)

var SchemaFields = []string{
	"access_policy",
	"all_users_entitled",
	"authorization_encrypted_response_alg",
	"authorization_encrypted_response_enc",
	"authorization_signed_response_alg",
	"client_id",
	"client_id_issued_at",
	"client_name",
	"client_secret",
	"client_secret_expires_at",
	"consent_action",
	"enforce_pkce",
	"grant_types",
	"id_token_map",
	"id_token_signed_response_alg",
	"initiate_login_uri",
	"redirect_uris",
	"registration_access_token",
	"registration_client_uri",
	"request_object_check_expiry",
	"request_object_lifetime",
	"request_object_parameters_only",
	"request_object_signing_alg",
	"require_pushed_authorization_requests",
	"response_types",
	"restrict_api_entitlements",
	"token_endpoint_auth_method",
	"token_endpoint_auth_single_use_jti",
	"token_map",
}

type ServiceConfig struct {
	TenantURL               string
	ServiceCredClientID     string
	ServiceCredClientSecret string
}

// Add any other fields that should be excluded here
var ExcludedFieldsFromPayload = map[string]bool{
	"client_id_issued_at":       true,
	"registration_access_token": true,
	"registration_client_uri":   true,
}
