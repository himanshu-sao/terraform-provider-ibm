package securityverify

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func ResourceIBMSecurityVerifyOidcApp() *schema.Resource {
	return &schema.Resource{
		Create: resourceIBMSecurityVerifyOidcAppCreate,
		Read:   resourceIBMSecurityVerifyOidcAppRead,
		Update: resourceIBMSecurityVerifyOidcAppUpdate,
		Delete: resourceIBMSecurityVerifyOidcAppDelete,

		Schema: map[string]*schema.Schema{
			"client_name": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"access_policy": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "default",
			},
			"all_users_entitled": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
			"authorization_encrypted_response_alg": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "none",
			},
			"authorization_encrypted_response_enc": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "none",
			},
			"authorization_signed_response_alg": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "RS256",
			},
			"client_secret_expires_at": {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  0,
			},
			"consent_action": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "always_prompt",
			},
			"enforce_pkce": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
			"grant_types": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"id_token_map": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"id_token_signed_response_alg": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "RS256",
			},
			"redirect_uris": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"request_object_check_expiry": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"request_object_lifetime": {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  1800,
			},
			"request_object_parameters_only": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"request_object_signing_alg": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "RS256",
			},
			"require_pushed_authorization_requests": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"response_types": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"restrict_api_entitlements": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"token_endpoint_auth_method": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "default",
			},
			"token_endpoint_auth_single_use_jti": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"token_map": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			// Computed fields
			"client_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"client_secret": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"client_id_issued_at": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"initiate_login_uri": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"registration_access_token": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"registration_client_uri": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}
