package securityverify

import (
	"fmt"
	"log"
	"net/http"

	"github.com/IBM-Cloud/terraform-provider-ibm/ibm/service/securityverify/util"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceIBMSecurityVerifyOidcAppCreate(resourceData *schema.ResourceData, m interface{}) error {
	config, err := util.GetOAuth2ClientConfig(m)
	if err != nil {
		return err
	}

	accessToken, err := util.GetAccessToken(config)
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] Creating OAuth2 client. Tenant URL: %s", config.TenantURL)

	payload, err := util.BuildPayloadFromSchema(resourceData)
	if err != nil {
		return err
	}

	resp, err := util.SendRequest("POST", fmt.Sprintf("%s%s", config.TenantURL, util.OauthClientEndpoint), payload, accessToken)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := util.HandleHTTPResponse(resp, http.StatusCreated); err != nil {
		return err
	}

	if err := util.ParseAndSetOAuth2ClientData(resourceData, resp.Body); err != nil {
		log.Printf("[ERROR] Failed to parse response: %s", err)
		return fmt.Errorf("error parsing response: %w", err)
	}

	resourceData.SetId(resourceData.Get("client_id").(string))
	log.Printf("[DEBUG] Successfully created OAuth2 client with ID: %s", resourceData.Id())
	return nil
}
