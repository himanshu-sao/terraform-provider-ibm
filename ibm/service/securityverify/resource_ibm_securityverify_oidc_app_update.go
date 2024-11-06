package securityverify

import (
	"fmt"
	"log"
	"net/http"

	"github.com/IBM-Cloud/terraform-provider-ibm/ibm/service/securityverify/util"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceIBMSecurityVerifyOidcAppUpdate(resourceData *schema.ResourceData, m interface{}) error {
	config, err := util.GetOAuth2ClientConfig(m)
	if err != nil {
		return err
	}

	accessToken, err := util.GetAccessToken(config)
	if err != nil {
		return err
	}

	clientID := resourceData.Id()
	log.Printf("[DEBUG] Updating OAuth2 client with ID: %s. Tenant URL: %s", clientID, config.TenantURL)

	payload, err := util.BuildPayloadFromSchema(resourceData)
	if err != nil {
		return err
	}

	resp, err := util.SendRequest("PUT", fmt.Sprintf("%s%s/%s", config.TenantURL, util.OauthClientEndpoint, clientID), payload, accessToken)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := util.HandleHTTPResponse(resp, http.StatusOK); err != nil {
		return err
	}

	if err := util.ParseAndSetOAuth2ClientData(resourceData, resp.Body); err != nil {
		log.Printf("[ERROR] Failed to parse response: %s", err)
		return fmt.Errorf("error parsing response: %w", err)
	}

	log.Printf("[DEBUG] Successfully updated OAuth2 client with ID: %s", resourceData.Id())
	return nil
}
