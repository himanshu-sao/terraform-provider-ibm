package securityverify

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/IBM-Cloud/terraform-provider-ibm/ibm/service/securityverify/util"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceIBMSecurityVerifyOidcAppRead(resourceData *schema.ResourceData, m interface{}) error {
	config, err := util.GetOAuth2ClientConfig(m)
	if err != nil {
		return err
	}

	accessToken, err := util.GetAccessToken(config)
	if err != nil {
		return err
	}

	client := &http.Client{}
	req, err := util.CreateHTTPRequest("GET", fmt.Sprintf("%s%s/%s", config.TenantURL, util.OauthClientEndpoint, resourceData.Id()), nil, accessToken)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		resourceData.SetId("")
		return nil
	}

	if err := util.HandleHTTPResponse(resp, http.StatusOK); err != nil {
		return err
	}

	var clientData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&clientData); err != nil {
		return fmt.Errorf("error decoding response: %w", err)
	}

	for _, field := range util.SchemaFields {
		if v, ok := clientData[field]; ok {
			if field == "registration_access_token" {
				// Skip setting registration_access_token to ignore changes
				continue
			}
			if err := resourceData.Set(field, v); err != nil {
				return fmt.Errorf("error setting %s: %w", field, err)
			}
		}
	}

	return nil
}
