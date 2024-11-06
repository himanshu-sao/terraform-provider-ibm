package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// OAuth2ClientConfig holds the configuration for the OAuth2 client
type OAuth2ClientConfig struct {
	TenantURL               string
	ServiceCredClientID     string
	ServiceCredClientSecret string
}

// getOAuth2ClientConfig extracts the OAuth2 client configuration from the provided interface
func GetOAuth2ClientConfig(m interface{}) (*OAuth2ClientConfig, error) {
	config := m.(*ServiceConfig)

	if config.TenantURL == "" {
		return nil, fmt.Errorf("tenant_url is not set in the provider configuration")
	}
	if config.ServiceCredClientID == "" {
		return nil, fmt.Errorf("serviceCredClientID is not set in the provider configuration")
	}
	if config.ServiceCredClientSecret == "" {
		return nil, fmt.Errorf("serviceCredClientSecret is not set in the provider configuration")
	}

	return &OAuth2ClientConfig{
		TenantURL:               config.TenantURL,
		ServiceCredClientID:     config.ServiceCredClientID,
		ServiceCredClientSecret: config.ServiceCredClientSecret,
	}, nil
}

// getAccessToken fetches an access token using the provided OAuth2 client configuration
func GetAccessToken(config *OAuth2ClientConfig) (string, error) {
	tokenURL := fmt.Sprintf("%s%s", config.TenantURL, TokenEndpointPath)
	return fetchAccessToken(tokenURL, config.ServiceCredClientID, config.ServiceCredClientSecret)
}

// fetchAccessToken makes a request to obtain an access token
func fetchAccessToken(tokenURL, clientID, clientSecret string) (string, error) {
	data := url.Values{}
	data.Set(GrantTypeKey, GrantTypeClientCreds)
	data.Set(ClientIDKey, clientID)
	data.Set(ClientSecretKey, clientSecret)

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		log.Printf("[ERROR] Error making token request: %s", err)
		return "", fmt.Errorf("error making token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] Error reading response body: %s", err)
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	accessToken, _, _, _, err := ParseTokenResponse(body)
	if err != nil {
		log.Printf("[ERROR] Error parsing token response: %s", err)
		return "", fmt.Errorf("error parsing token response: %w", err)
	}

	return accessToken, nil
}

// handleHTTPResponse checks if the HTTP response status code matches the expected status
func HandleHTTPResponse(resp *http.Response, expectedStatus int) error {
	if resp.StatusCode != expectedStatus {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("[ERROR] Unexpected status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}
	return nil
}

// buildPayloadFromSchema constructs a payload from the Terraform schema data
func BuildPayloadFromSchema(resourceData *schema.ResourceData) (map[string]interface{}, error) {
	payload := make(map[string]interface{})

	if jsonPath, ok := resourceData.GetOk(JsonConfigPathKey); ok {
		log.Printf("[DEBUG] Using JSON config file: %s", jsonPath.(string))
		jsonFile, err := os.ReadFile(jsonPath.(string))
		if err != nil {
			log.Printf("[ERROR] Failed to read JSON file: %s", err)
			return nil, fmt.Errorf("error reading JSON file: %w", err)
		}

		err = json.Unmarshal(jsonFile, &payload)
		if err != nil {
			log.Printf("[ERROR] Failed to parse JSON file: %s", err)
			return nil, fmt.Errorf("error parsing JSON file: %w", err)
		}
	} else {
		for _, key := range SchemaFields {
			if !ExcludedFieldsFromPayload[key] {
				if v, ok := resourceData.GetOk(key); ok {
					payload[key] = v
				}
			}
		}
	}

	// Log the payload before removing excluded fields
	log.Printf("[ERROR] Payload before removing excluded fields: %+v", payload)

	// Remove excluded fields from payload
	for key := range ExcludedFieldsFromPayload {
		delete(payload, key)
	}

	// Log the payload after removing excluded fields
	log.Printf("[ERROR] Payload after removing excluded fields: %+v", payload)

	if err := validateJSONPayload(payload); err != nil {
		log.Printf("[ERROR] Invalid payload: %s", err)
		return nil, fmt.Errorf("invalid payload: %w", err)
	}

	return payload, nil
}

// sendRequest sends an HTTP request with the given method, URL, payload, and access token
func SendRequest(method, url string, payload map[string]interface{}, accessToken string) (*http.Response, error) {
	requestBody, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal request body: %s", err)
		return nil, fmt.Errorf("error marshaling request body: %w", err)
	}

	client := &http.Client{}
	req, err := CreateHTTPRequest(method, url, bytes.NewReader(requestBody), accessToken)
	if err != nil {
		return nil, err
	}

	log.Printf("[DEBUG] Sending request to %s", req.URL.String())
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed to make request: %s", err)
		return nil, fmt.Errorf("error making request: %w", err)
	}

	return resp, nil
}

// parseAndSetOAuth2ClientData parses the response body and sets the data in the Terraform schema
func ParseAndSetOAuth2ClientData(resourceData *schema.ResourceData, body io.Reader) error {
	var result map[string]interface{}
	if err := json.NewDecoder(body).Decode(&result); err != nil {
		return fmt.Errorf("error decoding JSON response: %w", err)
	}

	for k, v := range result {
		if err := resourceData.Set(k, v); err != nil {
			return fmt.Errorf("error setting %s: %w", k, err)
		}
	}
	return nil
}

// createHTTPRequest creates an HTTP request with the necessary headers
func CreateHTTPRequest(method, url string, body io.Reader, accessToken string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Add("Content-Type", "application/json")

	return req, nil
}

// validateJSONPayload checks if the payload contains all required fields and if they are of the correct type
func validateJSONPayload(payload map[string]interface{}) error {
	required := []string{"redirect_uris", "client_name"}
	for _, field := range required {
		if _, ok := payload[field]; !ok {
			return fmt.Errorf("missing required field: %s", field)
		}
	}

	if redirectURIs, ok := payload["redirect_uris"].([]interface{}); ok {
		if len(redirectURIs) == 0 {
			return fmt.Errorf("redirect_uris must not be empty")
		}
		for _, uri := range redirectURIs {
			if _, ok := uri.(string); !ok {
				return fmt.Errorf("redirect_uris must be an array of strings")
			}
		}
	} else {
		return fmt.Errorf("redirect_uris must be an array")
	}

	if _, ok := payload["client_name"].(string); !ok {
		return fmt.Errorf("client_name must be a string")
	}

	return nil
}
