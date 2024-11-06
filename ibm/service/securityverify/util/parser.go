package util

import (
	"encoding/json"
	"fmt"
	"log"
)

// ParseTokenResponse parses the token response and extracts required fields
func ParseTokenResponse(body []byte) (string, string, string, int, error) {
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("[ERROR] Error parsing JSON response: %s", err)
		return "", "", "", 0, fmt.Errorf("error parsing JSON response: %s", err)
	}

	accessToken, ok := result[AccessTokenField].(string)
	if !ok {
		return "", "", "", 0, fmt.Errorf("%s not found in response", AccessTokenField)
	}

	grantID, ok := result[GrantIDField].(string)
	if !ok {
		return "", "", "", 0, fmt.Errorf("%s not found in response", GrantIDField)
	}

	tokenType, ok := result[TokenTypeField].(string)
	if !ok {
		return "", "", "", 0, fmt.Errorf("%s not found in response", TokenTypeField)
	}

	expiresIn, ok := result[ExpiresInField].(float64)
	if !ok {
		return "", "", "", 0, fmt.Errorf("%s not found in response", ExpiresInField)
	}

	return accessToken, grantID, tokenType, int(expiresIn), nil
}
