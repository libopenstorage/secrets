package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	authLoginPath = "/acs/api/v1/auth/login"
)

// CreateTokenRequest request object to the create token API
type CreateTokenRequest struct {
	UID      string `json:"uid,omitempty"`
	Password string `json:"password,omitempty"`
}

// CreateTokenResponse response object from the create token API
type CreateTokenResponse struct {
	Token string `json:"token,omitempty"`
}

type TokenConfig struct {
	Config
	// Username username of the user who has access to the APIs. The Username
	// and Password are needed to generate the DC/OS ACS token.
	Username string

	// Password password of the user to generate the ACS token.
	Password string
}

func DefaultTokenConfig() TokenConfig {
	return TokenConfig{
		Config: Config{
			ClusterURL: DefaultClusterURL,
			Insecure:   false,
		},
	}
}

// GenerateACSToken creates a new DC/OS token that can be used by API calls
func GenerateACSToken(config TokenConfig) (string, error) {

	if config.Username == "" || config.Password == "" {
		return "", fmt.Errorf("Username/password cannot be empty")
	}

	client, httpErr := newHTTPClient(config)
	if httpErr != nil {
		return "", httpErr
	}

	requestBody, jsonErr := json.Marshal(
		CreateTokenRequest{
			UID:      config.Username,
			Password: config.Password,
		},
	)
	if jsonErr != nil {
		return "", jsonErr
	}

	request, err := buildJSONRequest("POST", config.ClusterURL+authLoginPath, bytes.NewReader(requestBody))
	if err != nil {
		return "", err
	}

	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	result := new(CreateTokenResponse)
	if err := apiResponse(response, result); err != nil {
		return "", err
	}

	return result.Token, nil
}

func newHTTPClient(config TokenConfig) (*http.Client, error) {
	tlsConfig, err := getTLSConfig(config.Config)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}
