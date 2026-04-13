package infisical

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"
)

const tokenExpiryBuffer = 5 * time.Second

type kmsEncryptDecrypter interface {
	encrypt(plaintext string) (string, error)
	decrypt(ciphertext string) (string, error)
}

type kmsClient struct {
	httpClient   *http.Client
	baseURL      string
	kmsKeyID     string
	clientID     string
	clientSecret string

	mu        sync.RWMutex
	token     string
	expiresAt time.Time
}

func newKmsClient(siteURL, kmsKeyID, clientID, clientSecret string) *kmsClient {
	base := strings.TrimRight(siteURL, "/")
	if !strings.HasSuffix(base, "/api") {
		base += "/api"
	}
	return &kmsClient{
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		baseURL:      base,
		kmsKeyID:     kmsKeyID,
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

type loginRequest struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

type loginResponse struct {
	AccessToken string `json:"accessToken"`
	ExpiresIn   int64  `json:"expiresIn"`
}

func (c *kmsClient) login() error {
	body, err := json.Marshal(loginRequest{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
	})
	if err != nil {
		return fmt.Errorf("infisical-kms: failed to marshal login request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/v1/auth/universal-auth/login",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("infisical-kms: login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("infisical-kms: login returned %d: %s", resp.StatusCode, msg)
	}

	var result loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("infisical-kms: failed to decode login response: %w", err)
	}

	c.mu.Lock()
	c.token = result.AccessToken
	c.expiresAt = time.Now().Add(time.Duration(result.ExpiresIn)*time.Second - tokenExpiryBuffer)
	c.mu.Unlock()

	return nil
}

func (c *kmsClient) ensureToken() error {
	c.mu.RLock()
	valid := c.token != "" && time.Now().Before(c.expiresAt)
	c.mu.RUnlock()
	if valid {
		return nil
	}
	return c.login()
}

func (c *kmsClient) doKmsRequest(path string, reqBody, respBody interface{}) error {
	if err := c.ensureToken(); err != nil {
		return err
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("infisical-kms: failed to marshal request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("infisical-kms: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	c.mu.RLock()
	req.Header.Set("Authorization", "Bearer "+c.token)
	c.mu.RUnlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("infisical-kms: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("infisical-kms: request returned %d: %s", resp.StatusCode, msg)
	}

	if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
		return fmt.Errorf("infisical-kms: failed to decode response: %w", err)
	}
	return nil
}

type encryptRequest struct {
	Plaintext string `json:"plaintext"`
}

type encryptResponse struct {
	Ciphertext string `json:"ciphertext"`
}

func (c *kmsClient) encrypt(plaintext string) (string, error) {
	var resp encryptResponse
	path := fmt.Sprintf("/v1/kms/keys/%s/encrypt", c.kmsKeyID)
	encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))
	if err := c.doKmsRequest(path, encryptRequest{Plaintext: encoded}, &resp); err != nil {
		return "", err
	}
	return resp.Ciphertext, nil
}

type decryptRequest struct {
	Ciphertext string `json:"ciphertext"`
}

type decryptResponse struct {
	Plaintext string `json:"plaintext"`
}

func (c *kmsClient) decrypt(ciphertext string) (string, error) {
	var resp decryptResponse
	path := fmt.Sprintf("/v1/kms/keys/%s/decrypt", c.kmsKeyID)
	if err := c.doKmsRequest(path, decryptRequest{Ciphertext: ciphertext}, &resp); err != nil {
		return "", err
	}
	decoded, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return "", fmt.Errorf("infisical-kms: failed to base64-decode plaintext: %w", err)
	}
	return string(decoded), nil
}
