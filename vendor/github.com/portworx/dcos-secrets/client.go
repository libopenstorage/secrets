package api

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

type DCOSSecrets interface {
	UpdateACSToken(token string)
	GetSecret(store, key string) (*Secret, error)
	CreateSecret(store, key string, secret *Secret) error
	UpdateSecret(store, key string, secret *Secret) error
	CreateOrUpdateSecret(store, key string, secret *Secret) error
	DeleteSecret(store, key string) error
	RevokeSecret(store, key string) error
	RenewSecret(store, key string, duration int64) error
}

const (
	DefaultClusterURL = "https://master.mesos"
)

var (
	ErrNotImplemented = errors.New("API not implemented")
)

// variables to stub the external package calls
var (
	jsonMarshal    = json.Marshal
	jsonUnmarshal  = json.Unmarshal
	httpNewRequest = http.NewRequest
	ioutilReadFile = ioutil.ReadFile
	ioutilReadAll  = ioutil.ReadAll
)

// HTTPClient interface is used to mock the http.Client
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type secretsClient struct {
	config     Config
	httpClient HTTPClient
}

func NewClient(config Config) (DCOSSecrets, error) {
	tlsConfig, err := getTLSConfig(config)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return &secretsClient{
		config:     config,
		httpClient: httpClient,
	}, nil
}

func getTLSConfig(config Config) (*tls.Config, error) {
	if config.Insecure {
		return &tls.Config{
			InsecureSkipVerify: true,
		}, nil
	}

	if config.CACertFile == "" {
		return nil, fmt.Errorf("CA certificate file missing.")
	}

	caCert, err := ioutilReadFile(config.CACertFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to read CA certs. %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("Could not parse any CA certificates")
	}

	return &tls.Config{
		RootCAs: caCertPool,
	}, nil
}

func (s *secretsClient) UpdateACSToken(token string) {
	s.config.ACSToken = token
}

func (s *secretsClient) apiGet(path string, result interface{}) error {
	return s.apiRequest("GET", path, nil, result)
}

func (s *secretsClient) apiPut(path string, body, result interface{}) error {
	return s.apiRequest("PUT", path, body, result)
}

func (s *secretsClient) apiPatch(path string, body, result interface{}) error {
	return s.apiRequest("PATCH", path, body, result)
}

func (s *secretsClient) apiDelete(path string, result interface{}) error {
	return s.apiRequest("DELETE", path, nil, result)
}

func (s *secretsClient) apiRequest(method, path string, body, result interface{}) error {
	var requestBody []byte
	var err error

	if body != nil {
		if requestBody, err = jsonMarshal(body); err != nil {
			return err
		}
	}

	request, err := buildJSONRequest(method, s.config.ClusterURL+path, bytes.NewReader(requestBody))
	if err != nil {
		return err
	}

	if s.config.ACSToken != "" {
		request.Header.Set("Authorization", "token="+s.config.ACSToken)
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusUnauthorized ||
		response.StatusCode == http.StatusForbidden {
		return NewAPIError([]byte(http.StatusText(response.StatusCode)))
	}

	return apiResponse(response, result)
}

func apiResponse(response *http.Response, result interface{}) error {
	responseBody, err := ioutilReadAll(response.Body)
	if err != nil {
		return err
	}

	if response.StatusCode >= 200 && response.StatusCode <= 299 {
		if result != nil {
			if err := json.Unmarshal(responseBody, result); err != nil {
				return err
			}
		}
		return nil
	}

	return NewAPIError(responseBody)
}

func buildJSONRequest(method string, url string, reader io.Reader) (*http.Request, error) {
	request, err := httpNewRequest(method, url, reader)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Accept", "application/json")

	return request, nil
}
