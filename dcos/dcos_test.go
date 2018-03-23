package dcos

import (
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/dcos/mock"
	api "github.com/portworx/dcos-secrets"
	"github.com/stretchr/testify/assert"
)

func TestFailOnMissingCredentials(t *testing.T) {
	secretConfig := make(map[string]interface{})
	_, err := New(secretConfig)
	assert.NotNil(t, err)
	assert.Equal(t, ErrMissingCredentials, err)

	secretConfig = make(map[string]interface{})
	secretConfig[KeyUsername] = "username"
	_, err = New(secretConfig)
	assert.NotNil(t, err)
	assert.Equal(t, ErrMissingCredentials, err)

	secretConfig = make(map[string]interface{})
	secretConfig[KeyPassword] = "password"
	_, err = New(secretConfig)
	assert.NotNil(t, err)
	assert.Equal(t, ErrMissingCredentials, err)
}

func TestGetSecretWhenClientReturnsError(t *testing.T) {
	mockClient := getMockDCOSSecretsClient(t)
	s := getMockDCOSSecrets(mockClient)

	secretPath := "path/to/secret"
	mockClient.EXPECT().
		GetSecret("", secretPath).
		Return(nil, fmt.Errorf("Get secret error")).
		Times(1)

	_, err := s.GetSecret(secretPath, nil)

	assert.NotNil(t, err)
	assert.Equal(t, "Get secret error", err.Error())
}

func TestGetSecretWithEmptySecret(t *testing.T) {
	mockClient := getMockDCOSSecretsClient(t)
	s := getMockDCOSSecrets(mockClient)

	secretPath := "path/to/string_secret"
	mockClient.EXPECT().
		GetSecret("", secretPath).
		Return(nil, nil).
		Times(1)

	_, err := s.GetSecret(secretPath, nil)

	assert.NotNil(t, err)
	assert.Equal(t, secrets.ErrInvalidSecretId, err)
}

func TestGetSecretWithStringData(t *testing.T) {
	mockClient := getMockDCOSSecretsClient(t)
	s := getMockDCOSSecrets(mockClient)

	// Test without secret store / default secret store
	secretPath := "path/to/string_secret"
	secret := &api.Secret{
		Value: "string_value",
	}
	mockClient.EXPECT().
		GetSecret("", secretPath).
		Return(secret, nil).
		Times(1)

	secretData, err := s.GetSecret(secretPath, nil)

	assert.Nil(t, err)
	assert.Equal(t, 1, len(secretData))
	assert.Equal(t, "string_value", secretData[secretPath])

	// Test with a given secret store
	keyContext := map[string]string{KeySecretStore: "custom_store"}
	mockClient.EXPECT().
		GetSecret("custom_store", secretPath).
		Return(secret, nil).
		Times(1)

	secretData, err = s.GetSecret(secretPath, keyContext)

	assert.Nil(t, err)
	assert.Equal(t, 1, len(secretData))
	assert.Equal(t, "string_value", secretData[secretPath])
}

func TestGetSecretWithJSONData(t *testing.T) {
	mockClient := getMockDCOSSecretsClient(t)
	s := getMockDCOSSecrets(mockClient)

	// Test without secret store / default secret store
	secretPath := "path/to/json_secret"
	secret := &api.Secret{
		Value: `{"alpha": "foo", "numeric": 10}`,
	}
	mockClient.EXPECT().
		GetSecret("", secretPath).
		Return(secret, nil).
		Times(1)

	secretData, err := s.GetSecret(secretPath, nil)

	assert.Nil(t, err)
	assert.Equal(t, 2, len(secretData))
	assert.Equal(t, "foo", secretData["alpha"])
	assert.Equal(t, float64(10), secretData["numeric"])

	// Test with a given secret store
	keyContext := map[string]string{KeySecretStore: "custom_store"}
	mockClient.EXPECT().
		GetSecret("custom_store", secretPath).
		Return(secret, nil).
		Times(1)

	secretData, err = s.GetSecret(secretPath, keyContext)

	assert.Nil(t, err)
	assert.Equal(t, 2, len(secretData))
	assert.Equal(t, "foo", secretData["alpha"])
	assert.Equal(t, float64(10), secretData["numeric"])
}

func TestPutSecretWithEmptyData(t *testing.T) {
	mockClient := getMockDCOSSecretsClient(t)
	s := getMockDCOSSecrets(mockClient)

	err := s.PutSecret("path/to/secret", nil, nil)

	assert.NotNil(t, err)
	assert.Equal(t, secrets.ErrEmptySecretData, err)

	err = s.PutSecret("path/to/secret", make(map[string]interface{}), nil)

	assert.NotNil(t, err)
	assert.Equal(t, secrets.ErrEmptySecretData, err)
}

func TestPutSecretWhenClientReturnsError(t *testing.T) {
	mockClient := getMockDCOSSecretsClient(t)
	s := getMockDCOSSecrets(mockClient)

	data := map[string]interface{}{"alpha": "foo"}
	mockClient.EXPECT().
		CreateOrUpdateSecret("store",
			"path/to/secret",
			gomock.Eq(&api.Secret{
				Author: SecretsAuthor,
				Value:  `{"alpha":"foo"}`,
			})).
		Return(fmt.Errorf("Put secret error")).
		Times(1)

	keyContext := map[string]string{KeySecretStore: "store"}
	err := s.PutSecret("path/to/secret", data, keyContext)

	assert.NotNil(t, err)
	assert.Equal(t, "Put secret error", err.Error())
}

func TestPutSecretWithValidData(t *testing.T) {
	mockClient := getMockDCOSSecretsClient(t)
	s := getMockDCOSSecrets(mockClient)

	data := make(map[string]interface{})
	data["alpha"] = "foo"
	data["numeric"] = 10
	mockClient.EXPECT().
		CreateOrUpdateSecret("store",
			"path/to/secret",
			gomock.Eq(&api.Secret{
				Author: SecretsAuthor,
				Value:  `{"alpha":"foo","numeric":10}`,
			})).
		Return(nil).
		Times(1)

	keyContext := map[string]string{KeySecretStore: "store"}
	err := s.PutSecret("path/to/secret", data, keyContext)

	assert.Nil(t, err)
}

func getMockDCOSSecretsClient(t *testing.T) *mock.MockDCOSSecrets {
	return mock.NewMockDCOSSecrets(gomock.NewController(t))
}

func getMockDCOSSecrets(mockClient *mock.MockDCOSSecrets) secrets.Secrets {
	return &dcosSecrets{
		client: mockClient,
	}
}
