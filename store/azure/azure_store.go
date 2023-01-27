package azure

import (
	"context"
	"fmt"
	"github.com/libopenstorage/secrets/azure"

	"github.com/libopenstorage/secrets"
)

type azureStore struct {
	secrets secrets.Secrets
}

func (s *azureStore) String() string {
	return s.secrets.String()
}

func (s *azureStore) Get(_ context.Context, key secrets.SecretKey) (secret map[string]any, err error) {
	secretId := createSecretId(key)
	return s.secrets.GetSecret(secretId, nil)
}

func (s *azureStore) Set(_ context.Context, key secrets.SecretKey, secret map[string]any) error {
	secretId := createSecretId(key)
	return s.secrets.PutSecret(secretId, secret, nil)
}

func (s *azureStore) Delete(_ context.Context, key secrets.SecretKey) error {
	secretId := createSecretId(key)
	return s.secrets.DeleteSecret(secretId, nil)
}

func createSecretId(key secrets.SecretKey) string {
	return fmt.Sprintf("%s/%s", key.Prefix, key.Name)
}

func NewAzureStore(secretConfig map[string]interface{}) (secrets.SecretStore, error) {
	sec, err := azure.New(secretConfig)
	if err != nil {
		return nil, err
	}

	return &azureStore{secrets: sec}, nil
}
