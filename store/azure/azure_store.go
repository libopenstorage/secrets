package azure

import (
	"context"
	"fmt"
	"github.com/libopenstorage/secrets/azure"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/store"
)

type azureStore struct {
	secrets secrets.Secrets
}

func (s *azureStore) Get(ctx context.Context, key store.SecretKey) (secret map[string]any, err error) {
	secretId := createSecretId(key)
	return s.secrets.GetSecret(secretId, nil)
}

func (s *azureStore) Set(ctx context.Context, key store.SecretKey, secret map[string]any) error {
	secretId := createSecretId(key)
	return s.secrets.PutSecret(secretId, secret, nil)
}

func (s *azureStore) Delete(ctx context.Context, key store.SecretKey) error {
	secretId := createSecretId(key)
	return s.secrets.DeleteSecret(secretId, nil)
}

func createSecretId(key store.SecretKey) string {
	return fmt.Sprintf("%s/%s", key.Prefix, key.Name)
}

func NewAzureStore(secretConfig map[string]interface{}) (store.Store, error) {
	sec, err := azure.New(secretConfig)
	if err != nil {
		return nil, err
	}

	return &azureStore{secrets: sec}, nil
}
