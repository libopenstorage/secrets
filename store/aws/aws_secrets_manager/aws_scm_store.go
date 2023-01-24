package aws_secrets_manager

import (
	"context"
	"fmt"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/aws/aws_secrets_manager"
	"github.com/libopenstorage/secrets/store"
)

type awsSCMStore struct {
	secrets secrets.Secrets
}

func (s *awsSCMStore) Get(ctx context.Context, key store.SecretKey) (secret map[string]any, err error) {
	secretId := createSecretId(key)
	return s.secrets.GetSecret(secretId, nil)
}

func (s *awsSCMStore) Set(ctx context.Context, key store.SecretKey, secret map[string]any) error {
	secretId := createSecretId(key)
	return s.secrets.PutSecret(secretId, secret, nil)
}

func (s *awsSCMStore) Delete(ctx context.Context, key store.SecretKey) error {
	secretId := createSecretId(key)
	return s.secrets.DeleteSecret(secretId, nil)
}

func NewAwsScmStore(secretConfig map[string]interface{}) (store.Store, error) {
	sec, err := aws_secrets_manager.New(secretConfig)
	if err != nil {
		return nil, err
	}

	return &awsSCMStore{secrets: sec}, nil
}

func createSecretId(key store.SecretKey) string {
	return fmt.Sprintf("%s/%s", key.Prefix, key.Name)
}
