package gcloud

import (
	"context"
	"fmt"
	"github.com/libopenstorage/secrets/gcloud"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/store"
)

type gcloudStore struct {
	secrets secrets.Secrets
}

func (s *gcloudStore) Get(ctx context.Context, key store.SecretKey) (secret map[string]any, err error) {
	secretId := createSecretId(key)
	keyContext := map[string]string{secrets.CustomSecretData: "true"}
	return s.secrets.GetSecret(secretId, keyContext)
}

func (s *gcloudStore) Set(ctx context.Context, key store.SecretKey, secret map[string]any) error {
	secretId := createSecretId(key)
	keyContext := map[string]string{secrets.CustomSecretData: "true", secrets.OverwriteSecretDataInStore: "true"}
	return s.secrets.PutSecret(secretId, secret, keyContext)
}

func (s *gcloudStore) Delete(ctx context.Context, key store.SecretKey) error {
	secretId := createSecretId(key)
	return s.secrets.DeleteSecret(secretId, nil)
}

func NewGCloudStore(secretConfig map[string]interface{}) (store.Store, error) {
	sec, err := gcloud.New(secretConfig)
	if err != nil {
		return nil, err
	}

	return &gcloudStore{secrets: sec}, nil
}

func createSecretId(key store.SecretKey) string {
	return fmt.Sprintf("%s/%s", key.Prefix, key.Name)
}
