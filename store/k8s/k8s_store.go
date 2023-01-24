package k8s

import (
	"context"
	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/k8s"
	"github.com/libopenstorage/secrets/store"
)

type k8sStore struct {
	secrets secrets.Secrets
}

func (s *k8sStore) Get(ctx context.Context, key store.SecretKey) (secret map[string]any, err error) {
	keyContext := map[string]string{secrets.KeyVaultNamespace: key.Prefix}
	return s.secrets.GetSecret(key.Name, keyContext)
}

func (s *k8sStore) Set(ctx context.Context, key store.SecretKey, secret map[string]any) error {
	keyContext := map[string]string{secrets.KeyVaultNamespace: key.Prefix}
	return s.secrets.PutSecret(key.Name, secret, keyContext)
}

func (s *k8sStore) Delete(ctx context.Context, key store.SecretKey) error {
	keyContext := map[string]string{secrets.KeyVaultNamespace: key.Prefix}
	return s.secrets.DeleteSecret(key.Name, keyContext)
}

func NewK8SStore(secretConfig map[string]interface{}) (store.Store, error) {
	sec, err := k8s.New(secretConfig)
	if err != nil {
		return nil, err
	}

	return &k8sStore{secrets: sec}, nil
}
