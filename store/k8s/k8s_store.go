package k8s

import (
	"context"
	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/k8s"
)

type k8sStore struct {
	secrets secrets.Secrets
}

func (s *k8sStore) String() string {
	return s.secrets.String()
}

func (s *k8sStore) Get(_ context.Context, key secrets.SecretKey) (secret map[string]any, err error) {
	keyContext := map[string]string{secrets.KeyVaultNamespace: key.Prefix}
	return s.secrets.GetSecret(key.Name, keyContext)
}

func (s *k8sStore) Set(_ context.Context, key secrets.SecretKey, secret map[string]any) error {
	keyContext := map[string]string{secrets.KeyVaultNamespace: key.Prefix}
	return s.secrets.PutSecret(key.Name, secret, keyContext)
}

func (s *k8sStore) Delete(_ context.Context, key secrets.SecretKey) error {
	keyContext := map[string]string{secrets.KeyVaultNamespace: key.Prefix}
	return s.secrets.DeleteSecret(key.Name, keyContext)
}

func NewK8SStore(secretConfig map[string]interface{}) (secrets.SecretStore, error) {
	sec, err := k8s.New(secretConfig)
	if err != nil {
		return nil, err
	}

	return &k8sStore{secrets: sec}, nil
}
