package docker

import (
	"context"
	"fmt"
	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/docker"
	"github.com/libopenstorage/secrets/store"
)

type dockerReader struct {
	secrets secrets.Secrets
}

func (s *dockerReader) Get(ctx context.Context, key store.SecretKey) (secret map[string]any, err error) {
	secretId := createSecretId(key)
	return s.secrets.GetSecret(secretId, nil)
}

func createSecretId(key store.SecretKey) string {
	return fmt.Sprintf("%s_%s", key.Prefix, key.Name)
}

func NewDockerReader(secretConfig map[string]interface{}) (store.Reader, error) {
	sec, err := docker.New(secretConfig)
	if err != nil {
		return nil, err
	}

	return &dockerReader{secrets: sec}, nil
}
