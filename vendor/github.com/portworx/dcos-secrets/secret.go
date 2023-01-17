package api

import (
	"errors"
	"fmt"
	"strings"
)

type Secret struct {
	Value string `json:"value,omitempty"`
}

var (
	ErrKeyEmpty = errors.New("Secret path cannot be empty")
)

const (
	defaultSecretStore = "default"
	secretsPath        = "/secrets/v1/secret"
)

func (s *secretsClient) GetSecret(store, key string) (*Secret, error) {
	path, err := s.getSecretsPath(store, key)
	if err != nil {
		return nil, err
	}

	secret := new(Secret)
	if err := s.apiGet(path, secret); err != nil {
		return nil, err
	}
	return secret, nil
}

func (s *secretsClient) CreateSecret(store, key string, secret *Secret) error {
	path, err := s.getSecretsPath(store, key)
	if err != nil {
		return err
	}
	return s.apiPut(path, secret, nil)
}

func (s *secretsClient) UpdateSecret(store, key string, secret *Secret) error {
	path, err := s.getSecretsPath(store, key)
	if err != nil {
		return err
	}
	return s.apiPatch(path, secret, nil)
}

func (s *secretsClient) CreateOrUpdateSecret(store, key string, secret *Secret) error {
	err := s.CreateSecret(store, key, secret)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		return s.UpdateSecret(store, key, secret)
	}
	return err
}

func (s *secretsClient) DeleteSecret(store, key string) error {
	path, err := s.getSecretsPath(store, key)
	if err != nil {
		return err
	}
	return s.apiDelete(path, nil)
}

func (s *secretsClient) RevokeSecret(store, key string) error {
	return ErrNotImplemented
}

func (s *secretsClient) RenewSecret(store, key string, duration int64) error {
	return ErrNotImplemented
}

func (s *secretsClient) getSecretsPath(store, key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", ErrKeyEmpty
	} else if strings.HasPrefix(key, "/") {
		return "", fmt.Errorf("Path to secret should not start with slash")
	}

	if strings.TrimSpace(store) == "" {
		store = defaultSecretStore
	}

	apiPath := fmt.Sprintf("%s/%s/%s", secretsPath, store, key)
	return apiPath, nil
}
