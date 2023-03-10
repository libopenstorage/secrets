package secrets

import "context"

type SecretKey struct {
	Prefix string
	Name   string
}

type SecretReader interface {
	String() string
	Get(ctx context.Context, key SecretKey) (secret map[string]interface{}, err error)
}

type SecretStore interface {
	SecretReader
	Set(ctx context.Context, key SecretKey, secret map[string]interface{}) error
	Delete(ctx context.Context, key SecretKey) error
}
