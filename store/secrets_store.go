package store

import "context"

type SecretKey struct {
	Prefix string
	Name   string
}

type Reader interface {
	Get(ctx context.Context, key SecretKey) (secret map[string]any, err error)
}

type Store interface {
	Reader
	Set(ctx context.Context, key SecretKey, secret map[string]any) error
	Delete(ctx context.Context, key SecretKey) error
}
