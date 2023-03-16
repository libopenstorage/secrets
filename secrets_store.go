package secrets

import (
	"context"
	"fmt"
	"sync"
)

type ReaderInit func(map[string]interface{}) (SecretReader, error)
type StoreInit func(map[string]interface{}) (SecretStore, error)

var (
	secretReaders = make(map[string]ReaderInit)
	secretStores  = make(map[string]StoreInit)
	readersLock   sync.RWMutex
	storesLock    sync.RWMutex
)

func NewReader(name string, secretConfig map[string]interface{}) (SecretReader, error) {
	readersLock.RLock()
	defer readersLock.RUnlock()

	if init, exists := secretReaders[name]; exists {
		return init(secretConfig)
	}
	return nil, ErrNotSupported
}

func NewStore(name string, secretConfig map[string]interface{}) (SecretStore, error) {
	storesLock.RLock()
	defer storesLock.RUnlock()

	if init, exists := secretStores[name]; exists {
		return init(secretConfig)
	}
	return nil, ErrNotSupported
}

func RegisterReader(name string, init ReaderInit) error {
	readersLock.Lock()
	defer readersLock.Unlock()

	if _, exists := secretReaders[name]; exists {
		return fmt.Errorf("secrets reader %v is already registered", name)
	}
	secretReaders[name] = init
	return nil
}

func RegisterStore(name string, init StoreInit) error {
	storesLock.Lock()
	defer storesLock.Unlock()

	if _, exists := secretStores[name]; exists {
		return fmt.Errorf("secrets store %v is already registered", name)
	}
	secretStores[name] = init

	return RegisterReader(name, func(m map[string]interface{}) (SecretReader, error) {
		return init(m)
	})
}

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
