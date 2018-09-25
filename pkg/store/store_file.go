package store

import (
	"errors"
	"io/ioutil"
	"os"

	"github.com/libopenstorage/secrets"
)

const (
	filePersistenceStoreName = "filePersistenceStore"
)

var (
	// ErrInvalidRequest is returned when a request to get/put SecretData is made without configuring KVDB as a persistence store.
	ErrInvalidRequest = errors.New("Storing secret data is supported in Secrets only if provided with kvdb as persistence store.")
)

func NewFilePersistenceStore() PersistenceStore {
	return &filePersistenceStore{}
}

type filePersistenceStore struct{}

func (f *filePersistenceStore) GetPublic(secretId string) ([]byte, error) {
	var path string

	path = secrets.SecretPath + secretId
	return ioutil.ReadFile(path)
}

func (f *filePersistenceStore) GetSecretData(
	secretId string,
	plain []byte,
) (map[string]interface{}, error) {
	return nil, ErrInvalidRequest
}

func (f *filePersistenceStore) Set(
	secretId string,
	cipher []byte,
	plain []byte,
	secretData map[string]interface{},
) error {
	if secretData != nil {
		return ErrInvalidRequest
	}

	path := secrets.SecretPath + secretId
	os.MkdirAll(secrets.SecretPath, 0700)
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = file.Write(cipher)
	return err
}

func (f *filePersistenceStore) Exists(secretId string) (bool, error) {
	path := secrets.SecretPath + secretId
	if checkValidPath(path) {
		return true, nil
	}
	return false, nil
}

func (f *filePersistenceStore) Name() string {
	return filePersistenceStoreName
}

func checkValidPath(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false

}
