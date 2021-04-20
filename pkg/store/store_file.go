package store

import (
	"errors"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/libopenstorage/secrets"
)

const (
	FilePersistenceStoreName = "filePersistenceStore"
)

var (
	// ErrInvalidRequest is returned when a request to get/put SecretData is made without configuring KVDB as a persistence store.
	ErrInvalidRequest = errors.New("Storing secret data is supported in Secrets only if provided with kvdb as persistence store.")
)

func NewFilePersistenceStore() *FilePersistenceStore {
	return &FilePersistenceStore{
		basepath: secrets.SecretPath,
	}
}

type FilePersistenceStore struct{
	basepath string
}

func (f *FilePersistenceStore) GetPublic(secretId string) ([]byte, error) {
	return ioutil.ReadFile(path.Join(f.basepath, normalizeID(secretId)))
}

func (f *FilePersistenceStore) GetSecretData(
	secretId string,
	plain []byte,
) (map[string]interface{}, error) {
	return nil, ErrInvalidRequest
}

func (f *FilePersistenceStore) Set(
	secretId string,
	cipher []byte,
	plain []byte,
	secretData map[string]interface{},
	override bool,
) error {
	if secretData != nil {
		return ErrInvalidRequest
	}

	spath := path.Join(f.basepath, normalizeID(secretId))
	if err := os.MkdirAll(f.basepath, 0700); err != nil {
		return err
	}
	file, err := os.Create(spath)
	if err != nil {
		return err
	}
	_, err = file.Write(cipher)
	return err
}

func (f *FilePersistenceStore) Exists(secretId string) (bool, error) {
	spath := path.Join(f.basepath, normalizeID(secretId))
	if checkValidPath(spath) {
		return true, nil
	}
	return false, nil
}

func (f *FilePersistenceStore) Delete(secretId string) error {
	spath := path.Join(f.basepath, normalizeID(secretId))
	exists, _ := f.Exists(secretId)
	if !exists {
		return nil
	}
	return os.Remove(spath)
}

func (f *FilePersistenceStore) List() ([]string, error) {
	files, err := ioutil.ReadDir(f.basepath)
	if err != nil {
		return nil, err
	}
	secretIds := []string{}
	for _, f := range files {
		secretIds = append(secretIds, f.Name())
	}
	return secretIds, nil
}

func (f *FilePersistenceStore) Name() string {
	return FilePersistenceStoreName
}

// SetBasePath is used to set a base directory for the FilePersistenceStore.
// Should be used just for testing purposed as it's out of the PersistenceStore interface.
func (f *FilePersistenceStore) SetBasePath(path string) {
	f.basepath = path
}

func checkValidPath(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false
}

func normalizeID(id string) string {
	return strings.Replace(id, "/", "!", -1)
}
