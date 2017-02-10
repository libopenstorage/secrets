package kvdb

import (
	"errors"

	"github.com/libopenstorage/secrets"
	kv "github.com/portworx/kvdb"
)

const (
	Name    = "kvdb"
	KvdbKey = "KVDB"
)

var (
	ErrKvdbNotSet = errors.New("KVDB Key not set")
	ErrEmptyValue = errors.New("Cannot put empty value for a key")
)

type kvdbSecrets struct {
	client kv.Kvdb
}

func New(
	endpoint string,
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {

	kvdbIntf, exists := secretConfig[KvdbKey]
	if !exists {
		return nil, ErrKvdbNotSet
	}
	kvClient := kvdbIntf.(kv.Kvdb)
	return &kvdbSecrets{
		client: kvClient,
	}, nil
}

func (v *kvdbSecrets) String() string {
	return Name
}

func (v *kvdbSecrets) GetKey(
	encryptedKeyId string,
	keyContext map[string]string,
) (map[string]interface{}, error) {
	var secretData map[string]interface{}
	_, err := v.client.GetVal("secret/" + encryptedKeyId, &secretData)
	if err != nil {
		return nil, err
	}
	return secretData, nil
}

func (v *kvdbSecrets) PutKey(
	encryptedKeyId string,
	secretData map[string]interface{},
	keyContext map[string]string,
) error {
	_, err := v.client.Put("secret/"+encryptedKeyId, &secretData, 0)
	return err
}

func (v *kvdbSecrets) Encrypt(
	encryptedKeyId string,
	plaintTextData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (v *kvdbSecrets) Decrypt(
	encryptedKeyId string,
	encryptedData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (v *kvdbSecrets) Rencrypt(
	originalEncryptedKeyId string,
	newEncryptedKeyId string,
	originalKeyContext map[string]string,
	newKeyContext map[string]string,
	encryptedData string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func init() {
	if err := secrets.Register(Name, New); err != nil {
		panic(err.Error())
	}
}
