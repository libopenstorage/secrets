package k8s

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/libopenstorage/secrets"
)

const (
	Name          = "k8s"
	K8sSecretPath = "/etc/secrets/"
)

type k8sSecrets struct{}

func getSecretKey(secretId string) string {
	return K8sSecretPath + secretId
}

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {
	return &k8sSecrets{}, nil
}

func (s *k8sSecrets) String() string {
	return Name
}

func (s *k8sSecrets) GetSecret(
	secretId string,
	keyContext map[string]string,
) (map[string]interface{}, error) {
	cipherBlob := []byte{}
	secretPath := getSecretKey(secretId)
	_, err := os.Stat(secretPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, secrets.ErrInvalidSecretId
		}
		return nil, err
	}
	cipherBlob, err = ioutil.ReadFile(secretPath)
	if err != nil || len(cipherBlob) == 0 {
		return nil, fmt.Errorf("Invalid secretId. Unable to read cipherBlob"+
			" associated with secretId: %v", err)
	}

	secretData := make(map[string]interface{})
	secretData[secretId] = cipherBlob
	return secretData, nil
}

func (s *k8sSecrets) PutSecret(
	secretId string,
	secretData map[string]interface{},
	keyContext map[string]string,
) error {
	return secrets.ErrNotSupported
}

func (s *k8sSecrets) Encrypt(
	secretId string,
	plaintTextData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (s *k8sSecrets) Decrypt(
	secretId string,
	encryptedData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (s *k8sSecrets) Rencrypt(
	originalSecretId string,
	newSecretId string,
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
