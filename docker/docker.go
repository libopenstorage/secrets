package docker

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/libopenstorage/secrets"
)

const (
	Name             = "docker"
	DockerSecretPath = "/run/secrets/"
)

type dockerSecrets struct{}

func getSecretKey(secretId string) string {
	return DockerSecretPath + secretId
}

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {
	return &dockerSecrets{}, nil
}

func (v *dockerSecrets) String() string {
	return Name
}

func (v *dockerSecrets) GetSecret(
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
			" associated with secretId: %v", secretId)
	}

	secretData := make(map[string]interface{})
	secretData[secretId] = cipherBlob
	return secretData, nil
}

func (v *dockerSecrets) PutSecret(
	secretId string,
	secretData map[string]interface{},
	keyContext map[string]string,
) error {
	return secrets.ErrNotSupported
}

func (v *dockerSecrets) DeleteSecret(
	secretId string,
	keyContext map[string]string,
) error {
	return secrets.ErrNotSupported
}

func (v *dockerSecrets) Encrypt(
	secretId string,
	plaintTextData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (v *dockerSecrets) Decrypt(
	secretId string,
	encryptedData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (v *dockerSecrets) Rencrypt(
	originalSecretId string,
	newSecretId string,
	originalKeyContext map[string]string,
	newKeyContext map[string]string,
	encryptedData string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (v *dockerSecrets) ListSecrets() ([]string, error) {
	return nil, secrets.ErrNotSupported
}

func init() {
	if err := secrets.Register(Name, New); err != nil {
		panic(err.Error())
	}
}
