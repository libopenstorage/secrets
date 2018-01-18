package k8s

import (
	"fmt"

	"github.com/libopenstorage/secrets"
	"github.com/portworx/sched-ops/k8s"
)

const (
	Name            = "k8s"
	SecretNamespace = "namespace"
	SecretName      = "secret_name"
)

type k8sSecrets struct{}

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
	namespace, exists := keyContext[SecretNamespace]
	if !exists {
		return nil, fmt.Errorf("Namespace cannot be empty.")
	}

	secretName, exists := keyContext[SecretName]
	if !exists {
		return nil, fmt.Errorf("Secret name cannot be empty.")
	}

	secret, err := k8s.Instance().GetSecret(secretName, namespace)
	if err != nil {
		return nil, fmt.Errorf("Failed to get secret from [%s]. Err: %v",
			secretName, err)
	}

	cipherBlob, exists := secret.Data[secretId]
	if !exists || len(cipherBlob) == 0 {
		return nil, fmt.Errorf("Invalid secretId. Unable to read cipherBlob"+
			" associated with secretId: %v", secretId)
	}

	secretData := make(map[string]interface{})
	secretData[secretId] = fmt.Sprintf("%s", cipherBlob)
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
