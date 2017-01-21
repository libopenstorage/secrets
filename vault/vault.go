package vault

import (
	"errors"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/hashicorp/vault/api"
	"github.com/libopenstorage/secrets"
)

const (
	Name            = "hashicorp-vault"
	ReadEnvironment = "READ_ENVIRONMENT"
	VaultToken      = "VAULT_TOKEN"
)

var (
	ErrVaultTokenNotSet  = errors.New("VAULT_TOKEN not set.")
	ErrInvalidVaultToken = errors.New("VAULT_TOKEN is invalid")
)

var (
	defaultEndpoint = "http://127.0.0.1:8200"
)

type vaultSecrets struct {
	client   *api.Client
	endpoint string
}

func New(
	endpoint string,
	secretConfig map[string]string,
) (secrets.Secrets, error) {

	config := api.DefaultConfig()
	if endpoint != "" {
		config.Address = endpoint
	}

	// If ReadEnvironment specified override the
	// default config.
	if _, exists := secretConfig[ReadEnvironment]; exists {
		err := config.ReadEnvironment()
		if err != nil {
			return nil, err
		}
	}

	client, err := api.NewClient(config)
	if err != nil {
		logrus.Errorf("Failed to get new client")
		return nil, err
	}
	// Set the token for the Vault Client
	if token, exists := secretConfig[VaultToken]; exists {
		if token == "" {
			logrus.Errorf("invalid token")
			return nil, ErrInvalidVaultToken
		}
		client.SetToken(token)
	} else {
		token, exists := os.LookupEnv(VaultToken)
		if !exists {
			logrus.Errorf("token not set")
			return nil, ErrVaultTokenNotSet
		}
		client.SetToken(token)
	}
	return &vaultSecrets{
		endpoint: config.Address,
		client:   client,
	}, nil
}

func (v *vaultSecrets) String() string {
	return Name
}

func (v *vaultSecrets) GetKey(
	encryptedKeyId string,
	keyContext map[string]string,
) (map[string]interface{}, error) {
	secret, err := v.client.Logical().Read("secret/" + encryptedKeyId)
	if err != nil {
		return nil, err
	}
	return secret.Data, nil
}

func (v *vaultSecrets) PutKey(
	encryptedKeyId string,
	plainText map[string]interface{},
	keyContext map[string]string,
) error {
	_, err := v.client.Logical().Write("secret/"+encryptedKeyId, plainText)
	return err
}

func (v *vaultSecrets) Encrypt(
	encryptedKeyId string,
	plaintTextData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (v *vaultSecrets) Decrypt(
	encryptedKeyId string,
	encryptedData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (v *vaultSecrets) Rencrypt(
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
