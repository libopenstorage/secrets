package vault

import (
	"errors"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/hashicorp/vault/api"
	"github.com/libopenstorage/secrets"
)

const (
	Name               = "hashicorp-vault"
	ReadEnvironmentKey = "READ_ENVIRONMENT"
	VaultTokenKey      = "VAULT_TOKEN"
	defaultEndpoint    = "http://127.0.0.1:8200"
	SecretKey          = "secret/"
)

var (
	ErrVaultTokenNotSet  = errors.New("VAULT_TOKEN not set.")
	ErrInvalidVaultToken = errors.New("VAULT_TOKEN is invalid")
)

var ()

type vaultSecrets struct {
	client   *api.Client
	endpoint string
}

func getSecretKey(secretId string) string {
	return SecretKey + secretId
}

func New(
	endpoint string,
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {

	config := api.DefaultConfig()
	if endpoint != "" {
		config.Address = endpoint
	}

	// If ReadEnvironmentKey specified override the
	// default config.
	if _, exists := secretConfig[ReadEnvironmentKey]; exists {
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
	if tokenIntf, exists := secretConfig[VaultTokenKey]; exists {
		token = tokenIntf.(string)
		if token == "" {
			logrus.Errorf("invalid token")
			return nil, ErrInvalidVaultToken
		}
		client.SetToken(token)
	} else {
		token, exists := os.LookupEnv(VaultTokenKey)
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

func (v *vaultSecrets) GetSecret(
	secretId string,
	keyContext map[string]string,
) (map[string]interface{}, error) {
	secret, err := v.client.Logical().Read(getSecretKey(secretId) + encryptedKeyId)
	if err != nil {
		return nil, err
	}
	return secret.Data, nil
}

func (v *vaultSecrets) PutSecret(
	secretId string,
	secretData map[string]interface{},
	keyContext map[string]string,
) error {
	_, err := v.client.Logical().Write(getSecretKey(secretId), secretData)
	return err
}

func (v *vaultSecrets) Encrypt(
	secretId string,
	plaintTextData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (v *vaultSecrets) Decrypt(
	secretId string,
	encryptedData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (v *vaultSecrets) Rencrypt(
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
