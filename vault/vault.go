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
	VaultTokenKey      = "VAULT_TOKEN"
	VaultAddressKey    = "VAULT_ADDR"
	defaultEndpoint    = "http://127.0.0.1:8200"
	SecretKey          = "secret/"
)

var (
	ErrVaultTokenNotSet   = errors.New("VAULT_TOKEN not set.")
	ErrVaultAddressNotSet = errors.New("VAULT_ADDR not set.")
	ErrInvalidVaultToken  = errors.New("VAULT_TOKEN is invalid")
	ErrInvalidSecretId = errors.New("No Secret Data found for Secret Id")
)

var ()

type vaultSecrets struct {
	client   *api.Client
	endpoint string
}

func getSecretKey(secretId string) string {
	return SecretKey + secretId
}

func getVaultParam(secretConfig map[string]interface{}, paramName string) string {
	// Set the token for the Vault Client
	var token string
	if tokenIntf, exists := secretConfig[paramName]; exists {
		token := tokenIntf.(string)
		return token
	}
	token, exists := os.LookupEnv(VaultTokenKey)
	if !exists {
		return ""
	}
	return token
}

func getVaultClient(config *api.Config) (*api.Client, error) {
	client, err := api.NewClient(config)
	if err != nil {
		logrus.Errorf("Failed to get new client")
		return nil, err
	}
	return client, nil
}

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {
	config := api.DefaultConfig()
	// If ReadEnvironmentKey specified override the
	// default config.
	readEnvConfig := false
	if secretConfig == nil || len(secretConfig) == 0 {
		err := config.ReadEnvironment()
		if err != nil {
			return nil, err
		}
		readEnvConfig = true
	}
	client, err := getVaultClient(config)
	if err != nil {
		return nil, err
	}

	if !readEnvConfig {
		// Set Vault Token
		token := getVaultParam(secretConfig, VaultTokenKey)
		if token == "" {
			return nil, ErrVaultTokenNotSet
		}
		client.SetToken(token)
		address := getVaultParam(secretConfig, VaultAddressKey)
		if address == "" {
			return nil, ErrVaultAddressNotSet
		}
		err := client.SetAddress(address)
		if err != nil {
			return nil, err
		}

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
	secretValue, err := v.client.Logical().Read(getSecretKey(secretId))
	if err != nil {
		return nil, err
	}
	if secretValue == nil {
		return nil, ErrInvalidSecretId
	}
	return secretValue.Data, nil
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
