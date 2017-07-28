package vault

import (
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/hashicorp/vault/api"
	"github.com/libopenstorage/secrets"
)

const (
	Name               = "vault"
	defaultEndpoint    = "http://127.0.0.1:8200"
	SecretKey          = "secret/"
	VaultTokenKey      = "VAULT_TOKEN"
	vaultAddressPrefix = "http"
)

var (
	ErrVaultTokenNotSet   = errors.New("VAULT_TOKEN not set.")
	ErrVaultAddressNotSet = errors.New("VAULT_ADDR not set.")
	ErrInvalidVaultToken  = errors.New("VAULT_TOKEN is invalid")
	ErrInvalidSkipVerify  = errors.New("VAULT_SKIP_VERIFY is invalid")
	ErrInvalidVaultAddress = errors.New("VAULT_ADDRESS is invalid."+
		" Should be of the form http(s)://<ip>:<port>")
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
		// An extra check before we call vault's read env config
		if os.Getenv(api.EnvVaultAddress) == "" {
			return nil, ErrVaultAddressNotSet
		}
		err := config.ReadEnvironment()
		if err != nil {
			return nil, err
		}
		readEnvConfig = true
	}
	var token string
	if !readEnvConfig {
		// Vault Token
		token = getVaultParam(secretConfig, VaultTokenKey)
		if token == "" {
			return nil, ErrVaultTokenNotSet
		}
		// Vault Address
		address := getVaultParam(secretConfig, api.EnvVaultAddress)
		if address == "" {
			return nil, ErrVaultAddressNotSet
		}

		config.Address = address
		// Get TLS Settings
		tlsConfig := api.TLSConfig{}
		skipVerify := getVaultParam(secretConfig, api.EnvVaultInsecure)
		if skipVerify != "" {
			insecure, err := strconv.ParseBool(skipVerify)
			if err != nil {
				return nil, ErrInvalidSkipVerify
			}
			tlsConfig.Insecure = insecure
		}
		// Get Cert Paths
		cacert := getVaultParam(secretConfig, api.EnvVaultCACert)
		tlsConfig.CACert = cacert
		capath := getVaultParam(secretConfig, api.EnvVaultCAPath)
		tlsConfig.CAPath = capath
		clientcert := getVaultParam(secretConfig, api.EnvVaultClientCert)
		tlsConfig.ClientCert = clientcert
		clientkey := getVaultParam(secretConfig, api.EnvVaultClientKey)
		tlsConfig.ClientKey = clientkey
		tlsserverName := getVaultParam(secretConfig, api.EnvVaultTLSServerName)
		tlsConfig.TLSServerName = tlsserverName
		err := config.ConfigureTLS(&tlsConfig)
		if err != nil {
			return nil, err
		}
	}
	// Vault craps out if address is not in correct format
	if !strings.HasPrefix(config.Address, vaultAddressPrefix) {
		return nil, ErrInvalidVaultAddress
	}

	client, err := getVaultClient(config)
	if err != nil {
		return nil, err
	}

	client.SetToken(token)
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
		return nil, secrets.ErrInvalidSecretId
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
