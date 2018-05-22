package vault

import (
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/libopenstorage/secrets"
)

const (
	Name               = "vault"
	SecretKey          = "secret/"
	vaultAddressPrefix = "http"
)

var (
	ErrVaultTokenNotSet    = errors.New("VAULT_TOKEN not set.")
	ErrVaultAddressNotSet  = errors.New("VAULT_ADDR not set.")
	ErrInvalidVaultToken   = errors.New("VAULT_TOKEN is invalid")
	ErrInvalidSkipVerify   = errors.New("VAULT_SKIP_VERIFY is invalid")
	ErrInvalidVaultAddress = errors.New("VAULT_ADDRESS is invalid. " +
		"Should be of the form http(s)://<ip>:<port>")
)

type vaultSecrets struct {
	client   *api.Client
	endpoint string
}

// These variables are helpful in testing to stub method call from packages
var (
	newVaultClient = api.NewClient
)

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {
	// DefaultConfig uses the environment variables if present.
	config := api.DefaultConfig()

	if len(secretConfig) == 0 && config.Error != nil {
		return nil, config.Error
	}

	token := getVaultParam(secretConfig, api.EnvVaultToken)
	if token == "" {
		return nil, ErrVaultTokenNotSet
	}

	address := getVaultParam(secretConfig, api.EnvVaultAddress)
	if address == "" {
		return nil, ErrVaultAddressNotSet
	}
	// Vault fails if address is not in correct format
	if !strings.HasPrefix(address, vaultAddressPrefix) {
		return nil, ErrInvalidVaultAddress
	}
	config.Address = address

	if err := configureTLS(config, secretConfig); err != nil {
		return nil, err
	}

	client, err := newVaultClient(config)
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

func getSecretKey(secretId string) string {
	return SecretKey + secretId
}

func getVaultParam(secretConfig map[string]interface{}, name string) string {
	if tokenIntf, exists := secretConfig[name]; exists {
		return tokenIntf.(string)
	} else {
		return os.Getenv(name)
	}
}

func configureTLS(config *api.Config, secretConfig map[string]interface{}) error {
	tlsConfig := api.TLSConfig{}
	skipVerify := getVaultParam(secretConfig, api.EnvVaultInsecure)
	if skipVerify != "" {
		insecure, err := strconv.ParseBool(skipVerify)
		if err != nil {
			return ErrInvalidSkipVerify
		}
		tlsConfig.Insecure = insecure
	}

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

	return config.ConfigureTLS(&tlsConfig)
}

func init() {
	if err := secrets.Register(Name, New); err != nil {
		panic(err.Error())
	}
}
