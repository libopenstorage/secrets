package vault

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/libopenstorage/secrets"
)

const (
	Name                = secrets.TypeVault
	DefaultBackendPath  = "secret/"
	VaultBackendPathKey = "VAULT_BACKEND_PATH"
	vaultAddressPrefix  = "http"
	kvVersionKey        = "version"
	kvDataKey           = "data"
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
	client        *api.Client
	endpoint      string
	backendPath   string
	isKvBackendV2 bool
}

// These variables are helpful in testing to stub method call from packages
var (
	newVaultClient = api.NewClient
	isKvV2         = isKvBackendV2
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

	backendPath := getVaultParam(secretConfig, VaultBackendPathKey)
	if backendPath == "" {
		backendPath = DefaultBackendPath
	}

	isKvV2, err := isKvV2(client, backendPath)
	if err != nil {
		return nil, err
	}

	return &vaultSecrets{
		endpoint:      config.Address,
		client:        client,
		backendPath:   backendPath,
		isKvBackendV2: isKvV2,
	}, nil
}

func (v *vaultSecrets) String() string {
	return Name
}

func (v *vaultSecrets) keyPath(secretID, namespace string) string {
	if v.isKvBackendV2 {
		return path.Join(namespace, v.backendPath, kvDataKey, secretID)
	}
	return path.Join(namespace, v.backendPath, secretID)
}

func (v *vaultSecrets) GetSecret(
	secretID string,
	keyContext map[string]string,
) (map[string]interface{}, error) {
	secretValue, err := v.client.Logical().Read(v.keyPath(secretID, keyContext[secrets.KeyVaultNamespace]))
	if err != nil {
		return nil, err
	} else if secretValue == nil {
		return nil, secrets.ErrInvalidSecretId
	}

	if v.isKvBackendV2 {
		if data, exists := secretValue.Data[kvDataKey]; exists && data != nil {
			if data, ok := data.(map[string]interface{}); ok {
				return data, nil
			}
		}
		return nil, secrets.ErrInvalidSecretId
	} else {
		return secretValue.Data, nil
	}
}

func (v *vaultSecrets) PutSecret(
	secretID string,
	secretData map[string]interface{},
	keyContext map[string]string,
) error {
	if v.isKvBackendV2 {
		secretData = map[string]interface{}{
			kvDataKey: secretData,
		}
	}

	_, err := v.client.Logical().Write(v.keyPath(secretID, keyContext[secrets.KeyVaultNamespace]), secretData)
	return err
}

func (v *vaultSecrets) DeleteSecret(
	secretID string,
	keyContext map[string]string,
) error {
	_, err := v.client.Logical().Delete(v.keyPath(secretID, keyContext[secrets.KeyVaultNamespace]))
	return err
}

func (v *vaultSecrets) Encrypt(
	secretID string,
	plaintTextData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (v *vaultSecrets) Decrypt(
	secretID string,
	encryptedData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (v *vaultSecrets) Rencrypt(
	originalSecretID string,
	newSecretID string,
	originalKeyContext map[string]string,
	newKeyContext map[string]string,
	encryptedData string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (v *vaultSecrets) ListSecrets() ([]string, error) {
	return nil, secrets.ErrNotSupported
}

func isKvBackendV2(client *api.Client, backendPath string) (bool, error) {
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return false, err
	}

	for path, mount := range mounts {
		if path == backendPath {
			version := mount.Options[kvVersionKey]
			if version == "2" {
				return true, nil
			}
			return false, nil
		}
	}

	return false, fmt.Errorf("Secrets engine with mount path '%s' not found",
		backendPath)
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
