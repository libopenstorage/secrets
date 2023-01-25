package dcos

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/libopenstorage/secrets"
	api "github.com/portworx/dcos-secrets"
)

// Keys for the config to initialize the DC/OS secrets client
const (
	EnvSecretsUsername   = "DCOS_SECRETS_USERNAME"
	EnvSecretsPassword   = "DCOS_SECRETS_PASSWORD"
	EnvSecretsCACertFile = "DCOS_SECRETS_CA_CERT_FILE"
	EnvDCOSClusterURL    = "DCOS_CLUSTER_URL"
)

const (
	// Name name of the secret provider
	Name = secrets.TypeDCOS
	// KeySecretStore key used to set the secret store
	KeySecretStore = "secret_store"
)

var (
	// ErrMissingCredendtials returned when either of the creds are missing
	ErrMissingCredentials = errors.New("Username and password are required to authenticate")
)

var (
	// This is used for testing so that in tests we can override the newClient function
	// to have custom behavior.
	newClient = newSecretsClient
)

type dcosSecrets struct {
	client api.DCOSSecrets
}

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {
	client, err := newClient(secretConfig)
	if err != nil {
		return nil, err
	}
	return &dcosSecrets{
		client: client,
	}, nil
}

func newSecretsClient(
	secretConfig map[string]interface{},
) (api.DCOSSecrets, error) {
	clientConfig := getClientConfig(secretConfig)
	token, err := getAuthToken(clientConfig, secretConfig)
	if err != nil {
		return nil, err
	}
	clientConfig.ACSToken = token
	return api.NewClient(clientConfig)
}

func getClientConfig(secretConfig map[string]interface{}) api.Config {
	config := api.NewDefaultConfig()

	url := getConfigParam(secretConfig, EnvDCOSClusterURL)
	if url != "" {
		config.ClusterURL = url
	}

	caCertFile := getConfigParam(secretConfig, EnvSecretsCACertFile)
	if caCertFile != "" {
		config.CACertFile = caCertFile
	} else {
		config.Insecure = true
	}

	return config
}

func getAuthToken(clientConfig api.Config, secretConfig map[string]interface{}) (string, error) {
	username := getConfigParam(secretConfig, EnvSecretsUsername)
	if username == "" {
		return "", ErrMissingCredentials
	}
	password := getConfigParam(secretConfig, EnvSecretsPassword)
	if password == "" {
		return "", ErrMissingCredentials
	}

	tokenConfig := api.DefaultTokenConfig()
	tokenConfig.Username = username
	tokenConfig.Password = password
	tokenConfig.Config = clientConfig

	token, err := api.GenerateACSToken(tokenConfig)
	if err != nil {
		return "", err
	} else if token == "" {
		return "", fmt.Errorf("Error generating authentication token")
	}
	return token, nil
}

func (d *dcosSecrets) String() string {
	return Name
}

func (d *dcosSecrets) GetSecret(
	secretPath string,
	keyContext map[string]string,
) (map[string]interface{}, secrets.Version, error) {
	secret, err := d.client.GetSecret(keyContext[KeySecretStore], secretPath)
	if isTokenExpired(err) {
		client, err := newClient(nil)
		if err != nil {
			return nil, secrets.NoVersion, err
		}
		d.client = client
		secret, err = d.client.GetSecret(keyContext[KeySecretStore], secretPath)
		if err != nil {
			return nil, secrets.NoVersion, err
		}
	} else if err != nil {
		return nil, secrets.NoVersion, err
	}

	if secret == nil {
		return nil, secrets.NoVersion, secrets.ErrInvalidSecretId
	}

	var result map[string]interface{}

	err = json.Unmarshal([]byte(secret.Value), &result)
	if err != nil {
		result = make(map[string]interface{})
		result[secretPath] = secret.Value
	}
	return result, secrets.NoVersion, nil
}

func (d *dcosSecrets) PutSecret(
	secretPath string,
	secretData map[string]interface{},
	keyContext map[string]string,
) (secrets.Version, error) {
	if len(secretData) == 0 {
		return secrets.NoVersion, secrets.ErrEmptySecretData
	}

	value, err := json.Marshal(secretData)
	if err != nil {
		return secrets.NoVersion, err
	}

	secret := &api.Secret{
		Value: string(value),
	}
	err = d.client.CreateOrUpdateSecret(keyContext[KeySecretStore], secretPath, secret)
	if isTokenExpired(err) {
		client, err := newClient(nil)
		if err != nil {
			return secrets.NoVersion, err
		}
		d.client = client
		return secrets.NoVersion, d.client.CreateOrUpdateSecret(keyContext[KeySecretStore], secretPath, secret)
	}
	return secrets.NoVersion, err
}

func (d *dcosSecrets) DeleteSecret(
	secretPath string,
	keyContext map[string]string,
) error {
	err := d.client.DeleteSecret(keyContext[KeySecretStore], secretPath)
	if isTokenExpired(err) {
		client, err := newClient(nil)
		if err != nil {
			return err
		}
		d.client = client
		return d.client.DeleteSecret(keyContext[KeySecretStore], secretPath)
	}
	return err
}

func (d *dcosSecrets) Encrypt(
	secretID string,
	plainTextData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (d *dcosSecrets) Decrypt(
	secretID string,
	encryptedData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (d *dcosSecrets) Rencrypt(
	originalSecretID string,
	newSecretID string,
	originalKeyContext map[string]string,
	newKeyContext map[string]string,
	encryptedData string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (d *dcosSecrets) ListSecrets() ([]string, error) {
	return nil, secrets.ErrNotSupported
}

func getConfigParam(secretConfig map[string]interface{}, key string) string {
	if valueInterface, exists := secretConfig[key]; exists {
		if value, ok := valueInterface.(string); ok {
			return value
		}
	}
	return os.Getenv(key)
}

func isTokenExpired(err error) bool {
	return err != nil && strings.Contains(err.Error(), "Unauthorized")
}

func init() {
	if err := secrets.Register(Name, New); err != nil {
		panic(err.Error())
	}
}
