package dcos

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/libopenstorage/secrets"
	api "github.com/portworx/dcos-secrets"
)

// Keys for the config to initialize the DC/OS secrets client
const (
	KeyUsername   = "username"
	KeyPassword   = "password"
	KeyCACertFile = "cacert"
	KeyDcosURL    = "dcos_url"
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

type dcosSecrets struct {
	client api.DCOSSecrets
}

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {
	clientConfig := getClientConfig(secretConfig)
	token, err := getAuthToken(clientConfig, secretConfig)
	if err != nil {
		return nil, err
	}

	clientConfig.ACSToken = token
	client, err := api.NewClient(clientConfig)
	if err != nil {
		return nil, err
	}

	return &dcosSecrets{
		client: client,
	}, nil
}

func getClientConfig(secretConfig map[string]interface{}) api.Config {
	config := api.NewDefaultConfig()

	url := getConfigParam(secretConfig, KeyDcosURL)
	if url != "" {
		config.ClusterURL = url
	}

	caCertFile := getConfigParam(secretConfig, KeyCACertFile)
	if caCertFile != "" {
		config.CACertFile = caCertFile
	} else {
		config.Insecure = true
	}

	return config
}

func getAuthToken(clientConfig api.Config, secretConfig map[string]interface{}) (string, error) {
	username := getConfigParam(secretConfig, KeyUsername)
	if username == "" {
		return "", ErrMissingCredentials
	}
	password := getConfigParam(secretConfig, KeyPassword)
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
) (map[string]interface{}, error) {
	secret, err := d.client.GetSecret(keyContext[KeySecretStore], secretPath)
	if err != nil {
		return nil, err
	}

	if secret == nil {
		return nil, secrets.ErrInvalidSecretId
	}

	var result map[string]interface{}

	err = json.Unmarshal([]byte(secret.Value), &result)
	if err != nil {
		result = make(map[string]interface{})
		result[secretPath] = secret.Value
	}
	return result, nil
}

func (d *dcosSecrets) PutSecret(
	secretPath string,
	secretData map[string]interface{},
	keyContext map[string]string,
) error {
	if len(secretData) == 0 {
		return secrets.ErrEmptySecretData
	}

	value, err := json.Marshal(secretData)
	if err != nil {
		return err
	}

	secret := &api.Secret{
		Value: string(value),
	}
	return d.client.CreateOrUpdateSecret(keyContext[KeySecretStore], secretPath, secret)
}

func (d *dcosSecrets) DeleteSecret(
	secretPath string,
	keyContext map[string]string,
) error {
	return d.client.DeleteSecret(keyContext[KeySecretStore], secretPath)
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
	return ""
}

func init() {
	if err := secrets.Register(Name, New); err != nil {
		panic(err.Error())
	}
}
