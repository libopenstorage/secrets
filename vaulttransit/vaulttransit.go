package vaulttransit

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"sync"

	"github.com/hashicorp/vault/api"
	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/pkg/store"
	"github.com/libopenstorage/secrets/vault/utils"
	"github.com/libopenstorage/secrets/vaulttransit/client/transit"
	"github.com/portworx/kvdb"
)

const (
	Name                   = secrets.TypeVaultTransit
	TransitKvdbKey         = "vaulttransit-kvdb"
	kvdbPublicBasePath     = "vaulttransit/secrets/public/"
	kvdbDataBasePath       = "vaulttransit/secrets/data/"
	defaultPxEncryptionKey = "pwx-encryption-key"

	EncryptionKey = "VAULT_ENCRYPTION_KEY"
)

type vaultSecrets struct {
	mu     sync.RWMutex
	client *api.Client

	currentNamespace string
	lockClientToken  sync.Mutex

	namespace     string
	autoAuth      bool
	config        map[string]interface{}
	ps            store.PersistenceStore
	encryptionKey string
}

// These variables are helpful in testing to stub method call from packages
var (
	newVaultClient = api.NewClient
)

func init() {
	if err := secrets.Register(Name, New); err != nil {
		panic(err.Error())
	}
}

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {
	var (
		kv kvdb.Kvdb
	)
	v, ok := secretConfig[TransitKvdbKey]
	if !ok {
		return nil, secrets.ErrInvalidKvdbProvided
	}
	kv, ok = v.(kvdb.Kvdb)
	if !ok || kv == nil {
		return nil, secrets.ErrInvalidKvdbProvided
	}

	ps := store.NewKvdbPersistenceStore(kv, kvdbPublicBasePath, kvdbDataBasePath)

	// DefaultConfig uses the environment variables if present.
	config := api.DefaultConfig()

	if len(secretConfig) == 0 && config.Error != nil {
		return nil, config.Error
	}

	address := utils.GetVaultParam(secretConfig, api.EnvVaultAddress)
	if address == "" {
		return nil, utils.ErrVaultAddressNotSet
	}
	if err := utils.IsValidAddr(address); err != nil {
		return nil, err
	}
	config.Address = address

	if err := utils.ConfigureTLS(config, secretConfig); err != nil {
		return nil, err
	}

	client, err := newVaultClient(config)
	if err != nil {
		return nil, err
	}

	namespace := utils.GetVaultParam(secretConfig, api.EnvVaultNamespace)
	if len(namespace) > 0 {
		// use a namespace as a header for setup purposes
		// later use it as a key prefix
		client.SetNamespace(namespace)
		defer client.SetNamespace("")
	}

	token, autoAuth, err := utils.Authenticate(client, secretConfig)
	if token == "" {
		utils.CloseIdleConnections(config)
		return nil, utils.ErrVaultTokenNotSet
	}
	client.SetToken(token)

	userEncryptionKey := utils.GetVaultParam(secretConfig, EncryptionKey)
	// vault namespace has been already set to the client
	encryptionKey, err := ensureEncryptionKey(client, userEncryptionKey, "")
	if err != nil {
		return nil, err
	}

	return &vaultSecrets{
		namespace:        namespace,
		currentNamespace: namespace,
		client:           client,
		autoAuth:         autoAuth,
		config:           secretConfig,
		ps:               ps,
		encryptionKey:    encryptionKey,
	}, nil
}

func (v *vaultSecrets) String() string {
	return Name
}

func (v *vaultSecrets) GetSecret(
	secretID string,
	keyContext map[string]string,
) (map[string]interface{}, error) {
	_, customData := keyContext[secrets.CustomSecretData]
	_, publicData := keyContext[secrets.PublicSecretData]
	if customData && publicData {
		return nil, &secrets.ErrInvalidKeyContext{
			Reason: "both CustomSecretData and PublicSecretData flags cannot be set",
		}
	}

	key := v.encryptionSecret(keyContext)
	dek, err := v.getDekFromStore(key.Namespace, secretID)
	if err != nil {
		return nil, err
	}

	secretData := make(map[string]interface{})
	if publicData {
		secretData[secretID] = dek
		return secretData, nil
	}

	// Use the encryption key to unwrap the DEK and get the secret passphrase
	encodedPassphrase, err := v.decrypt(key, string(dek))
	if err != nil {
		return nil, err
	}
	decodedPassphrase, err := base64.StdEncoding.DecodeString(encodedPassphrase)
	if err != nil {
		return nil, err
	}
	if customData {
		if err := json.Unmarshal(decodedPassphrase, &secretData); err != nil {
			return nil, err
		}
	} else {
		secretData[secretID] = string(decodedPassphrase)
	}
	return secretData, nil
}

func (v *vaultSecrets) PutSecret(
	secretID string,
	secretData map[string]interface{},
	keyContext map[string]string,
) error {
	var (
		cipher string
		dek    []byte
		err    error
	)

	_, override := keyContext[secrets.OverwriteSecretDataInStore]
	_, customData := keyContext[secrets.CustomSecretData]
	_, publicData := keyContext[secrets.PublicSecretData]

	key := v.encryptionSecret(keyContext)
	if err := secrets.KeyContextChecks(keyContext, secretData); err != nil {
		return err
	} else if publicData && len(secretData) > 0 {
		publicDek, ok := secretData[secretID]
		if !ok {
			return secrets.ErrInvalidSecretData
		}
		dek, ok = publicDek.([]byte)
		if !ok {
			return &secrets.ErrInvalidKeyContext{
				Reason: "secret data when PublicSecretData flag is set should be of the type []byte",
			}
		}

	} else if len(secretData) > 0 && customData {
		// Wrap the custom secret data and create a new entry in store
		// with the input secretID and the returned dek
		value, err := json.Marshal(secretData)
		if err != nil {
			return err
		}
		encodedPassphrase := base64.StdEncoding.EncodeToString(value)
		cipher, err = v.encrypt(key, encodedPassphrase)
		dek = []byte(cipher)
	} else {
		// Generate a new dek and create a new entry in store
		// with the input secretID and the generated dek
		cipher, err = v.generateDataKey(key)
		dek = []byte(cipher)
	}
	if err != nil {
		return err
	}
	return v.ps.Set(
		v.persistentStorePath(key.Namespace, secretID),
		dek,
		nil,
		nil,
		override,
	)
}

func (v *vaultSecrets) DeleteSecret(
	secretID string,
	keyContext map[string]string,
) error {
	key := v.encryptionSecret(keyContext)
	return v.ps.Delete(v.persistentStorePath(key.Namespace, secretID))
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
	return v.ps.List()
}

func (v *vaultSecrets) encrypt(key transit.SecretKey, plaintext string) (string, error) {
	// as vault supports both auto auth and namespaces at once, needs to ensure that a correct
	// vault token is used for a namespace and lock it for the next usage
	if v.autoAuth {
		v.lockClientToken.Lock()
		defer v.lockClientToken.Unlock()

		if err := v.setNamespaceToken(key.Namespace); err != nil {
			return "", err
		}
	}

	secretValue, err := v.lockedEncrypt(key, plaintext)
	if v.isTokenExpired(err) {
		if err = v.renewToken(key.Namespace); err != nil {
			return "", fmt.Errorf("failed to renew token: %s", err)
		}
		return v.lockedEncrypt(key, plaintext)
	}
	return secretValue, err
}

func (v *vaultSecrets) lockedEncrypt(key transit.SecretKey, plaintext string) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	c, err := transit.New(v.client.Logical())
	if err != nil {
		return "", err
	}
	return c.Encrypt(key, plaintext)
}

func (v *vaultSecrets) decrypt(key transit.SecretKey, ciphertext string) (string, error) {
	if v.autoAuth {
		v.lockClientToken.Lock()
		defer v.lockClientToken.Unlock()

		if err := v.setNamespaceToken(key.Namespace); err != nil {
			return "", err
		}
	}

	secretValue, err := v.lockedDecrypt(key, ciphertext)
	if v.isTokenExpired(err) {
		if err = v.renewToken(key.Namespace); err != nil {
			return "", fmt.Errorf("failed to renew token: %s", err)
		}
		return v.lockedDecrypt(key, ciphertext)
	}
	return secretValue, err
}

func (v *vaultSecrets) lockedDecrypt(key transit.SecretKey, cipher string) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	c, err := transit.New(v.client.Logical())
	if err != nil {
		return "", err
	}
	return c.Decrypt(key, cipher)
}

func (v *vaultSecrets) generateDataKey(key transit.SecretKey) (string, error) {
	if v.autoAuth {
		v.lockClientToken.Lock()
		defer v.lockClientToken.Unlock()

		if err := v.setNamespaceToken(key.Namespace); err != nil {
			return "", err
		}
	}

	secretValue, err := v.lockedGenerate(key)
	if v.isTokenExpired(err) {
		if err = v.renewToken(key.Namespace); err != nil {
			return "", fmt.Errorf("failed to renew token: %s", err)
		}
		return v.lockedGenerate(key)
	}
	return secretValue, err
}

func (v *vaultSecrets) lockedGenerate(key transit.SecretKey) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	c, err := transit.New(v.client.Logical())
	if err != nil {
		return "", err
	}

	newKey := make([]byte, 32)
	_, err = rand.Read(newKey)
	if err != nil {
		return "", err
	}

	return c.Encrypt(key, base64.StdEncoding.EncodeToString(newKey))
}

func (v *vaultSecrets) getDekFromStore(namespace, secretID string) ([]byte, error) {
	secretPath := v.persistentStorePath(namespace, secretID)
	if exists, err := v.ps.Exists(secretPath); err != nil {
		return nil, err
	} else if !exists {
		return nil, secrets.ErrInvalidSecretId
	}

	// Get the DEK (Data Encryption Key) from kvdb
	return v.ps.GetPublic(secretPath)
}

func (v *vaultSecrets) renewToken(namespace string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if len(namespace) > 0 {
		v.client.SetNamespace(namespace)
		defer v.client.SetNamespace("")
	}
	token, err := utils.GetAuthToken(v.client, v.config)
	if err != nil {
		return fmt.Errorf("get auth token for %s namespace: %s", namespace, err)
	}

	v.currentNamespace = namespace
	v.client.SetToken(token)
	return nil
}

func (v *vaultSecrets) isTokenExpired(err error) bool {
	return err != nil && v.autoAuth && strings.Contains(err.Error(), "permission denied")
}

// setNamespaceToken  is used for a multi-token support with a kubernetes auto auth setup.
//
// This allows to talk with a multiple vault namespaces (which are not sub-namespace). Create
// the same “Kubernetes Auth Role” in each of the configured namespace. For every request it
// fetches the token for that specific namespace.
func (v *vaultSecrets) setNamespaceToken(namespace string) error {
	if v.currentNamespace == namespace {
		return nil
	}

	return v.renewToken(namespace)
}

func (v *vaultSecrets) encryptionSecret(keyContext map[string]string) transit.SecretKey {
	namespace := v.namespace
	if keyContext != nil && len(keyContext[secrets.KeyVaultNamespace]) > 0 {
		namespace = keyContext[secrets.KeyVaultNamespace]
	}
	return transit.SecretKey{
		Name:      v.encryptionKey,
		Namespace: namespace,
	}
}

func (v *vaultSecrets) persistentStorePath(namespace, name string) string {
	return path.Join("vault", namespace, name)
}

// ensureEncryptionKey creates an encryption key if it's not exist.
func ensureEncryptionKey(c *api.Client, key, namespace string) (string, error) {
	transitClient, err := transit.New(c.Logical())
	if err != nil {
		return "", err
	}

	// create an encryption key if it's not provided
	if key == "" {
		_, err = transitClient.Create(transit.SecretKey{Name: defaultPxEncryptionKey, Namespace: namespace}, "")
		if err != nil {
			return "", err
		}
		return defaultPxEncryptionKey, nil
	}

	// check if the provided key exists
	_, err = transitClient.Read(transit.SecretKey{Name: key, Namespace: namespace})
	if err != nil {
		return "", err
	}
	return key, nil
}
