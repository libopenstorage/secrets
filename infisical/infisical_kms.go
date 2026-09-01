package infisical

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/pkg/store"
	"github.com/portworx/kvdb"
	"github.com/sirupsen/logrus"
)

const (
	// Name of the secret store
	Name = secrets.TypeInfisical
	// SiteURLKey is the base URL of the Infisical instance
	SiteURLKey = "INFISICAL_SITE_URL"
	// ClientIDKey is the Infisical Universal Auth machine identity client ID
	ClientIDKey = "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID"
	// ClientSecretKey is the Infisical Universal Auth machine identity client secret
	ClientSecretKey = "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET"
	// KMSKeyIDKey is the ID of the Infisical KMS key used for encrypt/decrypt
	KMSKeyIDKey = "INFISICAL_KMS_KEY_ID"
	// KvdbKey is used to setup Infisical KMS with kvdb for persistence
	KvdbKey            = "KMS_KVDB"
	defaultSiteURL     = "https://app.infisical.com"
	kvdbPublicBasePath = "infisical/secrets/public/"
	kvdbDataBasePath   = "infisical/secrets/data/"
)

var (
	// ErrKvdbNotProvided is returned when a valid kvdb instance is not provided
	ErrKvdbNotProvided = errors.New("a valid kvdb.Kvdb instance must be provided via the KMS_KVDB config key")
	// ErrClientIDRequired is returned when INFISICAL_UNIVERSAL_AUTH_CLIENT_ID is not set
	ErrClientIDRequired = errors.New("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID is required (config key or env var)")
	// ErrClientSecretRequired is returned when INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET is not set
	ErrClientSecretRequired = errors.New("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET is required (config key or env var)")
	// ErrKMSKeyIDRequired is returned when INFISICAL_KMS_KEY_ID is not set
	ErrKMSKeyIDRequired = errors.New("INFISICAL_KMS_KEY_ID is required (config key or env var)")
)

type infisicalKms struct {
	client kmsEncryptDecrypter
	ps     store.PersistenceStore
}

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {
	v, ok := secretConfig[KvdbKey]
	if !ok {
		return nil, ErrKvdbNotProvided
	}
	kv, ok := v.(kvdb.Kvdb)
	if !ok {
		return nil, ErrKvdbNotProvided
	}
	ps := store.NewKvdbPersistenceStore(kv, kvdbPublicBasePath, kvdbDataBasePath)

	siteURL := configString(secretConfig, SiteURLKey, defaultSiteURL)
	clientID := configString(secretConfig, ClientIDKey, "")
	clientSecret := configString(secretConfig, ClientSecretKey, "")
	kmsKeyID := configString(secretConfig, KMSKeyIDKey, "")

	if clientID == "" {
		return nil, ErrClientIDRequired
	}
	if clientSecret == "" {
		return nil, ErrClientSecretRequired
	}
	if kmsKeyID == "" {
		return nil, ErrKMSKeyIDRequired
	}

	client, err := newKmsClient(siteURL, kmsKeyID, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	if err := client.login(); err != nil {
		return nil, fmt.Errorf("infisical-kms: authentication failed: %w", err)
	}

	logrus.WithField("site", siteURL).Info("infisical-kms: authenticated successfully")

	return &infisicalKms{
		client: client,
		ps:     ps,
	}, nil
}

func (k *infisicalKms) String() string {
	return Name
}

func (k *infisicalKms) GetSecret(
	secretId string,
	keyContext map[string]string,
) (map[string]interface{}, secrets.Version, error) {
	if secretId == "" {
		return nil, secrets.NoVersion, secrets.ErrEmptySecretId
	}

	_, customData := keyContext[secrets.CustomSecretData]
	_, publicData := keyContext[secrets.PublicSecretData]
	if customData && publicData {
		return nil, secrets.NoVersion, &secrets.ErrInvalidKeyContext{
			Reason: "both CustomSecretData and PublicSecretData flags cannot be set",
		}
	}

	exists, err := k.ps.Exists(secretId)
	if err != nil {
		return nil, secrets.NoVersion, err
	}
	if !exists {
		return nil, secrets.NoVersion, secrets.ErrInvalidSecretId
	}

	ciphertextBytes, err := k.ps.GetPublic(secretId)
	if err != nil {
		return nil, secrets.NoVersion, err
	}

	secretData := make(map[string]interface{})
	if publicData {
		secretData[secretId] = ciphertextBytes
		return secretData, secrets.NoVersion, nil
	}

	plaintext, err := k.client.decrypt(string(ciphertextBytes))
	if err != nil {
		return nil, secrets.NoVersion, fmt.Errorf("infisical-kms: decryption failed: %w", err)
	}

	if customData {
		if err := json.Unmarshal([]byte(plaintext), &secretData); err != nil {
			return nil, secrets.NoVersion, fmt.Errorf("infisical-kms: failed to unmarshal decrypted data: %w", err)
		}
	} else {
		secretData[secretId] = plaintext
	}
	return secretData, secrets.NoVersion, nil
}

func (k *infisicalKms) PutSecret(
	secretId string,
	secretData map[string]interface{},
	keyContext map[string]string,
) (secrets.Version, error) {
	if secretId == "" {
		return secrets.NoVersion, secrets.ErrEmptySecretId
	}

	_, override := keyContext[secrets.OverwriteSecretDataInStore]
	_, customData := keyContext[secrets.CustomSecretData]
	_, publicData := keyContext[secrets.PublicSecretData]

	if err := secrets.KeyContextChecks(keyContext, secretData); err != nil {
		return secrets.NoVersion, err
	}

	var ciphertext []byte
	if publicData && len(secretData) > 0 {
		raw, ok := secretData[secretId]
		if !ok {
			return secrets.NoVersion, secrets.ErrInvalidSecretData
		}
		ciphertext, ok = raw.([]byte)
		if !ok {
			return secrets.NoVersion, &secrets.ErrInvalidKeyContext{
				Reason: "secret data when PublicSecretData flag is set should be of the type []byte",
			}
		}
	} else if customData && len(secretData) > 0 {
		jsonBytes, err := json.Marshal(secretData)
		if err != nil {
			return secrets.NoVersion, fmt.Errorf("infisical-kms: failed to marshal secret data: %w", err)
		}
		encrypted, err := k.client.encrypt(string(jsonBytes))
		if err != nil {
			return secrets.NoVersion, fmt.Errorf("infisical-kms: encryption failed: %w", err)
		}
		ciphertext = []byte(encrypted)
	} else {
		return secrets.NoVersion, secrets.ErrEmptySecretData
	}

	return secrets.NoVersion, k.ps.Set(secretId, ciphertext, nil, nil, override)
}

func (k *infisicalKms) DeleteSecret(
	secretId string,
	keyContext map[string]string,
) error {
	if secretId == "" {
		return secrets.ErrEmptySecretId
	}
	return k.ps.Delete(secretId)
}

func (k *infisicalKms) ListSecrets() ([]string, error) {
	return k.ps.List()
}

func (k *infisicalKms) Encrypt(
	secretId string,
	plaintTextData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (k *infisicalKms) Decrypt(
	secretId string,
	encryptedData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (k *infisicalKms) Rencrypt(
	originalSecretId string,
	newSecretId string,
	originalKeyContext map[string]string,
	newKeyContext map[string]string,
	encryptedData string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func configString(config map[string]interface{}, key, fallback string) string {
	if config != nil {
		if v, ok := config[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	if env := os.Getenv(key); env != "" {
		return env
	}
	return fallback
}

func init() {
	if err := secrets.Register(Name, New); err != nil {
		panic(err.Error())
	}
}
