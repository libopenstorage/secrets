package gcloud

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/pkg/store"
	"github.com/portworx/kvdb"
	"golang.org/x/oauth2/google"
	cloudkms "google.golang.org/api/cloudkms/v1"
)

const (
	// Name of the secret store
	Name = "gcloud-kms"
	// GoogleKmsResourceKey corresponds to the asymmetric resource id
	GoogleKmsResourceKey = "GOOGLE_KMS_RESOURCE_ID"
	// KMSKvdbkey is used to setup Google KMS Secret Store with kvdb for persistence
	KMSKvdbKey         = "KMS_KVDB"
	kvdbPublicBasePath = "google_cloud/secrets/public/"
	kvdbDataBasePath   = "google_cloud/secrets/data/"
)

var (
	// ErrInvalidKvdbProvided is returned when an incorrect KVDB implementation is provided for persistence store.
	ErrInvalidKvdbProvided = errors.New("Invalid kvdb provided. Google Cloud KMS works in conjuction with a kvdb")
	// ErrGoogleKmsResourceKeyNotProvided is returned when GOOGLE_KMS_RESOURCE_ID is not provided
	ErrGoogleKmsResourceKeyNotProvided = errors.New("Google KMS asymmetric key resource ID is not provided")
)

type gcloudKmsSecrets struct {
	kms           *cloudkms.Service
	publicKeyPath string
	ps            store.PersistenceStore
}

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {
	v, ok := secretConfig[KMSKvdbKey]
	if !ok {
		return nil, ErrInvalidKvdbProvided
	}

	kv, ok := v.(kvdb.Kvdb)
	if !ok {
		return nil, ErrInvalidKvdbProvided
	}
	ps := store.NewKvdbPersistenceStore(kv, kvdbPublicBasePath, kvdbDataBasePath)

	v, _ = secretConfig[GoogleKmsResourceKey]
	publicKeyPath, _ := v.(string)
	if publicKeyPath == "" {
		publicKeyPath = os.Getenv(GoogleKmsResourceKey)
		if publicKeyPath == "" {
			return nil, ErrGoogleKmsResourceKeyNotProvided
		}
	}
	ctx := context.Background()
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	cloudkmsService, err := cloudkms.New(client)
	if err != nil {
		return nil, err
	}
	return &gcloudKmsSecrets{
		kms:           cloudkmsService,
		publicKeyPath: publicKeyPath,
		ps:            ps,
	}, nil
}

func (g *gcloudKmsSecrets) String() string {
	return Name
}

func (g *gcloudKmsSecrets) GetSecret(
	secretId string,
	keyContext map[string]string,
) (map[string]interface{}, error) {

	_, customData := keyContext[secrets.CustomSecretData]
	_, publicData := keyContext[secrets.PublicSecretData]
	if customData && publicData {
		return nil, &secrets.ErrInvalidKeyContext{
			Reason: "both CustomSecretData and PublicSecretData flags cannot be set",
		}
	}

	dek, err := g.getDekFromStore(secretId)
	if err != nil {
		return nil, err
	}

	secretData := make(map[string]interface{})
	if publicData {
		secretData[secretId] = dek
		return secretData, nil
	}

	ctx := context.Background()
	decryptRequest := &cloudkms.AsymmetricDecryptRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(dek),
	}
	response, err := g.kms.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
		AsymmetricDecrypt(g.publicKeyPath, decryptRequest).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("decryption request failed: %v", err.Error())
	}
	plaintext, err := base64.StdEncoding.DecodeString(response.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode decryted string: %v", err)
	}

	if customData {
		if err := json.Unmarshal(plaintext, &secretData); err != nil {
			return nil, err
		}
	} else {
		secretData[secretId] = string(plaintext)
	}
	return secretData, nil
}

func (g *gcloudKmsSecrets) PutSecret(
	secretId string,
	secretData map[string]interface{},
	keyContext map[string]string,
) error {

	var (
		dek []byte
	)
	_, override := keyContext[secrets.OverwriteSecretDataInStore]
	_, customData := keyContext[secrets.CustomSecretData]
	_, publicData := keyContext[secrets.PublicSecretData]

	if err := secrets.KeyContextChecks(keyContext, secretData); err != nil {
		return err
	} else if publicData && len(secretData) > 0 {
		publicDek, ok := secretData[secretId]
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
		plainTextByte, err := json.Marshal(secretData)
		if err != nil {
			return err
		}
		publicKey, err := g.getAsymmetricPublicKey()
		if err != nil {
			return err
		}
		// encrypt the plain text
		rsaKey := publicKey.(*rsa.PublicKey)
		dek, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaKey, plainTextByte, nil)
		if err != nil {
			return fmt.Errorf("encryption for secret failed: %v", err)
		}

	} else {
		return secrets.ErrEmptySecretData
	}

	return g.ps.Set(
		secretId,
		dek,
		nil,
		nil,
		override,
	)
}

func (g *gcloudKmsSecrets) DeleteSecret(
	secretId string,
	keyContext map[string]string,
) error {
	return g.ps.Delete(secretId)
}

func (g *gcloudKmsSecrets) ListSecrets() ([]string, error) {
	return g.ps.List()
}

func (g *gcloudKmsSecrets) Encrypt(
	secretId string,
	plaintTextData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (g *gcloudKmsSecrets) Decrypt(
	secretId string,
	encryptedData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (g *gcloudKmsSecrets) Rencrypt(
	originalSecretId string,
	newSecretId string,
	originalKeyContext map[string]string,
	newKeyContext map[string]string,
	encryptedData string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

// getAsymmetricPublicKey retrieves the public key from a saved asymmetric key pair on KMS.
func (g *gcloudKmsSecrets) getAsymmetricPublicKey() (interface{}, error) {
	ctx := context.Background()
	response, err := g.kms.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.GetPublicKey(g.publicKeyPath).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key: %v", err.Error())
	}
	keyBytes := []byte(response.Pem)
	block, _ := pem.Decode(keyBytes)
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}
	return publicKey, nil
}

func (g *gcloudKmsSecrets) getDekFromStore(secretId string) ([]byte, error) {
	if exists, err := g.ps.Exists(secretId); err != nil {
		return nil, err
	} else if !exists {
		return nil, secrets.ErrInvalidSecretId
	}

	return g.ps.GetPublic(secretId)
}
