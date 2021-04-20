package transit

import (
	"fmt"
	"path"

	"github.com/hashicorp/vault/api"
)

// VaultLogical represents methods from the vault.Logical client used by VaultTransit.
type VaultLogical interface {
	Read(path string) (*api.Secret, error)
	Write(path string, data map[string]interface{}) (*api.Secret, error)
	Delete(path string) (*api.Secret, error)
}

// SecretKey contains parameters used to identify the vault secret.
type SecretKey struct {
	// Name is a secret name, used to build a url (example, /transit/keys/:name).
	Name string
	// Namespace is a vault namespace, optional.
	Namespace string
}

// New returns a new instance of the VaultTransit.
func New(client VaultLogical) (*VaultTransit, error) {
	if client == nil {
		return nil, fmt.Errorf("vault client should be set")
	}
	return &VaultTransit{
		client: client,
	}, nil
}

// VaultTransit partially implements vault transit API.
type VaultTransit struct {
	client VaultLogical
}

// Create creates a new named encryption key of the specified type.
// https://www.vaultproject.io/api/secret/transit#create-key
//
func (v VaultTransit) Create(key SecretKey, keyType string) (*api.Secret, error) {
	params := map[string]interface{}{}
	if len(keyType) > 0 {
		params["type"] = keyType
	}
	return v.client.Write(v.keysPath(key), params)
}

// Read returns information about a named encryption key.
// https://www.vaultproject.io/api/secret/transit#read-key
//
func (v VaultTransit) Read(key SecretKey) (*api.Secret, error) {
	s, err := v.client.Read(v.keysPath(key))
	if err != nil {
		return nil, err
	}
	if s == nil || s.Data == nil {
		return nil, fmt.Errorf("no secret data found for %s secret", v.keysPath(key))
	}
	return s, nil
}

// Encrypt encrypts the provided plain text using the named key.
// All plaintext data must be base64-encoded.
// It supports the create (create an encryption key if it's not exist) and update policy capabilities.
// https://www.vaultproject.io/api/secret/transit#encrypt-data
//
func (v VaultTransit) Encrypt(key SecretKey, plaintext string) (string, error) {
	vaultSecret, err := v.client.Write(v.encryptPath(key), map[string]interface{}{
		"plaintext": plaintext,
	})
	if err != nil {
		return "", err
	}

	if vaultSecret.Data == nil {
		return "", fmt.Errorf("secret data is impty")
	}
	cipher, ok := vaultSecret.Data["ciphertext"].(string)
	if !ok {
		return "", fmt.Errorf("ciphertext is not set")
	}

	return cipher, nil
}

// Decrypt decrypts the provided cipher text using the named key.
// The output is a base64-encoded plain text.
// https://www.vaultproject.io/api/secret/transit#decrypt-data
//
func (v VaultTransit) Decrypt(key SecretKey, ciphertext string) (string, error) {
	vaultSecret, err := v.client.Write(v.decryptPath(key), map[string]interface{}{
		"ciphertext": ciphertext,
	})
	if err != nil {
		return "", err
	}

	if vaultSecret.Data == nil {
		return "", fmt.Errorf("secret data is impty")
	}
	plaintext, ok := vaultSecret.Data["plaintext"].(string)
	if !ok {
		return "", fmt.Errorf("plainttext is not set")
	}

	return plaintext, nil
}

// GenerateDataKey generates a new high-entropy key and the value encrypted with the named key.
// Returns a cipher text.
// It create an encryption key if it's not exist.
// https://www.vaultproject.io/api/secret/transit#generate-data-key
//
func (v VaultTransit) GenerateDataKey(key SecretKey) (string, error) {
	if _, err := v.client.Write(v.keysPath(key), nil); err != nil {
		return "", err
	}

	vaultSecret, err := v.client.Write(v.generateDataKeyPath(key), nil)
	if err != nil {
		return "", err
	}

	if vaultSecret.Data == nil {
		return "", fmt.Errorf("secret data is impty")
	}
	ciphertext, ok := vaultSecret.Data["ciphertext"].(string)
	if !ok {
		return "", fmt.Errorf("ciphertext is not set")
	}

	return ciphertext, nil
}

// Delete deletes a named encryption key.
// https://www.vaultproject.io/api/secret/transit#delete-key
//
func (v VaultTransit) Delete(key SecretKey) error {
	_, err := v.client.Write(
		path.Join(v.keysPath(key), "config"),
		map[string]interface{}{"deletion_allowed": true},
	)
	if err != nil {
		return err
	}

	_, err = v.client.Delete(v.keysPath(key))
	return err
}

func (v VaultTransit) generateDataKeyPath(secretKey SecretKey) string {
	return path.Join(secretKey.Namespace, "transit/datakey/wrapped", secretKey.Name)
}

func (v VaultTransit) encryptPath(secretKey SecretKey) string {
	return path.Join(secretKey.Namespace, "transit/encrypt", secretKey.Name)
}

func (v VaultTransit) decryptPath(secretKey SecretKey) string {
	return path.Join(secretKey.Namespace, "transit/decrypt", secretKey.Name)
}

func (v VaultTransit) keysPath(secretKey SecretKey) string {
	return path.Join(secretKey.Namespace, "transit/keys", secretKey.Name)
}
