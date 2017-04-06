package secrets

import (
	"errors"
)

var (
	// ErrNotSupported returned when implementation of specific function is not supported
	ErrNotSupported = errors.New("implementation not supported")
	// ErrNotAuthenticated returned when not authenticated with secrets endpoint
	ErrNotAuthenticated  = errors.New("Not authenticated with the secrets endpoint")
	// ErrInvalidSecretId returned when no secret data is found associated with the id
	ErrInvalidSecretId = errors.New("No Secret Data found for Secret Id")
	// ErrSecretExists returned when a secret for the given secret id already exists
	ErrSecretExists = errors.New("Secret Id already exists")
)

const (
	SecretPath = "/var/lib/osd/secrets/"
)

// Secrets interface implemented by backed Key Management Systems (KMS)
type Secrets interface {
	// String representation of the backend KMS
	String() string

	// GetSecret returns the secret data associated with the
	// supplied secretId. The secret data / plain text  can be used
	// by callers to encrypt their data. It is assumed that the plain text
	// data will be destroyed by the caller once used.
	GetSecret(
		secretId string,
		keyContext map[string]string,
	) (map[string]interface{}, error)

	// PutSecret will associate an secretId to its secret data
	// provided in the arguments and store it into the secret backend
	PutSecret(
		secretId string,
		plainText map[string]interface{},
		keyContext map[string]string,
	) error

	// Encrypt encrypts the supplied plain text data using the given key.
	// The API would fetch the plain text key, encrypt the data with it.
	// The plain text key will not be stored anywhere else and would be
	// deleted from memory.
	Encrypt(
		secretId string,
		plaintTextData string,
		keyContext map[string]string,
	) (string, error)

	// Decrypt decrypts the supplied encrypted  data using the given key.
	// The API would fetch the plain text key, decrypt the data with it.
	// The plain text key will not be stored anywhere else and would be
	// deleted from memory.
	Decrypt(
		secretId string,
		encryptedData string,
		keyContext map[string]string,
	) (string, error)

	// Reencrypt decrypts the data with the previous key and re-encrypts it
	// with the new key..
	Rencrypt(
		originalSecretId string,
		newSecretId string,
		originalKeyContext map[string]string,
		newKeyContext map[string]string,
		encryptedData string,
	) (string, error)
}

type BackendInit func(
	secretConfig map[string]interface{},
) (Secrets, error)
