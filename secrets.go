package secrets

import (
	"errors"
	"github.com/Sirupsen/logrus"
)

var (
	// ErrNotSupported implementation of specific function is not supported
	ErrNotSupported = errors.New("implementation not supported")
)

// Secrets interface implemented by backed Key Management Systems (KMS)
type Secrets interface {
	// String representation of the backend KMS
	String() string

	// GetKey returns the plain text version of the supplied encrypted key.
	// The plain text key   can be used by callers to encrypt their data.
	// It is assumed that the plain text key will be destroyed by the
	// caller once used.
	GetKey(
		encryptedKeyId string,
		keyContext map[string]string,
	) (string, error)

	// PutKey will write a new key pair of <encryped_key, plaintext_key>
	// into the backend KMS.
	PutKey(
		encryptedKey string,
		plainTextKey string,
		keyContext map[string]string,
	) error

	// Encrypt encrypts the supplied plain text data using the given key.
	// The API would fetch the plain text key, encrypt the data with it.
	// The plain text key will not be stored anywhere else and would be
	// deleted from memory.
	Encrypt(
		encryptedKeyId string,
		plaintTextData string,
		keyContext map[string]string,
	) (string, error)

	// Decrypt decrypts the supplied encrypted  data using the given key.
	// The API would fetch the plain text key, decrypt the data with it.
	// The plain text key will not be stored anywhere else and would be
	// deleted from memory.
	Decrypt(
		encryptedKeyId string,
		encryptedData string,
		keyContext map[string]string,
	) (string, error)

	// Reencrypt decrypts the data with the previous key and re-encrypts it
	// with the new key..
	Rencrypt(
		originalEncryptedKeyId string,
		newEncryptedKeyId string,
		originalKeyContext map[string]string,
		newKeyContext map[string]string,
		encryptedData string,
	) (string, error)
}

type SecretBackendInit func(
	name string,
	secretConfig map[string]string,
) (Secrets, error)
