package secrets

import (
	"errors"
)

var (
	// ErrNotSupported implementation of specific function is not supported
	ErrNotSupported = errors.New("implementation not supported")
)

// Secrets interface implemented by backed Key Management Systems (KMS)
type Secrets interface {
	// String representation of the backend KMS
	String() string

	// GetKey returns the secret data associated with the
	// supplied encrypted key Id. The secret data /plain text version of the key can be used
	// by callers to encrypt their data. It is assumed that the plain text
	// data will be destroyed by the caller once used.
	GetKey(
		encryptedKeyId string,
		keyContext map[string]string,
	) (map[string]interface{}, error)

	// PutKey will associate an encrypted key Id to its secret data
	// provided in the arguments and store it into the backend KMS
	PutKey(
		encryptedKeyId string,
		plainText map[string]interface{},
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

type BackendInit func(
	endpoint string,
	secretConfig map[string]interface{},
) (Secrets, error)
