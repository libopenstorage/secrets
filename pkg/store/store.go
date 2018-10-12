package store

type PersistenceStore interface {
	// GetPublic returns the persisted kms public info
	// of the given secretId
	GetPublic(secretId string) ([]byte, error)

	// GetSecretData returns the encrypted persisted secretData
	// if it exists for the given secretId
	GetSecretData(secretId string, plain []byte) (map[string]interface{}, error)

	// Exists checks if the given secretId already
	// exists
	Exists(secretId string) (bool, error)

	// Set persists the kms public info and encyrpted secretData if provided
	// for the given secretId
	Set(secretId string, cipher, plain []byte, secretData map[string]interface{}) error

	// Delete deletes the kms public info and the encrypted secretData if any
	// for the given secretId
	Delete(secretId string) error

	// Name returns the name of persistence store
	Name() string
}
