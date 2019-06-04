package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"

	"github.com/portworx/kvdb"
)

const (
	KvdbPersistenceStoreName = "kvdbPersistenceStore"
)

func NewKvdbPersistenceStore(
	kv kvdb.Kvdb,
	publicBasePath string,
	dataBasePath string,
) PersistenceStore {
	return &kvdbPersistenceStore{
		kv,
		publicBasePath,
		dataBasePath,
	}
}

type kvdbPersistenceStore struct {
	kv                 kvdb.Kvdb
	kvdbPublicBasePath string
	kvdbDataBasePath   string
}

func (k *kvdbPersistenceStore) GetPublic(secretId string) ([]byte, error) {
	key := k.kvdbPublicBasePath + secretId

	// Get the public cipher
	kvp, err := k.kv.Get(key)
	if err != nil {
		return nil, err
	}
	decodedCipherBlob, err := base64.StdEncoding.DecodeString(string(kvp.Value))
	if err != nil {
		return nil, err
	}
	return decodedCipherBlob, nil
}

func (k *kvdbPersistenceStore) GetSecretData(
	secretId string,
	plain []byte,
) (map[string]interface{}, error) {
	dataKey := k.kvdbDataBasePath + secretId

	// Check if there exists a key
	kvp, err := k.kv.Get(dataKey)
	if err == kvdb.ErrNotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	// base4 decode the encrypted data stored in kvdb.
	decodedEncryptedData, err := base64.StdEncoding.DecodeString(string(kvp.Value))
	if err != nil {
		return nil, err
	}

	// decrypt the encrypted data.
	decryptedData, err := decrypt(decodedEncryptedData, plain)
	if err != nil {
		return nil, fmt.Errorf("Unable to decrypt secret data: %v", err)
	}

	secretData := make(map[string]interface{})
	// unmarshal the data into a map
	err = json.Unmarshal(decryptedData, &secretData)
	if err != nil {
		return nil, fmt.Errorf("Unable to unmarshal decrypted secret data: %v", err)
	}
	return secretData, nil
}

func (k *kvdbPersistenceStore) Set(
	secretId string,
	cipher []byte,
	plain []byte,
	secretData map[string]interface{},
	override bool,
) error {
	key := k.kvdbPublicBasePath + secretId
	encodeCipher := base64.StdEncoding.EncodeToString(cipher)
	// Save the public cipher
	_, err := k.kv.Create(key, encodeCipher, 0)
	if err != nil {
		if err == kvdb.ErrExist && !override {
			return fmt.Errorf("secret with name %v already exists", secretId)
		} else if err == kvdb.ErrExist && override {
			_, err = k.kv.Put(key, encodeCipher, 0)
			if err != nil {
				return err
			}
		}
		return err
	}

	// If no secretData is provided no need to store it.
	if secretData == nil {
		return nil
	}

	// marshal the input map into a byte array
	data, err := json.Marshal(&secretData)
	if err != nil {
		return err
	}

	// Use the plaintext cipher to encrypt the
	// marshalled secretData
	encryptedData, err := encrypt(data, plain)
	if err != nil {
		return err
	}

	// encode the encrypted data and store it in kvdb
	encodedEncryptedData := base64.StdEncoding.EncodeToString(encryptedData)

	dataKey := k.kvdbDataBasePath + secretId
	_, err = k.kv.Create(dataKey, encodedEncryptedData, 0)
	if err != nil {
		if err == kvdb.ErrExist && !override {
			return fmt.Errorf("secret with name %v already exists.", secretId)
		} else if err == kvdb.ErrExist && override {
			_, err = k.kv.Put(dataKey, encodedEncryptedData, 0)
			if err != nil {
				return err
			}
		}
		return err
	}
	return nil
}

func (k *kvdbPersistenceStore) Exists(secretId string) (bool, error) {
	key := k.kvdbPublicBasePath + secretId
	_, err := k.kv.Get(key)
	if err == nil {
		return true, nil
	} else if err == kvdb.ErrNotFound {
		return false, nil
	}
	return false, err
}

func (k *kvdbPersistenceStore) Delete(secretId string) error {
	key := k.kvdbPublicBasePath + secretId
	_, err := k.kv.Delete(key)
	if err == nil || err == kvdb.ErrNotFound {
		return nil
	}
	return err
}

func (k *kvdbPersistenceStore) List() ([]string, error) {
	kvps, err := k.kv.Enumerate(k.kvdbPublicBasePath)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, kvp := range kvps {
		_, id := path.Split(kvp.Key)
		ids = append(ids, id)
	}
	return ids, nil
}

func (k *kvdbPersistenceStore) Name() string {
	return KvdbPersistenceStoreName
}

// encrypt encrypts the data using the passphrase
func encrypt(data, passphrase []byte) ([]byte, error) {
	gcm, err := getGCM(passphrase)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// decrypt decrypts the cipherData using the passphrase
func decrypt(cipherData, passphrase []byte) ([]byte, error) {
	gcm, err := getGCM(passphrase)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()

	if len(cipherData) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, cipherData := cipherData[:nonceSize], cipherData[nonceSize:]
	decryptedData, err := gcm.Open(cipherData[:0], nonce, cipherData, nil)
	return decryptedData, err
}

// getGCM returns golang's AEAD, a cipher mode for AES encryption
// using Galois/Counter Mode (GCM)
func getGCM(passphrase []byte) (cipher.AEAD, error) {
	c, err := aes.NewCipher(passphrase)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(c)
}
