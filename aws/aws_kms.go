package aws

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/libopenstorage/secrets"
	sc "github.com/libopenstorage/secrets/aws/credentials"
	"github.com/portworx/kvdb"
)

const (
	// Name of the secret store
	Name = "aws-kms"
	// AwsAccessKey corresponds to AWS credential AWS_ACCESS_KEY_ID
	AwsAccessKey = "AWS_ACCESS_KEY_ID"
	// AwsSecretAccessKey corresponds to AWS credential AWS_SECRET_ACCESS_KEY
	AwsSecretAccessKey = "AWS_SECRET_ACCESS_KEY"
	// AwsTokenKey corresponds to AWS credential AWS_SECRET_TOKEN_KEY
	AwsTokenKey = "AWS_SECRET_TOKEN_KEY"
	// AwsRegionKey defines the AWS region
	AwsRegionKey = "AWS_REGION"
	// AwsCMKey defines the KMS customer master key
	AwsCMKey = "AWS_CMK"
	// KMSKvdbKey is used to setup AWS KMS Secret Store with kvdb for persistence.
	KMSKvdbKey               = "KMS_KVDB"
	kvdbPublicBasePath       = "aws_kms/secrets/public/"
	kvdbDataBasePath         = "aws_kms/secrets/data/"
	filePersistenceStoreName = "filePersistenceStore"
	kvdbPersistenceStoreName = "kvdbPersistenceStore"
)

var (
	// ErrAwsAccessKeyNotSet is returned when AWS credential for ACCESS_KEY is not set
	ErrAwsAccessKeyNotSet = errors.New("AWS_ACCESS_KEY_ID not set.")
	// ErrAwsSecretAccessKeyNotSet is returned when AWS credential for SECRET_KEY is not set
	ErrAwsSecretAccessKeyNotSet = errors.New("AWS_SECRET_ACCESS_KEY not set.")
	// ErrInvalidSecret is returned when no secret data is found for given secret id
	ErrInvalidSecretId = errors.New("No Secret Data found for Secret Id")
	// ErrCMKNotProvided is returned when CMK is not provided.
	ErrCMKNotProvided = errors.New("AWS CMK not provided. Cannot perform KMS operations.")
	// ErrAWSRegionNotProvided is returned when region is not provided.
	ErrAWSRegionNotProvided = errors.New("AWS Region not provided. Cannot perform KMS operations.")
	// ErrInvalidKvdbProvided is returned when an incorrect KVDB implementation is provided for persistence store.
	ErrInvalidKvdbProvided = errors.New("Invalid kvdb provided. AWS KMS works in conjuction with a kvdb")
	// ErrInvalidRequest is returned when a request to get/put SecretData is made without configuring KVDB as a persistence store.
	ErrInvalidRequest = errors.New("Storing secret data is supported in AWS KMS only if provided with kvdb as persistence store.")
)

type awsKmsSecrets struct {
	client *kms.KMS
	creds  *credentials.Credentials
	sess   *session.Session
	cmk    string
	asc    sc.AWSCredentials
	ps     persistenceStore
}

type persistenceStore interface {
	// getPublic returns the persisted aws kms public info
	// of the given secretId
	getPublic(secretId string) ([]byte, error)

	// getSecretData returns the encrypted persisted secretData
	// if it exists for the given secretId
	getSecretData(secretId string, plain []byte) (map[string]interface{}, error)

	// exists checks if the given secretId already
	// exists
	exists(secretId string) (bool, error)

	// set persists the aws kms public info and encyrpted secretData if provided
	// for the given secretId
	set(secretId string, cipher, plain []byte, secretData map[string]interface{}) error

	// name returns the name of persistence store
	name() string
}

type filePersistenceStore struct{}

func (f *filePersistenceStore) getPublic(secretId string) ([]byte, error) {
	var path string

	path = secrets.SecretPath + secretId
	return ioutil.ReadFile(path)
}

func (f *filePersistenceStore) getSecretData(
	secretId string,
	plain []byte,
) (map[string]interface{}, error) {
	return nil, ErrInvalidRequest
}

func (f *filePersistenceStore) set(
	secretId string,
	cipher []byte,
	plain []byte,
	secretData map[string]interface{},
) error {
	if secretData != nil {
		return ErrInvalidRequest
	}

	path := secrets.SecretPath + secretId
	os.MkdirAll(secrets.SecretPath, 0700)
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = file.Write(cipher)
	return err
}

func (f *filePersistenceStore) exists(secretId string) (bool, error) {
	path := secrets.SecretPath + secretId
	if checkValidPath(path) {
		return true, nil
	}
	return false, nil
}

func (f *filePersistenceStore) name() string {
	return filePersistenceStoreName
}

type kvdbPersistenceStore struct {
	kv kvdb.Kvdb
}

func (k *kvdbPersistenceStore) getPublic(secretId string) ([]byte, error) {
	key := kvdbPublicBasePath + secretId

	// Get the public cipher
	kvp, err := k.kv.Get(key)
	if err != nil {
		return nil, err
	}
	return kvp.Value, nil
}

func (k *kvdbPersistenceStore) getSecretData(
	secretId string,
	plain []byte,
) (map[string]interface{}, error) {
	dataKey := kvdbDataBasePath + secretId

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

func (k *kvdbPersistenceStore) set(
	secretId string,
	cipher []byte,
	plain []byte,
	secretData map[string]interface{},
) error {
	key := kvdbPublicBasePath + secretId
	// Save the public cipher
	_, err := k.kv.Put(key, cipher, 0)
	if err != nil {
		return err
	}
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

	dataKey := kvdbDataBasePath + secretId
	_, err = k.kv.Put(dataKey, encodedEncryptedData, 0)
	if err != nil {
		return err
	}
	return nil
}

func (k *kvdbPersistenceStore) exists(secretId string) (bool, error) {
	key := kvdbPublicBasePath + secretId
	_, err := k.kv.Get(key)
	if err == nil {
		return true, nil
	} else if err == kvdb.ErrNotFound {
		return false, nil
	}
	return false, err
}

func (k *kvdbPersistenceStore) name() string {
	return kvdbPersistenceStoreName
}

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {
	if secretConfig == nil {
		return nil, ErrCMKNotProvided
	}
	var ps persistenceStore

	v, _ := secretConfig[AwsCMKey]
	cmk, _ := v.(string)
	if cmk == "" {
		return nil, ErrCMKNotProvided
	}
	v, _ = secretConfig[AwsRegionKey]
	region, _ := v.(string)
	if region == "" {
		return nil, ErrAWSRegionNotProvided
	}
	v, ok := secretConfig[KMSKvdbKey]
	if ok {
		kv, ok := v.(kvdb.Kvdb)
		if !ok {
			return nil, ErrInvalidKvdbProvided
		}
		ps = &kvdbPersistenceStore{kv}
	} else {
		ps = &filePersistenceStore{}
	}

	id, secret, token, err := authKeys(secretConfig)
	if err != nil {
		return nil, err
	}
	asc, err := sc.NewAWSCredentials(id, secret, token)
	if err != nil {
		return nil, fmt.Errorf("Failed to get credentials: %v", err)
	}
	creds, err := asc.Get()
	if err != nil {
		return nil, fmt.Errorf("Failed to get credentials: %v", err)
	}
	config := &aws.Config{
		Credentials: creds,
		Region:      &region,
	}
	sess := session.New(config)
	kmsClient := kms.New(sess)
	return &awsKmsSecrets{
		client: kmsClient,
		sess:   sess,
		creds:  creds,
		cmk:    cmk,
		asc:    asc,
		ps:     ps,
	}, nil
}

func (a *awsKmsSecrets) String() string {
	return Name
}

func (a *awsKmsSecrets) GetSecret(
	secretId string,
	keyContext map[string]string,
) (map[string]interface{}, error) {
	var (
		cipherBlob, decodedCipherBlob []byte
		secretData                    map[string]interface{}
	)

	if exists, err := a.ps.exists(secretId); err != nil {
		return nil, err
	} else if !exists {
		return nil, secrets.ErrInvalidSecretId
	}

	cipherBlob, err := a.ps.getPublic(secretId)
	if err != nil {
		return nil, err
	}
	// AWS KMS api requires the cipherBlob to be in base64 decoded format.
	// Check if it is encoded and decode if required.
	decodedCipherBlob, err = base64.StdEncoding.DecodeString(string(cipherBlob))
	if err != nil {
		decodedCipherBlob = cipherBlob
	}
	input := &kms.DecryptInput{
		EncryptionContext: getAWSKeyContext(keyContext),
		CiphertextBlob:    decodedCipherBlob,
	}
	output, err := a.client.Decrypt(input)
	if err != nil {
		return nil, err
	}

	// filePersistenceStore does not support storing of secretData
	if a.ps.name() == filePersistenceStoreName {
		goto return_plaintext
	}

	// check if kvdbPersistenceStore has any secretData stored for this
	// secretId
	secretData, err = a.ps.getSecretData(secretId, output.Plaintext)
	if err != nil {
		return nil, err
	} else if secretData != nil {
		return secretData, nil
	}

return_plaintext:
	secretData = make(map[string]interface{})
	secretData[secretId] = string(output.Plaintext)
	return secretData, nil
}

func (a *awsKmsSecrets) PutSecret(
	secretId string,
	secretData map[string]interface{},
	keyContext map[string]string,
) error {

	if exists, err := a.ps.exists(secretId); exists && err == nil {
		return secrets.ErrSecretExists
	} else if err != nil {
		return err
	}

	keySpec := "AES_256"
	input := &kms.GenerateDataKeyInput{
		KeyId:             &a.cmk,
		EncryptionContext: getAWSKeyContext(keyContext),
		KeySpec:           &keySpec,
	}

	output, err := a.client.GenerateDataKey(input)
	if err != nil {
		return err
	}

	return a.ps.set(
		secretId,
		output.CiphertextBlob,
		output.Plaintext,
		secretData,
	)
}

func (a *awsKmsSecrets) Encrypt(
	secretId string,
	plaintTextData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (a *awsKmsSecrets) Decrypt(
	secretId string,
	encryptedData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (a *awsKmsSecrets) Rencrypt(
	originalSecretId string,
	newSecretId string,
	originalKeyContext map[string]string,
	newKeyContext map[string]string,
	encryptedData string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func authKeys(params map[string]interface{}) (string, string, string, error) {
	accessKey, err := getAuthKey(AwsAccessKey, params)
	if err != nil {
		return "", "", "", err
	}

	secretKey, err := getAuthKey(AwsSecretAccessKey, params)
	if err != nil {
		return "", "", "", err
	}

	secretToken, err := getAuthKey(AwsTokenKey, params)
	if err != nil {
		return "", "", "", err
	}

	return accessKey, secretKey, secretToken, nil
}

func getAuthKey(key string, params map[string]interface{}) (string, error) {
	val, ok := params[key]
	valueStr := ""
	if ok {
		valueStr, ok = val.(string)
		if !ok {
			return "", fmt.Errorf("Authentication error. Invalid value for %v", key)
		}
	}
	return valueStr, nil
}

func getAWSKeyContext(keyContext map[string]string) map[string]*string {
	if keyContext == nil {
		return nil
	}
	encKeyContext := make(map[string]*string)
	for k, v := range keyContext {
		encKeyContext[k] = &v
	}
	return encKeyContext
}

func checkValidPath(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false

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

func init() {
	if err := secrets.Register(Name, New); err != nil {
		panic(err.Error())
	}
}
