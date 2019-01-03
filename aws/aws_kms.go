package aws

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/libopenstorage/secrets"
	sc "github.com/libopenstorage/secrets/aws/credentials"
	"github.com/libopenstorage/secrets/pkg/store"
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
	KMSKvdbKey         = "KMS_KVDB"
	kvdbPublicBasePath = "aws_kms/secrets/public/"
	kvdbDataBasePath   = "aws_kms/secrets/data/"
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
)

type awsKmsSecrets struct {
	client *kms.KMS
	creds  *credentials.Credentials
	sess   *session.Session
	cmk    string
	asc    sc.AWSCredentials
	ps     store.PersistenceStore
}

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {
	if secretConfig == nil {
		return nil, ErrCMKNotProvided
	}
	var ps store.PersistenceStore

	v, _ := secretConfig[AwsCMKey]
	cmk, _ := v.(string)
	if cmk == "" {
		cmk = os.Getenv(AwsCMKey)
		if cmk == "" {
			return nil, ErrCMKNotProvided
		}

	}
	v, _ = secretConfig[AwsRegionKey]
	region, _ := v.(string)
	if region == "" {
		region = os.Getenv(AwsRegionKey)
		if region == "" {
			return nil, ErrAWSRegionNotProvided
		}
	}
	v, ok := secretConfig[KMSKvdbKey]
	if ok {
		kv, ok := v.(kvdb.Kvdb)
		if !ok {
			return nil, ErrInvalidKvdbProvided
		}
		ps = store.NewKvdbPersistenceStore(kv, kvdbPublicBasePath, kvdbDataBasePath)
	} else {
		ps = store.NewFilePersistenceStore()
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

	if exists, err := a.ps.Exists(secretId); err != nil {
		return nil, err
	} else if !exists {
		return nil, secrets.ErrInvalidSecretId
	}

	cipherBlob, err := a.ps.GetPublic(secretId)
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
	if a.ps.Name() == store.FilePersistenceStoreName {
		goto return_plaintext
	}

	// check if kvdbPersistenceStore has any secretData stored for this
	// secretId
	secretData, err = a.ps.GetSecretData(secretId, output.Plaintext)
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

	return a.ps.Set(
		secretId,
		output.CiphertextBlob,
		output.Plaintext,
		secretData,
	)
}

func (a *awsKmsSecrets) DeleteSecret(
	secretId string,
	keyContext map[string]string,
) error {
	return a.ps.Delete(secretId)
}

func (a *awsKmsSecrets) ListSecrets() ([]string, error) {
	return a.ps.List()
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

func init() {
	if err := secrets.Register(Name, New); err != nil {
		panic(err.Error())
	}
}
