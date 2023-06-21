package aws_kms

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/libopenstorage/secrets/aws/utils"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/libopenstorage/secrets"
	sc "github.com/libopenstorage/secrets/aws/credentials"
	"github.com/libopenstorage/secrets/pkg/store"
	"github.com/portworx/kvdb"
)

const (
	// Name of the secret store
	Name = secrets.TypeAWSKMS
	// AwsCMKey defines the KMS customer master key
	AwsCMKey = "AWS_CMK"
	// KMSKvdbKey is used to setup AWS KMS Secret Store with kvdb for persistence.
	KMSKvdbKey         = "KMS_KVDB"
	kvdbPublicBasePath = "aws_kms/secrets/public/"
	kvdbDataBasePath   = "aws_kms/secrets/data/"
)

type awsKmsSecrets struct {
	client *kms.Client
	creds  *aws.Credentials
	cmk    string
	asc    sc.AWSCredentials
	ps     store.PersistenceStore
}

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {
	if secretConfig == nil {
		return nil, utils.ErrCMKNotProvided
	}
	var ps store.PersistenceStore

	v, _ := secretConfig[AwsCMKey]
	cmk, _ := v.(string)
	if cmk == "" {
		cmk = os.Getenv(AwsCMKey)
		if cmk == "" {
			return nil, utils.ErrCMKNotProvided
		}

	}
	v, _ = secretConfig[utils.AwsRegionKey]
	region, _ := v.(string)
	if region == "" {
		region = os.Getenv(utils.AwsRegionKey)
		if region == "" {
			return nil, utils.ErrAWSRegionNotProvided
		}
	}
	v, ok := secretConfig[KMSKvdbKey]
	if ok {
		kv, ok := v.(kvdb.Kvdb)
		if !ok {
			return nil, utils.ErrInvalidKvdbProvided
		}
		ps = store.NewKvdbPersistenceStore(kv, kvdbPublicBasePath, kvdbDataBasePath)
	} else {
		ps = store.NewFilePersistenceStore()
	}

	id, secret, token, err := utils.AuthKeys(secretConfig)
	if err != nil {
		return nil, err
	}
	asc, err := sc.NewAWSCredentials(id, secret, token, true)
	if err != nil {
		return nil, fmt.Errorf("Failed to get credentials: %v", err)
	}
	creds, err := asc.Get()
	if err != nil {
		return nil, fmt.Errorf("Failed to get credentials: %v", err)
	}
	credProv := credentialsToProvider(creds)
	config := aws.Config{
		Credentials: credProv,
		Region:      region,
	}

	kmsClient := kms.NewFromConfig(config)

	return &awsKmsSecrets{
		client: kmsClient,
		creds:  creds,
		cmk:    cmk,
		asc:    asc,
		ps:     ps,
	}, nil
}

func credentialsToProvider(creds *aws.Credentials) aws.CredentialsProvider {
	return credentials.StaticCredentialsProvider{
		Value: aws.Credentials{
			AccessKeyID:     creds.AccessKeyID,
			SecretAccessKey: creds.SecretAccessKey,
			SessionToken:    creds.SessionToken,
			Source:          creds.Source,
		},
	}
}

func (a *awsKmsSecrets) String() string {
	return Name
}

func (a *awsKmsSecrets) GetSecret(
	secretId string,
	keyContext map[string]string,
) (map[string]interface{}, secrets.Version, error) {
	var (
		cipherBlob, decodedCipherBlob []byte
		secretData                    map[string]interface{}
	)

	_, publicData := keyContext[secrets.PublicSecretData]

	if exists, err := a.ps.Exists(secretId); err != nil {
		return nil, secrets.NoVersion, err
	} else if !exists {
		return nil, secrets.NoVersion, secrets.ErrInvalidSecretId
	}

	cipherBlob, err := a.ps.GetPublic(secretId)
	if err != nil {
		return nil, secrets.NoVersion, err
	}

	if publicData {
		secretData := make(map[string]interface{})
		secretData[secretId] = cipherBlob
		return secretData, secrets.NoVersion, nil
	}

	// AWS KMS api requires the cipherBlob to be in base64 decoded format.
	// Check if it is encoded and decode if required.
	decodedCipherBlob, err = base64.StdEncoding.DecodeString(string(cipherBlob))
	if err != nil {
		decodedCipherBlob = cipherBlob
	}
	input := &kms.DecryptInput{
		EncryptionContext: keyContext,
		CiphertextBlob:    decodedCipherBlob,
	}
	output, err := a.client.Decrypt(context.TODO(), input)
	if err != nil {
		return nil, secrets.NoVersion, err
	}

	// filePersistenceStore does not support storing of secretData
	if a.ps.Name() == store.FilePersistenceStoreName {
		goto return_plaintext
	}

	// check if kvdbPersistenceStore has any secretData stored for this
	// secretId
	secretData, err = a.ps.GetSecretData(secretId, output.Plaintext)
	if err != nil {
		return nil, secrets.NoVersion, err
	} else if secretData != nil {
		return secretData, secrets.NoVersion, nil
	}

return_plaintext:
	secretData = make(map[string]interface{})
	secretData[secretId] = string(output.Plaintext)
	return secretData, secrets.NoVersion, nil
}

func (a *awsKmsSecrets) PutSecret(
	secretId string,
	secretData map[string]interface{},
	keyContext map[string]string,
) (secrets.Version, error) {

	_, override := keyContext[secrets.OverwriteSecretDataInStore]
	_, publicData := keyContext[secrets.PublicSecretData]

	if publicData && len(secretData) == 0 {
		return secrets.NoVersion, &secrets.ErrInvalidKeyContext{
			Reason: "secret data needs to be provided when PublicSecretData flag is set",
		}
	} else if publicData && len(secretData) > 0 {
		publicDek, ok := secretData[secretId]
		if !ok {
			return secrets.NoVersion, secrets.ErrInvalidSecretData
		}
		dek, ok := publicDek.([]byte)
		if !ok {
			return secrets.NoVersion, &secrets.ErrInvalidKeyContext{
				Reason: "secret data when PublicSecretData flag is set should be of the type []byte",
			}
		}
		return secrets.NoVersion, a.ps.Set(
			secretId,
			dek, // only store the public cipher text in store
			nil, // do not use the plain text to encrypt the secret data
			nil, // no secret data to encrypt
			override,
		)
	}

	keySpec := "AES_256"
	input := &kms.GenerateDataKeyInput{
		KeyId:             &a.cmk,
		EncryptionContext: keyContext,
		KeySpec:           types.DataKeySpec(keySpec),
	}

	output, err := a.client.GenerateDataKey(context.TODO(), input)
	if err != nil {
		return secrets.NoVersion, err
	}

	return secrets.NoVersion, a.ps.Set(
		secretId,
		output.CiphertextBlob, // store the public cipher text in store
		output.Plaintext,      // use the plain text to encrypt secret data if provided
		secretData,            // encrypt this secret data and store it
		override,
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

func getAWSKeyContext(keyContext map[string]string) map[string]*string {
	if keyContext == nil {
		return nil
	}
	encKeyContext := make(map[string]*string)
	for k, v := range keyContext {
		if k == secrets.CustomSecretData ||
			k == secrets.PublicSecretData ||
			k == secrets.OverwriteSecretDataInStore {
			// Do not add our keys to aws context
			continue
		}
		encKeyContext[k] = &v
	}
	return encKeyContext
}

func init() {
	if err := secrets.Register(Name, New); err != nil {
		panic(err.Error())
	}
}
