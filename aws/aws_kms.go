package aws

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/libopenstorage/secrets"
	sc "github.com/libopenstorage/secrets/aws/credentials"
)

const (
	Name                    = "aws-kms"
	awsAccessKey            = "AWS_ACCESS_KEY_ID"
	awsSecretAccessKey      = "AWS_SECRET_ACCESS_KEY"
	awsTokenKey             = "AWS_SECRET_TOKEN_KEY"
	awsSharedCredentialsKey = "AWS_SHARED_CREDENTIALS_FILE"
	awsRegionKey            = "AWS_REGION"
	awsCMKey                = "AWS_CMK"
	SecretKey               = "secret/"
)

var (
	ErrAwsAccessKeyNotSet       = errors.New("AWS_ACCESS_KEY_ID not set.")
	ErrAwsSecretAccessKeyNotSet = errors.New("AWS_SECRET_ACCESS_KEY not set.")
	ErrInvalidSecretId          = errors.New("No Secret Data found for Secret Id")
	ErrCMKNotProvided           = errors.New("AWS CMK not provided. Cannot perform KMS operations.")
	ErrAWSRegionNotProvided     = errors.New("AWS Region not provided. Cannot perform KMS operations.")
)

type awsKmsSecrets struct {
	client *kms.KMS
	creds  *credentials.Credentials
	sess   *session.Session
	cmk    string
	asc    sc.AWSCredentials
}

func getSecretKey(secretId string) string {
	return SecretKey + secretId
}

func authKeys(params map[string]interface{}) (string, string, string, error) {
	accessKey, err := getAuthKey(awsAccessKey, params)
	if err != nil {
		return "", "", err
	}

	secretKey, err := getAuthKey(awsSecretAccessKey, params)
	if err != nil {
		return "", "", err
	}

	secretToken, err := getAuthKey(awsTokenKey, params)
	if err != nil {
		return "", "", err
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

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {
	if secretConfig == nil {
		return nil, ErrCMKNotProvided
	}

	v, _ := secretConfig[awsCMKey]
	cmk, _ := v.(string)
	if cmk == "" {
		return nil, ErrCMKNotProvided
	}
	v, _ = secretConfig[awsRegionKey]
	region, _ := v.(string)
	if region == "" {
		return nil, ErrAWSRegionNotProvided
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
		path        string
		secretIdKey string
	)
	if checkValidPath(secretId) {
		path = secretId
		secretIdKey = getIdFromPath(path)
	} else {
		path = secrets.SecretPath + secretId
		secretIdKey = secretId
	}

	cipherBlob := []byte{}
	_, err := os.Stat(path)

	if err == nil || os.IsExist(err) {
		cipherBlob, err = ioutil.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("Invalid secretId. Unable to read cipherBlob"+
				" associated with secretId: %v", err)
		}
	}
	// EncryptedDataKey passed in as an argument
	if len(cipherBlob) == 0 {
		cipherBlob = []byte(secretId)
	}
	input := &kms.DecryptInput{
		EncryptionContext: getAWSKeyContext(keyContext),
		CiphertextBlob:    cipherBlob,
	}
	output, err := a.client.Decrypt(input)
	if err != nil {
		return nil, err
	}
	secretData := make(map[string]interface{})
	secretData[secretIdKey] = output.Plaintext
	return secretData, nil
}

func (a *awsKmsSecrets) PutSecret(
	secretId string,
	secretData map[string]interface{},
	keyContext map[string]string,
) error {
	if checkValidPath(secretId) {
		return secrets.ErrSecretExists
	}
	if secretData != nil {
		return fmt.Errorf("AWS KMS does not support storing of custom secret data")
	}
	keySpec := "AES_256"
	input := &kms.GenerateDataKeyInput{
		KeyId:             &a.cmk,
		EncryptionContext: getAWSKeyContext(keyContext),
		KeySpec:           &keySpec,
	}
	path := secrets.SecretPath + secretId
	if checkValidPath(path) {
		return secrets.ErrSecretExists
	}

	output, err := a.client.GenerateDataKey(input)
	if err != nil {
		return err
	}

	os.MkdirAll(secrets.SecretPath, 0700)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = f.Write(output.CiphertextBlob)
	return err
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

func init() {
	if err := secrets.Register(Name, New); err != nil {
		panic(err.Error())
	}
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

func getIdFromPath(path string) string {
	path = strings.TrimSuffix(path, "/")
	tokens := strings.Split(path, "/")
	if len(tokens) == 0 {
		return path
	}
	return tokens[len(tokens)-1]
}
