package aws_secrets_manager

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/libopenstorage/secrets/aws/utils"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/libopenstorage/secrets"
	sc "github.com/libopenstorage/secrets/aws/credentials"
	"github.com/libopenstorage/secrets/pkg/store"
)

const (
	// Name of the secret store
	Name = secrets.TypeAWSSecretsManager
	// SecretRetentionPeriodInDaysKey is passed through context to the DeleteSecret API
	SecretRetentionPeriodInDaysKey = "secret-retention-period-in-days"
)

type awsSecretsMgr struct {
	creds *credentials.Credentials
	sess  *session.Session
	cmk   string
	asc   sc.AWSCredentials
	ps    store.PersistenceStore
	scm   *secretsmanager.SecretsManager
}

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {
	if secretConfig == nil {
		return nil, utils.ErrAWSCredsNotProvided
	}

	v, _ := secretConfig[utils.AwsRegionKey]
	region, _ := v.(string)
	if region == "" {
		region = os.Getenv(utils.AwsRegionKey)
		if region == "" {
			return nil, utils.ErrAWSRegionNotProvided
		}
	}

	id, secret, token, err := utils.AuthKeys(secretConfig)
	if err != nil {
		return nil, err
	}
	asc, err := sc.NewAWSCredentials(id, secret, token, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create aws credentials instance: %v", err)
	}
	creds, err := asc.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %v", err)
	}
	config := &aws.Config{
		Credentials: creds,
		Region:      &region,
	}
	sess, err := session.NewSession(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create a session: %v", err)
	}
	scm := secretsmanager.New(sess)
	return &awsSecretsMgr{
		scm:   scm,
		sess:  sess,
		creds: creds,
		asc:   asc,
	}, nil
}

func (a *awsSecretsMgr) String() string {
	return Name
}

func (a *awsSecretsMgr) GetSecret(
	secretId string,
	keyContext map[string]string,
) (map[string]interface{}, secrets.Version, error) {
	secretValueOutput, err := a.scm.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretId),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == secretsmanager.ErrCodeResourceNotFoundException {
				return nil, secrets.NoVersion, secrets.ErrInvalidSecretId
			} else if aerr.Code() == secretsmanager.ErrCodeInvalidRequestException &&
				strings.Contains(aerr.Error(), "marked for deletion") {
				return nil, secrets.NoVersion, secrets.ErrInvalidSecretId
			}
		}
		return nil, secrets.NoVersion, &secrets.ErrProviderInternal{Reason: err.Error(), Provider: Name}
	}
	if secretValueOutput.SecretString == nil || len(*secretValueOutput.SecretString) <= 0 {
		return nil, secrets.NoVersion, secrets.ErrEmptySecretData
	}
	secretOut := make(map[string]interface{})
	if err := json.Unmarshal([]byte(*secretValueOutput.SecretString), &secretOut); err != nil {
		return nil, secrets.NoVersion, fmt.Errorf("failed to unmarshal secret data: %v", err)
	}
	if secretValueOutput.VersionId == nil {
		return nil, secrets.NoVersion, fmt.Errorf("invalid version returned by aws")
	}
	return secretOut, secrets.Version(*secretValueOutput.VersionId), nil
}

func (a *awsSecretsMgr) PutSecret(
	secretId string,
	secretData map[string]interface{},
	keyContext map[string]string,
) (secrets.Version, error) {
	// Marshal the secret data
	secretBytes, err := json.Marshal(secretData)
	if err != nil {
		return secrets.NoVersion, fmt.Errorf("failed to marshal secret data: %v", err)
	}
	// Check if there already exists a key.
	_, err = a.scm.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretId),
	})
	if err == nil {
		// Update the existing secret
		secretValueOutput, putErr := a.scm.PutSecretValue(&secretsmanager.PutSecretValueInput{
			SecretId:     aws.String(secretId),
			SecretString: aws.String(string(secretBytes)),
		})
		if putErr != nil {
			return secrets.NoVersion, &secrets.ErrProviderInternal{Reason: putErr.Error(), Provider: Name}
		}
		if secretValueOutput.VersionId == nil {
			return secrets.NoVersion, &secrets.ErrProviderInternal{Reason: "invalid version returned by aws", Provider: Name}
		}
		return secrets.Version(*secretValueOutput.VersionId), nil
	} else {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == secretsmanager.ErrCodeResourceNotFoundException {
				// Create a new secret
				secretValueOutput, createErr := a.scm.CreateSecret(&secretsmanager.CreateSecretInput{
					SecretString: aws.String(string(secretBytes)),
					Name:         aws.String(secretId),
				})
				if createErr != nil {
					return secrets.NoVersion, &secrets.ErrProviderInternal{Reason: createErr.Error(), Provider: Name}
				}
				if secretValueOutput.VersionId == nil {
					return secrets.NoVersion, &secrets.ErrProviderInternal{Reason: "invalid version returned by aws", Provider: Name}
				}
				return secrets.Version(*secretValueOutput.VersionId), nil
			} // return the aws error
		} // return the non-aws error
	}
	// Gets, Puts & Creates have failed
	return secrets.NoVersion, &secrets.ErrProviderInternal{Reason: err.Error(), Provider: Name}
}

func (a *awsSecretsMgr) DeleteSecret(
	secretId string,
	keyContext map[string]string,
) error {
	retentionPeriod, ok := keyContext[SecretRetentionPeriodInDaysKey]
	if !ok {
		_, err := a.scm.DeleteSecret(&secretsmanager.DeleteSecretInput{
			// By default, aws keeps the secret for 30 days
			// Delete immediately
			ForceDeleteWithoutRecovery: aws.Bool(true),
			SecretId:                   aws.String(secretId),
		})
		if err != nil {
			return &secrets.ErrProviderInternal{Reason: err.Error(), Provider: Name}
		}
		return nil
	}

	retentionPeriodInDays, err := strconv.Atoi(retentionPeriod)
	if err != nil {
		return &secrets.ErrProviderInternal{
			Reason:   "invalid retention period, value must be a number between 7 and 30",
			Provider: Name,
		}
	}
	_, err = a.scm.DeleteSecret(&secretsmanager.DeleteSecretInput{
		SecretId:             aws.String(secretId),
		RecoveryWindowInDays: aws.Int64(int64(retentionPeriodInDays)),
	})
	if err != nil {
		return &secrets.ErrProviderInternal{Reason: err.Error(), Provider: Name}
	}
	return nil
}

func (a *awsSecretsMgr) ListSecrets() ([]string, error) {
	return nil, secrets.ErrNotSupported
}

func (a *awsSecretsMgr) Encrypt(
	secretId string,
	plaintTextData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (a *awsSecretsMgr) Decrypt(
	secretId string,
	encryptedData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (a *awsSecretsMgr) Rencrypt(
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
