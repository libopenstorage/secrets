package aws_secrets_manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go"
	"github.com/libopenstorage/secrets"
	sc "github.com/libopenstorage/secrets/aws/credentials"
	"github.com/libopenstorage/secrets/aws/utils"
)

const (
	// Name of the secret store
	Name = secrets.TypeAWSSecretsManager
	// SecretRetentionPeriodInDaysKey is passed through context to the DeleteSecret API
	SecretRetentionPeriodInDaysKey = "secret-retention-period-in-days"
)

// AWSSecretsMgr is backend for secrets.SecretStore.
type AWSSecretsMgr struct {
	scm *secretsmanager.Client
}

// New creates new instance of AWSSecretsMgr with provided configuration.
func New(
	secretConfig map[string]interface{},
) (*AWSSecretsMgr, error) {
	if secretConfig == nil {
		return nil, utils.ErrAWSCredsNotProvided
	}

	awsConfig, ok := secretConfig[utils.AwsConfigKey]
	if ok {
		awsConfig, ok := awsConfig.(aws.Config)
		if !ok {
			return nil, utils.ErrAWSConfigWrongType
		}

		return NewFromAWSConfig(awsConfig)
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
	credProv := CredentialsToProvider(creds)
	config := aws.Config{
		Credentials: credProv,
		Region:      region,
	}

	return NewFromAWSConfig(config)
}

// credentialsToProvider converts a aws.Credential object to a aws.CredentialProvider object
func CredentialsToProvider(creds *aws.Credentials) aws.CredentialsProvider {
	return credentials.StaticCredentialsProvider{
		Value: aws.Credentials{
			AccessKeyID:     creds.AccessKeyID,
			SecretAccessKey: creds.SecretAccessKey,
			SessionToken:    creds.SessionToken,
			Source:          creds.Source,
		},
	}
}

// NewFromAWSConfig creates new instance of AWSSecretsMgr with provided AWS configuration (aws.Config).
func NewFromAWSConfig(config aws.Config) (*AWSSecretsMgr, error) {
	scm := secretsmanager.NewFromConfig(config)
	return &AWSSecretsMgr{
		scm: scm,
	}, nil
}

func (a *AWSSecretsMgr) String() string {
	return Name
}

func (a *AWSSecretsMgr) Get(_ context.Context, key secrets.SecretKey) (map[string]interface{}, error) {
	secretID := createSecretId(key)
	secret, _, err := a.get(secretID)
	return secret, err
}

func (a *AWSSecretsMgr) Set(_ context.Context, key secrets.SecretKey, secret map[string]interface{}) error {
	secretID := createSecretId(key)
	_, err := a.put(secretID, secret)
	return err
}

func (a *AWSSecretsMgr) Delete(_ context.Context, key secrets.SecretKey) error {
	secretID := createSecretId(key)
	return a.delete(secretID, 0)
}

func (a *AWSSecretsMgr) GetSecret(
	secretID string,
	_ map[string]string,
) (map[string]interface{}, secrets.Version, error) {
	return a.get(secretID)
}

func (a *AWSSecretsMgr) PutSecret(
	secretID string,
	secretData map[string]interface{},
	_ map[string]string,
) (secrets.Version, error) {
	return a.put(secretID, secretData)
}

func (a *AWSSecretsMgr) DeleteSecret(
	secretID string,
	keyContext map[string]string,
) error {
	retentionPeriodInDays := 0
	retentionPeriod, ok := keyContext[SecretRetentionPeriodInDaysKey]
	if ok {
		var err error
		retentionPeriodInDays, err = strconv.Atoi(retentionPeriod)
		if err != nil {
			return &secrets.ErrProviderInternal{
				Reason:   "invalid retention period, value must be a number between 7 and 30",
				Provider: Name,
			}
		}
	}

	return a.delete(secretID, int64(retentionPeriodInDays))
}

func (a *AWSSecretsMgr) ListSecrets() ([]string, error) {
	return nil, secrets.ErrNotSupported
}

func (a *AWSSecretsMgr) Encrypt(
	_ string,
	_ string,
	_ map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (a *AWSSecretsMgr) Decrypt(
	_ string,
	_ string,
	_ map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (a *AWSSecretsMgr) Rencrypt(
	_ string,
	_ string,
	_ map[string]string,
	_ map[string]string,
	_ string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (a *AWSSecretsMgr) get(secretID string) (map[string]interface{}, secrets.Version, error) {
	secretValueOutput, err := a.scm.GetSecretValue(context.TODO(), &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			// aerr, ok := err.(awserr.Error); ok {
			if apiErr.ErrorCode() == "ResourceNotFoundException" {
				return nil, secrets.NoVersion, secrets.ErrInvalidSecretId
			} else if apiErr.ErrorCode() == "InvalidRequestException" &&
				strings.Contains(apiErr.ErrorCode(), "Marked for deletion") {
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
		secretOut = make(map[string]interface{})
		secretOut[secretID] = *secretValueOutput.SecretString

	}
	if secretValueOutput.VersionId == nil {
		return nil, secrets.NoVersion, fmt.Errorf("invalid version returned by aws")
	}
	return secretOut, secrets.Version(*secretValueOutput.VersionId), nil
}

func (a *AWSSecretsMgr) put(
	secretID string,
	secretData map[string]interface{},
) (secrets.Version, error) {
	// Marshal the secret data
	secretBytes, err := json.Marshal(secretData)
	if err != nil {
		return secrets.NoVersion, fmt.Errorf("failed to marshal secret data: %v", err)
	}
	// Check if there already exists a key.
	_, err = a.scm.GetSecretValue(context.TODO(), &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	})
	if err == nil {
		// Update the existing secret
		secretValueOutput, putErr := a.scm.PutSecretValue(context.TODO(), &secretsmanager.PutSecretValueInput{
			SecretId:     aws.String(secretID),
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
		// if aerr, ok := err.(awserr.Error); ok {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			if apiErr.ErrorCode() == "ResourceNotFoundException" {
				// Create a new secret
				secretValueOutput, createErr := a.scm.CreateSecret(context.TODO(), &secretsmanager.CreateSecretInput{
					SecretString: aws.String(string(secretBytes)),
					Name:         aws.String(secretID),
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

func (a *AWSSecretsMgr) delete(
	secretID string,
	retentionPeriodInDays int64,
) error {
	if retentionPeriodInDays != 0 && (retentionPeriodInDays < 7 || retentionPeriodInDays > 30) {
		return &secrets.ErrProviderInternal{
			Reason:   "invalid retention period, value must be a number between 7 and 30",
			Provider: Name,
		}
	}

	var deleteSecretInput *secretsmanager.DeleteSecretInput
	if retentionPeriodInDays == 0 {
		deleteSecretInput = &secretsmanager.DeleteSecretInput{
			// By default, aws keeps the secret for 30 days
			// Delete immediately
			ForceDeleteWithoutRecovery: aws.Bool(true),
			SecretId:                   aws.String(secretID),
		}
	} else {
		deleteSecretInput = &secretsmanager.DeleteSecretInput{
			SecretId:             aws.String(secretID),
			RecoveryWindowInDays: aws.Int64(retentionPeriodInDays),
		}
	}

	_, err := a.scm.DeleteSecret(context.TODO(), deleteSecretInput)
	if err != nil {
		return &secrets.ErrProviderInternal{Reason: err.Error(), Provider: Name}
	}
	return nil
}

func createSecretId(key secrets.SecretKey) string {
	if key.Prefix == "" {
		return key.Name
	}

	return fmt.Sprintf("%s/%s", key.Prefix, key.Name)
}

func init() {
	if err := secrets.Register(Name, func(secretConfig map[string]interface{}) (secrets.Secrets, error) {
		return New(secretConfig)
	}); err != nil {
		panic(err.Error())
	}

	if err := secrets.RegisterStore(Name, func(secretConfig map[string]interface{}) (secrets.SecretStore, error) {
		return New(secretConfig)
	}); err != nil {
		panic(err.Error())
	}
}
