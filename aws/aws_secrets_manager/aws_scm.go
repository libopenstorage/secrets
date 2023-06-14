package aws_secrets_manager

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
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
		awsConfig, ok := awsConfig.(*aws.Config)
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
	config := aws.Config{
		Credentials: creds,
		Region:      region,
	}

	return NewFromAWSConfig(&config)
}

// NewFromAWSConfig creates new instance of AWSSecretsMgr with provided AWS configuration (aws.Config).
func NewFromAWSConfig(config *aws.Config) (*AWSSecretsMgr, error) {
	cfg, err := external.LoadDefaultAWSConfig(*config)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %v", err)
	}

	scm := secretsmanager.NewFromConfig(cfg)
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

func (a *AWSSecretsMgr) Delete(ctx context.Context, key secrets.SecretKey) error {
	secretID := createSecretId(key)

	retentionPeriodInDays := getSecretRetentionPeriodFromContext(ctx)

	if retentionPeriodInDays > 0 {
		return a.deleteSecretWithRetention(secretID, retentionPeriodInDays)
	}

	_, err := a.deleteSecret(secretID)
	return err
}

func (a *AWSSecretsMgr) get(secretID string) (map[string]interface{}, string, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	}

	result, err := a.scm.GetSecretValue(context.TODO(), input)
	if err != nil {
		return nil, "", convertAWSErr(err)
	}

	var secret map[string]interface{}
	if err := json.Unmarshal([]byte(*result.SecretString), &secret); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal secret value: %v", err)
	}

	return secret, *result.VersionId, nil
}

func (a *AWSSecretsMgr) put(secretID string, secret map[string]interface{}) (string, error) {
	secretValue, err := json.Marshal(secret)
	if err != nil {
		return "", fmt.Errorf("failed to marshal secret value: %v", err)
	}

	input := &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(secretID),
		SecretString: aws.String(string(secretValue)),
	}

	result, err := a.scm.PutSecretValue(context.TODO(), input)
	if err != nil {
		return "", convertAWSErr(err)
	}

	return *result.VersionId, nil
}

func (a *AWSSecretsMgr) deleteSecret(secretID string) (string, error) {
	input := &secretsmanager.DeleteSecretInput{
		SecretId: aws.String(secretID),
	}

	result, err := a.scm.DeleteSecret(context.TODO(), input)
	if err != nil {
		return "", convertAWSErr(err)
	}

	return *result.DeletionDate, nil
}

func (a *AWSSecretsMgr) deleteSecretWithRetention(secretID string, retentionPeriodInDays int) error {
	input := &secretsmanager.DeleteSecretInput{
		SecretId: aws.String(secretID),
	}
	ctx := context.WithValue(context.Background(), SecretRetentionPeriodInDaysKey, retentionPeriodInDays)
	_, err := a.scm.DeleteSecretWithContext(ctx, input)
	if err != nil {
		return convertAWSErr(err)
	}

	return nil
}

func (a *AWSSecretsMgr) Type() string {
	return Name
}

func (a *AWSSecretsMgr) Versions(key secrets.SecretKey) ([]string, error) {
	secretID := createSecretId(key)

	input := &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(secretID),
	}

	result, err := a.scm.DescribeSecret(context.Background(), input)
	if err != nil {
		return nil, convertAWSErr(err)
	}

	var versions []string
	for _, version := range result.VersionIdsToStages {
		versions = append(versions, *version)
	}

	return versions, nil
}

func (a *AWSSecretsMgr) Version(key secrets.SecretKey, version string) (map[string]interface{}, error) {
	secretID := createSecretId(key)

	input := &secretsmanager.GetSecretValueInput{
		SecretId:         aws.String(secretID),
		VersionStage:     aws.String(version),
		VersionId:        aws.String(version),
	}

	result, err := a.scm.GetSecretValue(context.Background(), input)
	if err != nil {
		return nil, convertAWSErr(err)
	}

	var secret map[string]interface{}
	if err := json.Unmarshal([]byte(*result.SecretString), &secret); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret value: %v", err)
	}

	return secret, nil
}

func createSecretId(key secrets.SecretKey) string {
	return fmt.Sprintf("%s/%s", key.Namespace, key.Name)
}

func convertAWSErr(err error) error {
	if awsErr, ok := err.(awserr.Error); ok {
		return fmt.Errorf("AWS error: %s - %s", awsErr.Code(), awsErr.Message())
	}
	return err
}

func getSecretRetentionPeriodFromContext(ctx context.Context) int {
	retentionPeriodInDays, _ := ctx.Value(SecretRetentionPeriodInDaysKey).(int)
	return retentionPeriodInDays
}