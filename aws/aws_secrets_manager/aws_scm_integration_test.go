//go:build integration
// +build integration

package aws_secrets_manager

import (
	"os"
	"testing"
	"time"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/aws/utils"
	"github.com/libopenstorage/secrets/test"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAll(t *testing.T) {
	// Set the relevant environmnet fields for aws.
	secretConfig := make(map[string]interface{})

	// Fill in the appropriate keys and values
	secretConfig[utils.AwsRegionKey] = os.Getenv(utils.AwsRegionKey)
	secretConfig[utils.AwsSecretAccessKey] = os.Getenv(utils.AwsSecretAccessKey)
	secretConfig[utils.AwsAccessKey] = os.Getenv(utils.AwsAccessKey)

	as, err := NewAwsSecretTest(secretConfig)
	if err != nil {
		t.Fatalf("Unable to create a AWS Secrets Manager instance: %v", err)
		return
	}
	test.Run(as, t)
}

type awsSecretTest struct {
	s                          secrets.Secrets
	totalPuts                  int
	secretIdWithData           string
	secretIdWithoutData        string
	secretIdWithDataVersion    secrets.Version
	secretIdWithoutDataVersion secrets.Version
}

func NewAwsSecretTest(secretConfig map[string]interface{}) (test.SecretTest, error) {
	s, err := New(secretConfig)
	if err != nil {
		return nil, err
	}
	return &awsSecretTest{
		s:                   s,
		totalPuts:           0,
		secretIdWithData:    "openstorage_secret_data_" + uuid.New(),
		secretIdWithoutData: "openstorage_secret_" + uuid.New(),
	}, nil
}

func (a *awsSecretTest) TestPutSecret(t *testing.T) error {
	secretData := make(map[string]interface{})
	secretData["key1"] = "value1"
	secretData["key2"] = "value2"
	// PutSecret with non-nil secretData
	version, err := a.s.PutSecret(a.secretIdWithData, secretData, nil)
	assert.NoError(t, err, "Unexpected error on PutSecret")
	assert.NotEmptyf(t, string(version), "expected non-empty version")
	a.totalPuts++
	a.secretIdWithDataVersion = version

	// PutSecret with nil secretData
	version, err = a.s.PutSecret(a.secretIdWithoutData, nil, nil)
	assert.NoError(t, err, "Expected PutSecret to succeed. Failed with error: %v", err)
	assert.NotEmptyf(t, string(version), "expected non-empty version")
	a.secretIdWithoutDataVersion = version

	a.totalPuts++

	return nil
}

func (a *awsSecretTest) TestGetSecret(t *testing.T) error {
	// GetSecret with non-existant id
	_, version, err := a.s.GetSecret("dummy", nil)
	assert.Error(t, err, "Expected GetSecret to fail")
	assert.Equal(t, version, secrets.NoVersion)

	// GetSecret using a secretId with data
	plainText1, version, err := a.s.GetSecret(a.secretIdWithData, nil)
	assert.NoError(t, err, "Expected GetSecret to succeed")
	assert.NotNil(t, plainText1, "Expected plainText to not be nil")
	assert.Equal(t, a.secretIdWithDataVersion, version)
	v, ok := plainText1["key1"]
	assert.True(t, ok, "Unexpected secretData")
	str, ok := v.(string)
	assert.True(t, ok, "Unexpected secretData")
	assert.Equal(t, str, "value1", "Unexpected secretData")

	// GetSecret using a secretId without data
	_, version, err = a.s.GetSecret(a.secretIdWithoutData, nil)
	assert.NoError(t, err, "Expected GetSecret to succeed")
	assert.Equal(t, a.secretIdWithoutDataVersion, version)

	return nil
}

func (a *awsSecretTest) TestListSecrets(t *testing.T) error {
	// Not implemented
	return nil
}

func (a *awsSecretTest) TestDeleteSecret(t *testing.T) error {
	// Delete of a key that exists should succeed
	keyContext := make(map[string]string)
	keyContext[SecretRetentionPeriodInDaysKey] = "7"

	err := a.s.DeleteSecret(a.secretIdWithData, keyContext)
	assert.NoError(t, err, "Expected DeleteSecret to succeed")

	// Add a delay to allow time for deletion to propagate
	time.Sleep(time.Second * 30)

	// Get of a deleted key should fail
	_, version, err := a.s.GetSecret(a.secretIdWithData, nil)
	assert.EqualError(t, secrets.ErrInvalidSecretId, err.Error(), "Unexpected error on GetSecret after delete")
	assert.Equal(t, version, secrets.NoVersion)

	// Delete of a key that exists should succeed
	err = a.s.DeleteSecret(a.secretIdWithoutData, nil)
	assert.NoError(t, err, "Expected DeleteSecret to succeed")

	// Add a delay to allow time for deletion to propagate
	time.Sleep(time.Second * 30)

	// GetSecret using a secretId without data
	_, version, err = a.s.GetSecret(a.secretIdWithoutData, nil)
	assert.EqualError(t, secrets.ErrInvalidSecretId, err.Error(), "Unexpected error on GetSecret after delete")
	assert.Equal(t, version, secrets.NoVersion)

	// Delete of a non-existent key should also succeed
	err = a.s.DeleteSecret("dummy", nil)
	assert.NoError(t, err, "Unexpected error on DeleteSecret")
	return nil
}
