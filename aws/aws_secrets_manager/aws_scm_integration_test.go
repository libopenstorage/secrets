//go:build integration
// +build integration

package aws_secrets_manager

import (
	"os"
	"testing"

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
	s                   secrets.Secrets
	totalPuts           int
	secretIdWithData    string
	secretIdWithoutData string
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
	err := a.s.PutSecret(a.secretIdWithData, secretData, nil)
	assert.NoError(t, err, "Unepxected error on PutSecret")
	a.totalPuts++

	// PutSecret with nil secretData
	err = a.s.PutSecret(a.secretIdWithoutData, nil, nil)
	assert.NoError(t, err, "Expected PutSecret to succeed. Failed with error: %v", err)
	a.totalPuts++

	return nil
}

func (a *awsSecretTest) TestGetSecret(t *testing.T) error {
	// GetSecret with non-existant id
	_, err := a.s.GetSecret("dummy", nil)
	assert.Error(t, err, "Expected GetSecret to fail")

	// GetSecret using a secretId with data
	plainText1, err := a.s.GetSecret(a.secretIdWithData, nil)
	assert.NoError(t, err, "Expected GetSecret to succeed")
	assert.NotNil(t, plainText1, "Expected plainText to not be nil")
	v, ok := plainText1["key1"]
	assert.True(t, ok, "Unexpected secretData")
	str, ok := v.(string)
	assert.True(t, ok, "Unexpected secretData")
	assert.Equal(t, str, "value1", "Unexpected secretData")

	// GetSecret using a secretId without data
	_, err = a.s.GetSecret(a.secretIdWithoutData, nil)
	assert.NoError(t, err, "Expected GetSecret to succeed")

	return nil
}

func (a *awsSecretTest) TestListSecrets(t *testing.T) error {
	// Not implemented
	return nil
}

func (a *awsSecretTest) TestDeleteSecret(t *testing.T) error {
	// Delete of a key that exists should succeed
	err := a.s.DeleteSecret(a.secretIdWithData, nil)
	assert.NoError(t, err, "Expected DeleteSecret to succeed")

	// Get of a deleted key should fail
	_, err = a.s.GetSecret(a.secretIdWithData, nil)
	assert.EqualError(t, secrets.ErrInvalidSecretId, err.Error(), "Unexpected error on GetSecret after delete")

	// Delete of a key that exists should succeed
	err = a.s.DeleteSecret(a.secretIdWithoutData, nil)
	assert.NoError(t, err, "Expected DeleteSecret to succeed")

	// GetSecret using a secretId without data
	_, err = a.s.GetSecret(a.secretIdWithoutData, nil)
	assert.EqualError(t, secrets.ErrInvalidSecretId, err.Error(), "Unexpected error on GetSecret after delete")

	// Delete of a non-existent key should also succeed
	err = a.s.DeleteSecret("dummy", nil)
	assert.NoError(t, err, "Unexpected error on DeleteSecret")
	return nil
}
