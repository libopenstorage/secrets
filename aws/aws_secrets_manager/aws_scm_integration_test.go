//go:build integration
// +build integration

package aws_secrets_manager

import (
	"testing"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/aws/utils"
	"github.com/libopenstorage/secrets/test"
	"github.com/stretchr/testify/assert"
)

const (
	secretIdWithData    = "openstorage_secret_data"
	secretIdWithoutData = "openstorage_secret"
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
	s         secrets.Secrets
	totalPuts int
}

func NewAwsSecretTest(secretConfig map[string]interface{}) (test.SecretTest, error) {
	s, err := New(secretConfig)
	if err != nil {
		return nil, err
	}
	return &awsSecretTest{s, 0}, nil
}

func (a *awsSecretTest) TestPutSecret(t *testing.T) error {
	secretData := make(map[string]interface{})
	secretData["key1"] = "value1"
	secretData["key2"] = "value2"
	// PutSecret with non-nil secretData
	err := a.s.PutSecret(secretIdWithData, secretData, nil)
	assert.NoError(t, err, "Unepxected error on PutSecret")
	a.totalPuts++

	// PutSecret with nil secretData
	err = a.s.PutSecret(secretIdWithoutData, nil, nil)
	assert.NoError(t, err, "Expected PutSecret to succeed. Failed with error: %v", err)
	a.totalPuts++

	return nil
}

func (a *awsSecretTest) TestGetSecret(t *testing.T) error {
	// GetSecret with non-existant id
	_, err := a.s.GetSecret("dummy", nil)
	assert.Error(t, err, "Expected GetSecret to fail")

	// GetSecret using a secretId with data
	plainText1, err := a.s.GetSecret(secretIdWithData, nil)
	assert.NoError(t, err, "Expected GetSecret to succeed")
	assert.NotNil(t, plainText1, "Expected plainText to not be nil")
	v, ok := plainText1["key1"]
	assert.True(t, ok, "Unexpected secretData")
	str, ok := v.(string)
	assert.True(t, ok, "Unexpected secretData")
	assert.Equal(t, str, "value1", "Unexpected secretData")

	// GetSecret using a secretId without data
	_, err = a.s.GetSecret(secretIdWithoutData, nil)
	assert.NoError(t, err, "Expected GetSecret to succeed")

	return nil
}

func (a *awsSecretTest) TestListSecrets(t *testing.T) error {
	// Not implemented
	return nil
}

func (a *awsSecretTest) TestDeleteSecret(t *testing.T) error {
	// Delete of a key that exists should succeed
	err := a.s.DeleteSecret(secretIdWithData, nil)
	assert.NoError(t, err, "Expected DeleteSecret to succeed")

	// Get of a deleted key should fail
	_, err = a.s.GetSecret(secretIdWithData, nil)
	assert.EqualError(t, secrets.ErrInvalidSecretId, err.Error(), "Unexpected error on GetSecret after delete")

	// Delete of a key that exists should succeed
	err = a.s.DeleteSecret(secretIdWithoutData, nil)
	assert.NoError(t, err, "Expected DeleteSecret to succeed")

	// GetSecret using a secretId without data
	_, err = a.s.GetSecret(secretIdWithoutData, nil)
	assert.EqualError(t, secrets.ErrInvalidSecretId, err.Error(), "Unexpected error on GetSecret after delete")

	// Delete of a non-existent key should also succeed
	err = a.s.DeleteSecret("dummy", nil)
	assert.NoError(t, err, "Unexpected error on DeleteSecret")
	return nil
}
