//go:build integration
// +build integration

package aws_kms

import (
	"os"
	"testing"
	"time"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/aws/utils"
	"github.com/libopenstorage/secrets/test"
	"github.com/portworx/kvdb"
	"github.com/portworx/kvdb/mem"
	"github.com/stretchr/testify/assert"
)

const (
	secretIdWithData    = "openstorage_secret_data"
	secretIdWithoutData = "openstorage_secret"
	secretIdWithPublic  = "openstorage_secret_with_public"
)

func TestAll(t *testing.T) {
	// Set the relevant environmnet fields for aws.
	secretConfig := make(map[string]interface{})
	// Fill in the appropriate keys and values
	secretConfig[AwsCMKey] = os.Getenv(AwsCMKey)
	secretConfig[utils.AwsRegionKey] = os.Getenv(utils.AwsRegionKey)

	os.RemoveAll(secrets.SecretPath + secretIdWithoutData)

	// With kvdbPersistenceStore
	kv, err := kvdb.New(mem.Name, "openstorage/", nil, nil, nil)
	if err != nil {
		t.Fatalf("Unable to create a AWS Secret instance: %v", err)
		return
	}
	secretConfig[KMSKvdbKey] = kv
	as, err := NewAwsSecretTest(secretConfig)
	if err != nil {
		t.Fatalf("Unable to create a AWS Secret instance: %v", err)
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
	_, err := a.s.PutSecret(secretIdWithData, secretData, nil)
	assert.NoError(t, err, "Unepxected error on PutSecret")
	a.totalPuts++

	// PutSecret with nil secretData
	_, err = a.s.PutSecret(secretIdWithoutData, nil, nil)
	assert.NoError(t, err, "Expected PutSecret to succeed. Failed with error: %v", err)
	a.totalPuts++

	// PublicSecretData with no data
	keyContext := make(map[string]string)
	keyContext[secrets.PublicSecretData] = "true"
	_, err = a.s.PutSecret(secretIdWithPublic, nil, keyContext)
	errInvalidContext, ok := err.(*secrets.ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(),
		"secret data needs to be provided", "Unexpected error on PutSecret")

	// PublicSecretData with invalid data
	invalidData := map[string]interface{}{secretIdWithPublic: true}
	_, err = a.s.PutSecret(secretIdWithPublic, invalidData, keyContext)
	errInvalidContext, ok = err.(*secrets.ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(),
		"should be of the type []byte", "Unexpected error on PutSecret")

	// Successful PutSecret with PublicSecretData
	getKC := make(map[string]string)
	getKC[secrets.PublicSecretData] = "true"
	secretData, _, err = a.s.GetSecret(secretIdWithoutData, getKC)
	dek := secretData[secretIdWithoutData]
	putSecretData := make(map[string]interface{})
	putSecretData[secretIdWithPublic] = dek
	_, err = a.s.PutSecret(secretIdWithPublic, putSecretData, keyContext)
	assert.NoError(t, err, "Unexpected error on PutSecret")
	a.totalPuts++

	return nil
}

func (a *awsSecretTest) TestGetSecret(t *testing.T) error {
	invalidKeyContext := map[string]string{"key": "invalid"}
	// GetSecret with non-existant id
	_, _, err := a.s.GetSecret("dummy", nil)
	assert.Error(t, err, "Expected GetSecret to fail")

	// GetSecret with different key context from PutSecret should fail
	_, _, err = a.s.GetSecret(secretIdWithData, invalidKeyContext)
	assert.Error(t, err, "Expected GetSecret to fail")

	// GetSecret using a secretId with data
	plainText1, _, err := a.s.GetSecret(secretIdWithData, nil)
	assert.NoError(t, err, "Expected GetSecret to succeed")
	assert.NotNil(t, plainText1, "Expected plainText to not be nil")
	v, ok := plainText1["key1"]
	assert.True(t, ok, "Unexpected secretData")
	str, ok := v.(string)
	assert.True(t, ok, "Unexpected secretData")
	assert.Equal(t, str, "value1", "Unexpected secretData")

	// GetSecret using a secretId without data
	_, _, err = a.s.GetSecret(secretIdWithoutData, nil)
	assert.NoError(t, err, "Expected GetSecret to succeed")

	// GetSecret using the secretID for public
	keyContext := make(map[string]string)
	keyContext[secrets.PublicSecretData] = "true"
	// deks for both secrets should match
	sec1, _, err := a.s.GetSecret(secretIdWithoutData, keyContext)
	assert.NoError(t, err, "Unexpected error on GetSecret")
	dek1, ok := sec1[secretIdWithoutData]
	assert.True(t, ok, "Unexpected secret returned")

	// GetSecret with different key context from PutSecret should fail
	_, _, err = a.s.GetSecret(secretIdWithPublic, invalidKeyContext)
	assert.Error(t, err, "Expected GetSecret to fail")
	// GetSecret with nil key context passes although PutSecret had key context
	_, _, err = a.s.GetSecret(secretIdWithPublic, nil)
	assert.NoError(t, err, "Unexpected error on GetSecret")

	sec2, _, err := a.s.GetSecret(secretIdWithPublic, keyContext)
	assert.NoError(t, err, "Unexpected error on GetSecret")
	dek2, ok := sec2[secretIdWithPublic]
	assert.True(t, ok, "Unexpected secret returned")

	assert.Equal(t, dek1, dek2, "Unequal secrets returned.")
	return nil
}

func (a *awsSecretTest) TestListSecrets(t *testing.T) error {
	ids, err := a.s.ListSecrets()
	assert.NoError(t, err, "Unexpected error on ListSecrets")
	assert.Equal(t, len(ids), a.totalPuts, "Unexpected number of secrets listed")
	return nil
}

func (a *awsSecretTest) TestDeleteSecret(t *testing.T) error {
	// Delete of a key that exists should succeed
	err := a.s.DeleteSecret(secretIdWithData, nil)
	assert.NoError(t, err, "Expected DeleteSecret to succeed")

	// Add a delay to allow time for deletion to propagate
	time.Sleep(time.Second * 30)

	// Get of a deleted key should fail
	_, _, err = a.s.GetSecret(secretIdWithData, nil)
	assert.EqualError(t, secrets.ErrInvalidSecretId, err.Error(), "Unexpected error on GetSecret after delete")

	// Delete of a non-existent key should also succeed
	err = a.s.DeleteSecret("dummy", nil)
	assert.NoError(t, err, "Unexpected error on DeleteSecret")
	return nil
}
