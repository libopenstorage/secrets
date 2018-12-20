package gcloud

import (
	"os"
	"testing"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/test"
	"github.com/pborman/uuid"
	"github.com/portworx/kvdb"
	"github.com/portworx/kvdb/mem"
	"github.com/stretchr/testify/assert"
)

const (
	testSecretIdWithPassphrase = "openstorage_secret_with_passphrase"
	testSecretId               = "openstorage_secret"
	testSecretIdWithPublic     = "openstorage_secret_with_public"
)

func TestAll(t *testing.T) {
	// Set the relevant environmnet fields for aws.
	secretConfig := make(map[string]interface{})
	// Fill in the appropriate keys and values
	secretConfig[GoogleKmsResourceKey] = os.Getenv(GoogleKmsResourceKey)

	kv, err := kvdb.New(mem.Name, "openstorage/", nil, nil, nil)
	if err != nil {
		t.Fatalf("Unable to create a gcloud secret instance: %v", err)
		return
	}
	secretConfig[KMSKvdbKey] = kv
	gs, err := NewGcloudSecretTest(secretConfig)
	if err != nil {
		t.Fatalf("Unable to create a gcloud secret instance: %v", err)
		return
	}
	test.Run(gs, t)
}

type gcloudSecretTest struct {
	s          secrets.Secrets
	passphrase string
	totalPuts  int
}

func NewGcloudSecretTest(secretConfig map[string]interface{}) (test.SecretTest, error) {
	s, err := New(secretConfig)
	if err != nil {
		return nil, err
	}
	return &gcloudSecretTest{s, "", 0}, nil
}

func (i *gcloudSecretTest) TestPutSecret(t *testing.T) error {
	secretData := make(map[string]interface{})
	i.passphrase = uuid.New()
	secretData[testSecretIdWithPassphrase] = i.passphrase

	// PutSecret with non-nil secretData and no key context
	err := i.s.PutSecret(testSecretIdWithPassphrase, secretData, nil)
	assert.Error(t, err, "Expected error on PutSecret")
	errInvalidContext, ok := err.(*secrets.ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "when none of", "Unexpected error on PutSecret")

	keyContext := make(map[string]string)
	keyContext[secrets.CustomSecretData] = "true"

	// PutSecret with nil secretData and key context
	err = i.s.PutSecret(testSecretIdWithPassphrase, nil, keyContext)
	errInvalidContext, ok = err.(*secrets.ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "secret data needs to be provided", "Unexpected error on PutSecret")

	// Successful PutSecret with custom secret data
	err = i.s.PutSecret(testSecretIdWithPassphrase, secretData, keyContext)
	assert.NoError(t, err, "Unexpected error on PutSecret")
	i.totalPuts++

	// PutSecret with nil secretData
	err = i.s.PutSecret(testSecretId, nil, nil)
	assert.Error(t, secrets.ErrEmptySecretData, err.Error(), "Unexpected error on PutSecret")

	// Both CustomSecretData and PublicSecretData cannot be set
	keyContext[secrets.PublicSecretData] = "true"
	err = i.s.PutSecret(testSecretIdWithPublic, nil, keyContext)
	errInvalidContext, ok = err.(*secrets.ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "both", "Unexpected error on PutSecret")

	delete(keyContext, secrets.CustomSecretData)

	// PublicSecretData with no data
	err = i.s.PutSecret(testSecretIdWithPublic, nil, keyContext)
	errInvalidContext, ok = err.(*secrets.ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "secret data needs to be provided", "Unexpected error on PutSecret")

	// Successful PutSecret with PublicSecretData
	getKC := make(map[string]string)
	getKC[secrets.PublicSecretData] = "true"
	secretData, err = i.s.GetSecret(testSecretIdWithPassphrase, getKC)
	dek := secretData[testSecretIdWithPassphrase]
	putSecretData := make(map[string]interface{})
	putSecretData[testSecretIdWithPublic] = dek
	err = i.s.PutSecret(testSecretIdWithPublic, putSecretData, keyContext)
	assert.NoError(t, err, "Unexpected error on PutSecret")
	i.totalPuts++
	return nil
}

func (i *gcloudSecretTest) TestGetSecret(t *testing.T) error {
	// GetSecret with non-existant id
	_, err := i.s.GetSecret("dummy", nil)
	assert.Error(t, err, "Expected GetSecret to fail")

	// GetSecret using a secretId with data
	keyContext := make(map[string]string)
	keyContext[secrets.CustomSecretData] = "true"
	plainText1, err := i.s.GetSecret(testSecretIdWithPassphrase, keyContext)
	assert.NoError(t, err, "Unexpected error on GetSecret")
	// We have got secretData
	assert.NotNil(t, plainText1, "Invalid plainText was returned")
	v, ok := plainText1[testSecretIdWithPassphrase]
	assert.True(t, ok, "Unexpected plainText")
	str, ok := v.(string)
	assert.True(t, ok, "Unexpected plainText")
	assert.Equal(t, str, i.passphrase, "Unexpected passphrase")

	// GetSecret using a secretId without data
	_, err = i.s.GetSecret(testSecretId, nil)
	assert.Error(t, secrets.ErrInvalidSecretId, err.Error(), "Unexpected error on GetSecret")

	// Both the flags are set
	keyContext[secrets.PublicSecretData] = "true"
	_, err = i.s.GetSecret(testSecretIdWithPublic, keyContext)
	errInvalidContext, ok := err.(*secrets.ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "both", "Unexpected error on PutSecret")

	// GetSecret using the secretID for public
	delete(keyContext, secrets.CustomSecretData)

	// deks for both secrets should match
	sec1, err := i.s.GetSecret(testSecretIdWithPassphrase, keyContext)
	assert.NoError(t, err, "Unexpected error on GetSecret")
	dek1, ok := sec1[testSecretIdWithPassphrase]
	assert.True(t, ok, "Unexpected secret returned")

	sec2, err := i.s.GetSecret(testSecretIdWithPublic, keyContext)
	assert.NoError(t, err, "Unexpected error on GetSecret")
	dek2, ok := sec2[testSecretIdWithPublic]
	assert.True(t, ok, "Unexpected secret returned")

	assert.Equal(t, dek1, dek2, "Unequal secrets returned.")
	return nil
}

func (i *gcloudSecretTest) TestListSecrets(t *testing.T) error {
	ids, err := i.s.ListSecrets()
	assert.NoError(t, err, "Unexpected error on ListSecrets")
	assert.Equal(t, len(ids), i.totalPuts, "Unexpected number of secrets listed")
	return nil
}

func (i *gcloudSecretTest) TestDeleteSecret(t *testing.T) error {
	// Delete of a key that exists should succeed
	err := i.s.DeleteSecret(testSecretId, nil)
	assert.NoError(t, err, "Unexpected error on DeleteSecret")

	// Get of a deleted key should fail
	_, err = i.s.GetSecret(testSecretId, nil)
	assert.EqualError(t, secrets.ErrInvalidSecretId, err.Error(), "Expected an error on GetSecret after the key is deleted")

	// Delete of a non-existent key should also succeed
	err = i.s.DeleteSecret("dummy", nil)
	assert.NoError(t, err, "Unepxected error on DeleteSecret")
	return nil
}

func TestNew(t *testing.T) {
	os.Unsetenv(GoogleKmsResourceKey)
	// nil secret config
	_, err := New(nil)
	assert.EqualError(t, err, ErrInvalidKvdbProvided.Error(), "Unexpected error on nil secret config")

	// empty secret config
	secretConfig := make(map[string]interface{})
	_, err = New(secretConfig)
	assert.EqualError(t, err, ErrInvalidKvdbProvided.Error(), "Unexpected error on empty secret config")

	// kvdb key is incorrect
	secretConfig[KMSKvdbKey] = "dummy"
	_, err = New(secretConfig)
	assert.EqualError(t, err, ErrInvalidKvdbProvided.Error(), "Unepxected error when Kvdb Key not provided")

	// With kvdbPersistenceStore
	kv, err := kvdb.New(mem.Name, "openstorage/", nil, nil, nil)
	if err != nil {
		t.Fatalf("Unable to create a IBM Key Protect Secret instance: %v", err)
		return
	}

	// kvdb key is correct
	secretConfig[KMSKvdbKey] = kv
	kp, err := New(secretConfig)
	assert.EqualError(t, err, ErrGoogleKmsResourceKeyNotProvided.Error(), "Unepxected error when Kvdb Key not provided")

	secretConfig[GoogleKmsResourceKey] = "crk"
	kp, err = New(secretConfig)
	assert.NotNil(t, kp, "Expected New API to succeed")
	assert.NoError(t, err, "Unepxected error on New")

}
