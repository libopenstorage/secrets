package ibm

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
	secretConfig := make(map[string]interface{})

	// With kvdbPersistenceStore
	kv, err := kvdb.New(mem.Name, "openstorage/", nil, nil, nil)
	if err != nil {
		t.Fatalf("Unable to create a IBM Key Protect Secret instance: %v", err)
		return
	}
	secretConfig[IbmKvdbKey] = kv
	kp, err := New(secretConfig)
	if err != nil {
		t.Fatalf("Unable to create a IBM Key Protect Secret instance: %v", err)
		return
	}
	ik := &ibmSecretTest{kp, ""}
	test.Run(ik, t)
}

type ibmSecretTest struct {
	s          secrets.Secrets
	passphrase string
}

func (i *ibmSecretTest) TestPutSecret(t *testing.T) error {
	secretData := make(map[string]interface{})
	i.passphrase = uuid.New()
	secretData[testSecretIdWithPassphrase] = i.passphrase

	// PutSecret with non-nil secretData and no key context
	err := i.s.PutSecret(testSecretIdWithPassphrase, secretData, nil)
	assert.Error(t, err, "Expected error on PutSecret")
	errInvalidContext, ok := err.(*ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "when none of", "Unexpected error on PutSecret")

	keyContext := make(map[string]string)
	keyContext[secrets.CustomSecretData] = "true"

	// PutSecret with nil secretData and key context
	err = i.s.PutSecret(testSecretIdWithPassphrase, nil, keyContext)
	errInvalidContext, ok = err.(*ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "secret data needs to be provided", "Unexpected error on PutSecret")

	// Successful PutSecret with custom secret data
	err = i.s.PutSecret(testSecretIdWithPassphrase, secretData, keyContext)
	assert.NoError(t, err, "Unexpected error on PutSecret")

	// PutSecret with nil secretData
	err = i.s.PutSecret(testSecretId, nil, nil)
	assert.NoError(t, err, "Unexpected error on PutSecret")

	// Both CustomSecretData and PublicSecretData cannot be set
	keyContext[secrets.PublicSecretData] = "true"
	err = i.s.PutSecret(testSecretIdWithPublic, nil, keyContext)
	errInvalidContext, ok = err.(*ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "both", "Unexpected error on PutSecret")

	delete(keyContext, secrets.CustomSecretData)

	// PublicSecretData with no data
	err = i.s.PutSecret(testSecretIdWithPublic, nil, keyContext)
	errInvalidContext, ok = err.(*ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "secret data needs to be provided", "Unexpected error on PutSecret")

	// Successful PutSecret with PublicSecretData
	getKC := make(map[string]string)
	getKC[secrets.PublicSecretData] = "true"
	secretData, err = i.s.GetSecret(testSecretId, getKC)
	dek := secretData[testSecretId]
	putSecretData := make(map[string]interface{})
	putSecretData[testSecretIdWithPublic] = dek
	err = i.s.PutSecret(testSecretIdWithPublic, putSecretData, keyContext)
	assert.NoError(t, err, "Unexpected error on PutSecret")
	return nil
}

func (i *ibmSecretTest) TestGetSecret(t *testing.T) error {
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
	assert.NoError(t, err, "Unexpected error on GetSecret")

	// Both the flags are set
	keyContext[secrets.PublicSecretData] = "true"
	_, err = i.s.GetSecret(testSecretIdWithPublic, keyContext)
	errInvalidContext, ok := err.(*ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "both", "Unexpected error on PutSecret")

	// GetSecret using the secretID for public
	delete(keyContext, secrets.CustomSecretData)

	// deks for both secrets should match
	sec1, err := i.s.GetSecret(testSecretId, keyContext)
	assert.NoError(t, err, "Unexpected error on GetSecret")
	dek1, ok := sec1[testSecretId]
	assert.True(t, ok, "Unexpected secret returned")

	sec2, err := i.s.GetSecret(testSecretIdWithPublic, keyContext)
	assert.NoError(t, err, "Unexpected error on GetSecret")
	dek2, ok := sec2[testSecretIdWithPublic]
	assert.True(t, ok, "Unexpected secret returned")

	assert.Equal(t, dek1, dek2, "Unequal secrets returned.")
	return nil
}

func (i *ibmSecretTest) TestDeleteSecret(t *testing.T) error {
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
	os.Unsetenv(IbmServiceApiKey)
	os.Unsetenv(IbmInstanceIdKey)
	os.Unsetenv(IbmCustomerRootKey)
	// nil secret config
	_, err := New(nil)
	assert.EqualError(t, err, ErrInvalidKvdbProvided.Error(), "Unexpected error on nil secret config")

	// empty secret config
	secretConfig := make(map[string]interface{})
	_, err = New(secretConfig)
	assert.EqualError(t, err, ErrInvalidKvdbProvided.Error(), "Unexpected error on empty secret config")

	// kvdb key is incorrect
	secretConfig[IbmKvdbKey] = "dummy"
	_, err = New(secretConfig)
	assert.EqualError(t, err, ErrInvalidKvdbProvided.Error(), "Unepxected error when Kvdb Key not provided")

	// With kvdbPersistenceStore
	kv, err := kvdb.New(mem.Name, "openstorage/", nil, nil, nil)
	if err != nil {
		t.Fatalf("Unable to create a IBM Key Protect Secret instance: %v", err)
		return
	}

	// kvdb key is correct
	secretConfig[IbmKvdbKey] = kv
	kp, err := New(secretConfig)
	assert.EqualError(t, err, ErrCRKNotProvided.Error(), "Unepxected error when Kvdb Key not provided")
	// crk not provided
	secretConfig[IbmServiceApiKey] = "foo"
	secretConfig[IbmInstanceIdKey] = "bar"
	_, err = New(secretConfig)
	assert.EqualError(t, err, ErrCRKNotProvided.Error(), "Unepxected error when CRK not provided")

	// service api key not provided
	secretConfig[IbmCustomerRootKey] = "bar1"
	delete(secretConfig, IbmServiceApiKey)
	_, err = New(secretConfig)
	assert.EqualError(t, err, ErrIbmServiceApiKeyNotSet.Error(), "Unexpected error when Service API Key not provided")

	// instance id not provided
	secretConfig[IbmServiceApiKey] = "foo"
	delete(secretConfig, IbmInstanceIdKey)
	_, err = New(secretConfig)
	assert.EqualError(t, err, ErrIbmInstanceIdKeyNotSet.Error(), "Unexpected error when Instance ID Key not provided")

	// kvdb key not provided
	secretConfig[IbmInstanceIdKey] = "bar"
	kp, err = New(secretConfig)
	assert.NotNil(t, kp, "Expected New API to succeed")
	assert.NoError(t, err, "Unepxected error on New")

}
