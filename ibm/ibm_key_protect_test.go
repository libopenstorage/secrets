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
	testSecretId = "openstorage_secret"
)

func TestAll(t *testing.T) {
	// Set the relevant environment fields for ibm kp.
	secretConfig := make(map[string]interface{})
	// Fill in the appropriate keys and values
	secretConfig[IbmServiceApiKey] = os.Getenv(IbmServiceApiKey)
	secretConfig[IbmInstanceIdKey] = os.Getenv(IbmInstanceIdKey)
	secretConfig[IbmCustomerRootKey] = os.Getenv(IbmCustomerRootKey)
	secretConfig[IbmBaseUrlKey] = os.Getenv(IbmBaseUrlKey)
	secretConfig[IbmTokenUrlKey] = os.Getenv(IbmTokenUrlKey)

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
	secretData[testSecretId] = i.passphrase
	// PutSecret with non-nil secretData
	err := i.s.PutSecret(testSecretId, secretData, nil)
	if err != nil {
		t.Errorf("Expected PutSecret to not fail.: %v", err)
	}

	// PutSecret with nil secretData
	err = i.s.PutSecret(testSecretId, nil, nil)
	if err == nil {
		t.Errorf("Expected PutSecret to return with an error")
	}

	// PutSecret with already existing secretId
	err = i.s.PutSecret(testSecretId, secretData, nil)
	if err != nil {
		t.Errorf("Expected PutSecret to fail with ErrSecretExists error")
	}

	return nil
}

func (i *ibmSecretTest) TestGetSecret(t *testing.T) error {
	// GetSecret with non-existant id
	_, err := i.s.GetSecret("dummy", nil)
	if err == nil {
		t.Errorf("Expected GetSecret to fail. Invalid secretId")
	}

	// GetSecret using a secretId with data
	plainText1, err := i.s.GetSecret(testSecretId, nil)
	if err != nil && err != secrets.ErrInvalidSecretId {
		t.Errorf("Expected GetSecret to succeed. Failed with error: %v", err)
	} else if err == nil {
		// We have got secretData
		if plainText1 == nil {
			t.Errorf("Invalid PlainText was returned")
		}
		v, ok := plainText1[testSecretId]
		if !ok {
			t.Errorf("Unexpected secretData")
		}
		str, ok := v.(string)
		if !ok {
			t.Errorf("Unexpected secretData")
		}
		if str != i.passphrase {
			t.Errorf("Unexpected secretData")
		}
	}
	return nil
}

func TestNew(t *testing.T) {
	// nil secret config
	_, err := New(nil)
	assert.EqualError(t, err, ErrIbmServiceApiKeyNotSet.Error(), "Unexpected error on nil secret config")

	// empty secret config
	secretConfig := make(map[string]interface{})
	_, err = New(secretConfig)
	assert.EqualError(t, err, ErrIbmServiceApiKeyNotSet.Error(), "Unexpected error on empty secret config")

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
	_, err = New(secretConfig)
	assert.EqualError(t, err, ErrInvalidKvdbProvided.Error(), "Unepxected error when Kvdb Key not provided")

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
	assert.NotNil(t, kp, "Expected New API to succeed")
	assert.NoError(t, err, "Unepxected error on New")

}
