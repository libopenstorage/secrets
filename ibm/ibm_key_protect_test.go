package ibm

import (
	"os"
	"testing"

	"github.com/portworx/kvdb"
	"github.com/portworx/kvdb/mem"
	"github.com/stretchr/testify/assert"
)

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
