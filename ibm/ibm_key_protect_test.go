package ibm

import (
	"os"
	"testing"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/test"
	"github.com/pborman/uuid"
	"github.com/portworx/kvdb"
	"github.com/portworx/kvdb/mem"
)

const (
	testSecretId = "openstorage_secret"
)

func TestAll(t *testing.T) {
	// Set the relevant environmnet fields for aws.
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
		t.Fatalf("Unable to create a AWS Secret instance: %v", err)
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
