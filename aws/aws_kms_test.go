package aws

import (
	"os"
	"testing"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/test"
	"github.com/portworx/kvdb"
	"github.com/portworx/kvdb/mem"
)

const (
	secretIdWithData    = "openstorage_secret_data"
	secretIdWithoutData = "openstorage_secret"
)

func TestAll(t *testing.T) {
	// Set the relevant environmnet fields for aws.
	secretConfig := make(map[string]interface{})
	// Fill in the appropriate keys and values
	secretConfig[AwsCMKKey] = os.Getenv(AwsCMKKey)
	secretConfig[AwsRegionKey] = os.Getenv(AwsRegionKey)

	os.RemoveAll(secrets.SecretPath + secretIdWithoutData)
	// With filePersistenceStore
	as, err := NewAwsSecretTest(secretConfig)
	if err != nil {
		t.Fatalf("Unable to create a AWS Secret instance: %v", err)
		return
	}
	test.Run(as, t)

	// With kvdbPersistenceStore
	kv, err := kvdb.New(mem.Name, "openstorage/", nil, nil, nil)
	if err != nil {
		t.Fatalf("Unable to create a AWS Secret instance: %v", err)
	}
	secretConfig[KMSKvdbKey] = kv
	as, err = NewAwsSecretTest(secretConfig)
	if err != nil {
		t.Fatalf("Unable to create a AWS Secret instance: %v", err)
		return
	}
	test.Run(as, t)
}

type awsSecretTest struct {
	s secrets.Secrets
}

func NewAwsSecretTest(secretConfig map[string]interface{}) (test.SecretTest, error) {
	s, err := New(secretConfig)
	if err != nil {
		return nil, err
	}
	return &awsSecretTest{s}, nil
}

func (a *awsSecretTest) TestPutSecret(t *testing.T) error {
	secretData := make(map[string]interface{})
	secretData["key1"] = "value1"
	secretData["key2"] = "value2"
	// PutSecret with non-nil secretData
	err := a.s.PutSecret(secretIdWithData, secretData, nil)
	if err != nil && err != ErrInvalidRequest {
		t.Errorf("Expected PutSecret to not fail.: %v", err)
	}

	// PutSecret with nil secretData
	err = a.s.PutSecret(secretIdWithoutData, nil, nil)
	if err != nil {
		t.Errorf("Expected PutSecret to succeed. Failed with error: %v", err)
	}

	// PutSecret with already existing secretId
	err = a.s.PutSecret(secretIdWithData, secretData, nil)
	if err != secrets.ErrSecretExists && err != ErrInvalidRequest {
		t.Errorf("Expected PutSecret to fail with ErrSecretExists error")
	}

	err = a.s.PutSecret(secretIdWithoutData, nil, nil)
	if err != secrets.ErrSecretExists {
		t.Errorf("Expected PutSecret to fail with ErrSecretExists error")
	}

	return nil
}

func (a *awsSecretTest) TestGetSecret(t *testing.T) error {
	// GetSecret with non-existant id
	_, err := a.s.GetSecret("dummy", nil)
	if err == nil {
		t.Errorf("Expected GetSecret to fail. Invalid secretId")
	}

	// GetSecret using a secretId with data
	plainText1, err := a.s.GetSecret(secretIdWithData, nil)
	if err != nil && err != secrets.ErrInvalidSecretId {
		t.Errorf("Expected GetSecret to succeed. Failed with error: %v", err)
	} else if err == nil {
		// We have got secretData
		if plainText1 == nil {
			t.Errorf("Invalid PlainText was returned")
		}
		v, ok := plainText1["key1"]
		if !ok {
			t.Errorf("Unexpected secretData")
		}
		str, ok := v.(string)
		if !ok {
			t.Errorf("Unexpected secretData")
		}
		if str != "value1" {
			t.Errorf("Unexpected secretData")
		}
	}

	// GetSecret using a secretId without data
	_, err = a.s.GetSecret(secretIdWithoutData, nil)
	if err != nil {
		t.Errorf("Expected GetSecret to succeed. Failed with error: %v", err)
	}
	return nil
}
