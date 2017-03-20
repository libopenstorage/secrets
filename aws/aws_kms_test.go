package aws

import (
	"os"
	"testing"
	"io/ioutil"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/test"
)

const (
	secretId = "openstorage_secret"
)

func TestAll(t *testing.T) {
	// Set the relevant environmnet fields for aws.
	secretConfig := make(map[string]interface{})
	// Fill in the appropriate keys and values
	secretConfig[awsCMKey] = "xxxx"
	secretConfig[awsRegionKey] = "us-<region>-1"
	as, err := NewAwsSecretTest(secretConfig)
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
	err := a.s.PutSecret(secretId, secretData, nil)
	if err == nil {
		t.Errorf("Expected PutSecret to fail. SecretData should always be null")
	}

	err = a.s.PutSecret(secretId, nil, nil)
	if err != nil {
		t.Errorf("Expected PutSecret to succeed. Failed with error: %v", err)
	}
	_, err = os.Stat(secrets.SecretPath + secretId)
	if os.IsNotExist(err) {
		t.Errorf("Expected PutSecret to write a file with cipher text blob")
	}
	return nil
}

func (a *awsSecretTest) TestGetSecret(t *testing.T) error {
	_, err := a.s.GetSecret("dummy", nil)
	if err == nil {
		t.Errorf("Expected GetSecret to fail. Invalid secretId")
	}

	plainText, err := a.s.GetSecret(secretId, nil)
	if err != nil {
		t.Errorf("Expected GetSecret to succeed. Failed with error: %v", err)
	}
	if plainText == nil || len(plainText) != 1 {
		t.Errorf("Invalid PlainText was returned")
	}

	path := secrets.SecretPath + secretId
	cipherBlob := []byte{}
	_, err = os.Stat(path)
	if err == nil || os.IsExist(err) {
		cipherBlob, err = ioutil.ReadFile(path)
		if err != nil {
			t.Errorf("Unable to read file")
		}
	}
	plainText2, err := a.s.GetSecret(string(cipherBlob), nil)
	if err != nil {
		t.Errorf("Expected GetSecret to succeed. Failed with error: %v", err)
	}
	if plainText2 == nil || len(plainText2) != 1 {
		t.Errorf("Invalid PlainText was returned")
	}

	pT1, _ := plainText[secretId]
	pT2, _ := plainText2[string(cipherBlob)]
	if pT1 == nil || pT2 == nil {
		t.Errorf("Plaintext is null")
	}

	if len(pT1.([]byte)) != len(pT2.([]byte)) {
		t.Errorf("Plain text do not match")
	}
	return nil
}
