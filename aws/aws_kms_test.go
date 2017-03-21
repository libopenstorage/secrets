package aws

import (
	"io/ioutil"
	"os"
	"testing"

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
	secretConfig[awsCMKey] = "<cmk-key>"
	secretConfig[awsRegionKey] = "<aws-region>"
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
	// PutSecret with non-nil secretData
	err := a.s.PutSecret(secretId, secretData, nil)
	if err == nil {
		t.Errorf("Expected PutSecret to fail. SecretData should always be null")
	}

	// A successful PutSecret
	err = a.s.PutSecret(secretId, nil, nil)
	if err != nil {
		t.Errorf("Expected PutSecret to succeed. Failed with error: %v", err)
	}
	// Check if file with encrypted blob is created
	_, err = os.Stat(secrets.SecretPath + secretId)
	if os.IsNotExist(err) {
		t.Errorf("Expected PutSecret to write a file with cipher text blob")
	}

	// PutSecret with already existing secretId
	err = a.s.PutSecret(secretId, nil, nil)
	if err != secrets.ErrSecretExists {
		t.Errorf("Expected PutSecret to fail with ErrSecretExists error")
	}

	// PutSecret with input as a file path which already exists
	err = a.s.PutSecret(secrets.SecretPath+secretId, nil, nil)
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

	// GetSecret using a secretId
	plainText1, err := a.s.GetSecret(secretId, nil)
	if err != nil {
		t.Errorf("Expected GetSecret to succeed. Failed with error: %v", err)
	}
	if plainText1 == nil || len(plainText1) != 1 {
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
	// GetSecret with id as the actual cipherblob
	plainText2, err := a.s.GetSecret(string(cipherBlob), nil)
	if err != nil {
		t.Errorf("Expected GetSecret to succeed. Failed with error: %v", err)
	}
	if plainText2 == nil || len(plainText2) != 1 {
		t.Errorf("Invalid PlainText was returned")
	}

	checkPlainTextEquality(plainText1, plainText2, t)

	// GetSecret with id as a file path where the cipherblob is present
	plainText3, err := a.s.GetSecret(path, nil)
	if err != nil {
		t.Errorf("Expected GetSecret to succeed. Failed with error: %v", err)
	}
	if plainText3 == nil || len(plainText3) != 1 {
		t.Errorf("Invalid PlainText was returned")
	}

	checkPlainTextEquality(plainText1, plainText3, t)
	return nil
}

func checkPlainTextEquality(plainText1, plainText2 map[string]interface{}, t *testing.T) {
	if len(plainText1) != len(plainText2) {
		t.Errorf("Plaintext lengths do no match")
	}
	var (
		pT1, pT2 interface{}
	)
	for _, v := range plainText1 {
		pT1 = v
		break
	}
	for _, v := range plainText2 {
		pT2 = v
		break
	}
	if pT1 == nil || pT2 == nil {
		t.Errorf("Plaintext is null")
	}

	if len(pT1.([]byte)) != len(pT2.([]byte)) {
		t.Errorf("Plain text do not match")
	}
}
