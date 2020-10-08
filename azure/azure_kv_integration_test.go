// +build integration

package azure

import (
	"testing"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/test"
	"github.com/stretchr/testify/assert"
)

const (
	testkey    = "test-kv-key"
	testsecret = "test-kv-secret"
)

type azureSecretsTest struct {
	s secrets.Secrets
}

func TestAll(t *testing.T) {

	config := make(map[string]interface{})
	az, err := NewAzureKVSecretTest(config)
	assert.Nil(t, err)
	assert.NotNil(t, az)
	test.Run(az, t)
}

func NewAzureKVSecretTest(secretConfig map[string]interface{}) (test.SecretTest, error) {
	s, err := New(secretConfig)
	if err != nil {
		return nil, err
	}
	return &azureSecretsTest{s}, nil
}

func (a *azureSecretsTest) TestPutSecret(t *testing.T) error {
	secretData := make(map[string]interface{})
	// PutSecret should be successfull
	err := a.s.PutSecret(testkey, secretData, nil)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Secret data cannot be empty", "Unexpected error on PutSecret")

	secretData["testcred"] = "test-cred"
	secretData["testval"] = 10
	secretData["testzone"] = "azure--dummy"

	// PutSecret should be successfull
	err = a.s.PutSecret(testkey, secretData, nil)
	assert.Nil(t, err)

	// Since azure allow to set multiple version of same secrets
	// make sure you are getting same secret ID after resetting

	secretData[testkey] = testsecret
	err = a.s.PutSecret(testkey, secretData, nil)
	assert.Nil(t, err)

	resp, err := a.s.GetSecret(testkey, nil)
	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, resp["testcred"].(string), "test-cred")

	// clean up
	err = a.s.DeleteSecret(testkey, nil)
	assert.Nil(t, err)

	// try to get secret again, should return err
	resp, err = a.s.GetSecret(testkey, nil)
	assert.Error(t, err, "Expected secret to fail for non-existant key")

	return nil
}

func (a *azureSecretsTest) TestGetSecret(t *testing.T) error {
	// GetSecret with non-existant id
	_, err := a.s.GetSecret("dummy", nil)
	assert.Error(t, err, "Expected GetSecret to fail")

	_, err = a.s.GetSecret("", nil)
	assert.Error(t, err, "Secret Name/ID cannot be empty")

	secretData := make(map[string]interface{})
	secretData["testcred"] = "test-cred"
	secretData["testval"] = 10
	secretData["testzone"] = "azure--dummy"

	err = a.s.PutSecret(testkey, secretData, nil)
	assert.Nil(t, err)

	resp, err := a.s.GetSecret(testkey, nil)
	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, resp["testzone"].(string), "azure--dummy")

	// clean up
	err = a.s.DeleteSecret(testkey, nil)
	assert.Nil(t, err)

	return nil
}

func (a *azureSecretsTest) TestDeleteSecret(t *testing.T) error {
	// Already Tested in PutSecret And GetSecret tests
	return nil
}

func (a *azureSecretsTest) TestListSecrets(t *testing.T) error {
	ids, err := a.s.ListSecrets()
	assert.Error(t, secrets.ErrNotSupported, err.Error(), "ListSecrets is not supported for azure KV")
	assert.Nil(t, ids, "Ids is expected to be nil")
	return nil
}
