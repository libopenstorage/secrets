package dcos

import (
	"os"
	"testing"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/test"
	"github.com/stretchr/testify/assert"
)

type dcosSecretTest struct {
	s secrets.Secrets
}

func NewDCOSSecretTest(secretConfig map[string]interface{}) (test.SecretTest, error) {
	s, err := New(secretConfig)
	if err != nil {
		return nil, err
	}
	return &dcosSecretTest{s}, nil
}

// TestAll needs the below environment variables to be set to test against
// a enterprise DC/OS cluster as these are integration tests.
func TestAll(t *testing.T) {
	secretConfig := make(map[string]interface{})
	secretConfig[KeyUsername] = os.Getenv("DCOS_SECRETS_TEST_USERNAME")
	secretConfig[KeyPassword] = os.Getenv("DCOS_SECRETS_TEST_PASSWORD")
	secretConfig[KeyDcosURL] = os.Getenv("DCOS_SECRETS_TEST_CLUSTER_URL")

	ds, err := NewDCOSSecretTest(secretConfig)
	if err != nil {
		t.Fatalf("Unable to create a dcos secrets client: %v", err)
	}

	test.Run(ds, t)
}

func (d *dcosSecretTest) TestPutSecret(t *testing.T) error {
	// Test empty secret data
	err := d.s.PutSecret("osd/test/fail1", nil, nil)
	assert.NotNil(t, err)
	assert.Equal(t, secrets.ErrEmptySecretData, err)

	secretData := make(map[string]interface{})
	err = d.s.PutSecret("osd/test/fail2", secretData, nil)
	assert.NotNil(t, err)
	assert.Equal(t, secrets.ErrEmptySecretData, err)

	// Test with data, but no explicit secret store
	secretData["foo"] = "bar"
	secretData["count"] = 10
	err = d.s.PutSecret("osd/test/secret_with_default_store", secretData, nil)
	assert.Nil(t, err)

	// Test with data and explicit secret store
	keyContext := make(map[string]string)
	keyContext[KeySecretStore] = "default"
	err = d.s.PutSecret("osd/test/secret_with_store", secretData, keyContext)
	assert.Nil(t, err)

	return nil
}

func (d *dcosSecretTest) TestGetSecret(t *testing.T) error {
	// Test failure cases
	_, err := d.s.GetSecret("path/does/not/exist", nil)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "does not exist")

	keyContext := make(map[string]string)
	keyContext[KeySecretStore] = "fake"
	_, err = d.s.GetSecret("any/secret/path", keyContext)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "store not found")

	// Test valid secret
	secretData, err := d.s.GetSecret("osd/test/secret_with_default_store", nil)
	assert.Nil(t, err)
	assert.Equal(t, "bar", secretData["foo"])
	assert.Equal(t, float64(10), secretData["count"])

	return nil
}

func (d *dcosSecretTest) TestDeleteSecret(t *testing.T) error {
	return nil
}
