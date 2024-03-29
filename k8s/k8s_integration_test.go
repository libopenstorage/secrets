//go:build integration
// +build integration

package k8s

import (
	"testing"
	"time"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/test"
	"github.com/pborman/uuid"
	"github.com/portworx/sched-ops/k8s/core"
	"github.com/stretchr/testify/assert"
	kubernetes "k8s.io/client-go/kubernetes/fake"
)

const (
	secretName = "openstorage-secret-test"
	secretId   = "mysql-username"
)

func TestAll(t *testing.T) {

	fakeKubeClient := kubernetes.NewSimpleClientset()
	core.SetInstance(core.New(fakeKubeClient))

	ks, err := NewK8sSecretTest(nil)
	if err != nil {
		t.Fatalf("Unable to create a Kubernetes Secret instance: %v", err)
		return
	}
	// The secret needs to be created before running the tests
	data := make(map[string][]byte)
	data[secretId] = []byte("passphrase")
	_, err = core.Instance().UpdateSecretData(secretName, "default", data)
	if err != nil {
		t.Fatalf("Failed to get secret for test: %v", err)
		return
	}
	test.Run(ks, t)
}

type k8sSecretTest struct {
	s             secrets.Secrets
	passphrase    string
	secretVersion secrets.Version
}

func NewK8sSecretTest(secretConfig map[string]interface{}) (test.SecretTest, error) {
	s, err := New(secretConfig)
	if err != nil {
		return nil, err
	}
	return &k8sSecretTest{s, "", secrets.NoVersion}, nil
}

func (k *k8sSecretTest) TestPutSecret(t *testing.T) error {
	secretData := make(map[string]interface{})
	k.passphrase = uuid.New()
	secretData[secretId] = k.passphrase
	// PutSecret with non-nil secretData and no namespace should fail
	_, err := k.s.PutSecret(secretName, secretData, nil)
	assert.Error(t, err, "Expected an error on PutSecret")

	keyContext := make(map[string]string)
	keyContext[SecretNamespace] = "default"
	// PutSecret with already existing secretId
	secretVersion, err := k.s.PutSecret(secretName, secretData, keyContext)
	assert.NoError(t, err, "Unexpected error on PutSecret")
	k.secretVersion = secretVersion
	return nil
}

func (k *k8sSecretTest) TestGetSecret(t *testing.T) error {
	secretData, secretVersion, err := k.s.GetSecret(secretName, nil)
	assert.Error(t, err, "Expected an error when no namespace is provided")
	assert.Nil(t, secretData, "Expected empty secret data")
	assert.Equal(t, secrets.NoVersion, secretVersion, "Unexpected secret version")

	keyContext := make(map[string]string)
	keyContext[SecretNamespace] = "default"

	plainText1, secretVersion, err := k.s.GetSecret(secretName, keyContext)
	assert.NoError(t, err, "Expected no error on GetSecret")
	// We have got secretData
	assert.NotNil(t, plainText1, "Invalid plainText was returned")
	v, ok := plainText1[secretId]
	assert.True(t, ok, "Unexpected plainText")
	str, ok := v.(string)
	assert.True(t, ok, "Unexpected plainText")
	assert.Equal(t, k.passphrase, str, "Unexpected passphrase")
	assert.Equal(t, k.secretVersion, secretVersion, "Unexpected secret version")

	return nil
}

func (k *k8sSecretTest) TestDeleteSecret(t *testing.T) error {
	err := k.s.DeleteSecret(secretName, nil)
	assert.Error(t, err, "Expected an error when no namespace is provided")

	keyContext := make(map[string]string)
	keyContext[SecretNamespace] = "default"

	err = k.s.DeleteSecret(secretName, keyContext)
	assert.NoError(t, err, "Unexpected an error on Delete")

	// Get of a deleted secret should fail. Sleeping for the delete to finish
	time.Sleep(2 * time.Second)
	_, _, err = k.s.GetSecret(secretName, keyContext)
	assert.Error(t, err, "Expected error on GetSecret")
	return nil
}

func (k *k8sSecretTest) TestListSecrets(t *testing.T) error {
	ids, err := k.s.ListSecrets()
	assert.Error(t, secrets.ErrNotSupported, err.Error(), "ListSecrets is not supported for k8s secrets")
	assert.Nil(t, ids, "Ids is expected to be nil")
	return nil
}
