package k8s

import (
	"io/ioutil"
	"testing"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/test"
)

func TestAll(t *testing.T) {
	ks, err := NewK8sSecretTest(nil)
	if err != nil {
		t.Fatalf("Unable to create a Kubernetes Secret instance: %v", err)
		return
	}
	test.Run(ks, t)
}

type k8sSecretTest struct {
	s secrets.Secrets
}

func NewK8sSecretTest(secretConfig map[string]interface{}) (test.SecretTest, error) {
	s, err := New(secretConfig)
	if err != nil {
		return nil, err
	}
	return &k8sSecretTest{s}, nil
}

// PutSecret is not yet implemented
func (k *k8sSecretTest) TestPutSecret(t *testing.T) error {
	return nil
}

func (k *k8sSecretTest) TestGetSecret(t *testing.T) error {
	secretId := "mysql_username"
	cipherBlob := []byte{116, 101, 115, 116}
	err := ioutil.WriteFile(getSecretKey(secretId), cipherBlob, 0644)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	secretData, err := k.s.GetSecret(secretId, nil)
	if err != nil {
		t.Errorf("Unexpected error in GetSecret: %v", err)
	}
	if len(secretData) == 0 {
		t.Errorf("GetSecret returned invalid data.")
	}
	secretBlob, ok := secretData[secretId]
	if !ok {
		t.Errorf("GetSecret returned invalid data")
	}

	if len(secretBlob.([]byte)) != len(cipherBlob) {
		t.Errorf("Cipher texts do not match")
	}

	return nil
}
