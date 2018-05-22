package vault

import (
	"testing"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/test"
)

func TestAll(t *testing.T) {
	// Set the relevant environment fields for vault.
	vs, err := NewVaultSecretTest(nil)
	if err != nil {
		t.Fatalf("Unable to create a Vault Secret instance: %v", err)
		return
	}
	test.Run(vs, t)
}

type vaultSecretTest struct {
	s secrets.Secrets
}

func NewVaultSecretTest(secretConfig map[string]interface{}) (test.SecretTest, error) {
	s, err := New(secretConfig)
	if err != nil {
		return nil, err
	}
	return &vaultSecretTest{s}, nil
}

func (v *vaultSecretTest) TestPutSecret(t *testing.T) error {
	data := make(map[string]interface{})
	keyId := "hello"
	data["key1"] = "value1"
	data["key2"] = "value2"

	if v.s == nil {
		t.Fatalf("secrets is nil")
	}
	err := v.s.PutSecret(keyId, data, nil)
	if err != nil {
		t.Fatalf("Unable to put key into secrets: %v", err)
	}

	plainText, err := v.s.GetSecret(keyId, nil)
	if err != nil {
		t.Fatalf("Unable to get key from secrets: %v", err)
	}
	if len(data) != len(plainText) {
		t.Errorf("Put and Get keys do not match")
	}
	for k, v := range plainText {
		if o, exists := data[k]; !exists || o != v {
			t.Errorf("Put and Get values do not match")
		}
	}
	_, err = v.s.GetSecret("unknown_key", nil)
	if err == nil {
		t.Fatalf("Expected error when no secret key present")
	}
	return nil
}

func (v *vaultSecretTest) TestGetSecret(t *testing.T) error {
	// TestPutSecret does get testing as well
	return nil
}
