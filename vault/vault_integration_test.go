package vault

import (
	"strings"
	"testing"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/test"
)

func TestAllWithDefaultBackend(t *testing.T) {
	// Set the relevant environment fields for vault.
	vs, err := NewVaultSecretTest(nil)
	if err != nil {
		t.Fatalf("Unable to create a Vault Secret instance: %v", err)
	}
	test.Run(vs, t)
}

func TestAllWithDifferentBackend(t *testing.T) {
	// Set the relevant environment fields for vault.
	secretConfig := map[string]interface{}{
		"VAULT_BACKEND_PATH": "test/secret",
	}

	vs, err := NewVaultSecretTest(secretConfig)
	if err != nil && strings.Contains(err.Error(), "Secrets engine with mount path") {
		t.Fatalf("Please create a kv backend with path 'test/secret' for testing\n" +
			"`vault secrets enable [-version=2] -path=test/secret kv`")
	} else if err != nil {
		t.Fatalf("Unable to create a Vault Secret instance: %v", err)
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

	err = v.s.DeleteSecret(keyId, nil)
	if err != nil {
		t.Fatalf("Unable to delete key: %v %v", keyId, err)
	}
	return nil
}

func (v *vaultSecretTest) TestGetSecret(t *testing.T) error {
	// TestPutSecret does get testing as well
	return nil
}

func (v *vaultSecretTest) TestDeleteSecret(t *testing.T) error {
	// TestPutSecret does delete testing as well
	return nil
}
