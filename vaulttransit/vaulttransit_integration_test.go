// +build integration

package vaulttransit

import (
	"fmt"
	"github.com/libopenstorage/secrets/vaulttransit/client/transit"
	"os"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/test"
	"github.com/pborman/uuid"
	"github.com/portworx/kvdb"
	"github.com/portworx/kvdb/mem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testSecretIdWithPassphrase = "openstorage_secret_with_passphrase"
	testSecretId               = "openstorage_secret"
	testSecretIdWithPublic     = "openstorage_secret_with_public"
)

func setupVaultClient() (*api.Client, error) {
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, err
	}
	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("VAULT_TOKEN should be provided")
	}
	client.SetToken(token)
	return client, nil
}

func setupVaultTransitSecrets() (secrets.Secrets, error) {
	secretConfig := make(map[string]interface{})

	// With kvdbPersistenceStore
	kv, err := kvdb.New(mem.Name, "openstorage/", nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Unable to create a Vault Transit Secret instance: %v", err)
	}
	secretConfig[TransitKvdbKey] = kv
	kp, err := New(secretConfig)
	if err != nil {
		return nil, fmt.Errorf("Unable to create a Vault Transit Secret instance: %v", err)
	}

	return kp, nil
}

func TestAll(t *testing.T) {
	vs, err := setupVaultTransitSecrets()
	if err != nil {
		t.Fatal(err)
		return
	}
	vt := &vaultTransitSecretTest{
		s:          vs,
		passphrase: "",
		totalPuts:  0,
	}
	test.Run(vt, t)

}

type vaultTransitSecretTest struct {
	s           secrets.Secrets
	vaultClient *api.Client
	passphrase  string
	totalPuts   int
}

func (v *vaultTransitSecretTest) TestPutSecret(t *testing.T) error {
	secretData := make(map[string]interface{})
	v.passphrase = uuid.New()
	secretData[testSecretIdWithPassphrase] = v.passphrase

	// PutSecret with non-nil secretData and no key context
	err := v.s.PutSecret(testSecretIdWithPassphrase, secretData, nil)
	assert.Error(t, err, "Expected error on PutSecret")
	errInvalidContext, ok := err.(*secrets.ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "when none of", "Unexpected error on PutSecret")

	keyContext := make(map[string]string)
	keyContext[secrets.CustomSecretData] = "true"

	// PutSecret with nil secretData and key context
	err = v.s.PutSecret(testSecretIdWithPassphrase, nil, keyContext)
	errInvalidContext, ok = err.(*secrets.ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "secret data needs to be provided", "Unexpected error on PutSecret")

	// Successful PutSecret with custom secret data
	err = v.s.PutSecret(testSecretIdWithPassphrase, secretData, keyContext)
	assert.NoError(t, err, "Unexpected error on PutSecret")
	v.totalPuts++

	// PutSecret with nil secretData
	err = v.s.PutSecret(testSecretId, nil, nil)
	assert.NoError(t, err, "Unexpected error on PutSecret")
	v.totalPuts++

	// Both CustomSecretData and PublicSecretData cannot be set
	keyContext[secrets.PublicSecretData] = "true"
	err = v.s.PutSecret(testSecretIdWithPublic, nil, keyContext)
	errInvalidContext, ok = err.(*secrets.ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "both", "Unexpected error on PutSecret")

	delete(keyContext, secrets.CustomSecretData)

	// PublicSecretData with no data
	err = v.s.PutSecret(testSecretIdWithPublic, nil, keyContext)
	errInvalidContext, ok = err.(*secrets.ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "secret data needs to be provided", "Unexpected error on PutSecret")

	// Successful PutSecret with PublicSecretData
	getKC := make(map[string]string)
	getKC[secrets.PublicSecretData] = "true"
	secretData, err = v.s.GetSecret(testSecretId, getKC)
	assert.NoError(t, err, "Get %s secret", testSecretId)
	dek := secretData[testSecretId]
	putSecretData := make(map[string]interface{})
	putSecretData[testSecretIdWithPublic] = dek
	err = v.s.PutSecret(testSecretIdWithPublic, putSecretData, keyContext)
	assert.NoError(t, err, "Unexpected error on PutSecret")
	v.totalPuts++
	return nil
}

func (v *vaultTransitSecretTest) TestGetSecret(t *testing.T) error {
	// GetSecret with non-existant id
	_, err := v.s.GetSecret("dummy", nil)
	assert.Error(t, err, "Expected GetSecret to fail")

	// GetSecret using a secretId with data
	keyContext := make(map[string]string)
	keyContext[secrets.CustomSecretData] = "true"
	plainText1, err := v.s.GetSecret(testSecretIdWithPassphrase, keyContext)
	assert.NoError(t, err, "Unexpected error on GetSecret")
	// We have got secretData
	assert.NotNil(t, plainText1, "Invalid plainText was returned")
	value, ok := plainText1[testSecretIdWithPassphrase]
	assert.True(t, ok, "Unexpected plainText")
	str, ok := value.(string)
	assert.True(t, ok, "Unexpected plainText")
	assert.Equal(t, str, v.passphrase, "Unexpected passphrase")

	// GetSecret using a secretId without data
	_, err = v.s.GetSecret(testSecretId, nil)
	assert.NoError(t, err, "Unexpected error on GetSecret")

	// Both the flags are set
	keyContext[secrets.PublicSecretData] = "true"
	_, err = v.s.GetSecret(testSecretIdWithPublic, keyContext)
	errInvalidContext, ok := err.(*secrets.ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "both", "Unexpected error on PutSecret")

	// GetSecret using the secretID for public
	delete(keyContext, secrets.CustomSecretData)

	// deks for both secrets should match
	sec1, err := v.s.GetSecret(testSecretId, keyContext)
	assert.NoError(t, err, "Unexpected error on GetSecret")
	dek1, ok := sec1[testSecretId]
	assert.True(t, ok, "Unexpected secret returned")

	sec2, err := v.s.GetSecret(testSecretIdWithPublic, keyContext)
	assert.NoError(t, err, "Unexpected error on GetSecret")
	dek2, ok := sec2[testSecretIdWithPublic]
	assert.True(t, ok, "Unexpected secret returned")

	assert.Equal(t, dek1, dek2, "Unequal secrets returned.")
	return nil
}

func (v *vaultTransitSecretTest) TestDeleteSecret(t *testing.T) error {
	// Delete of a key that exists should succeed
	err := v.s.DeleteSecret(testSecretId, nil)
	assert.NoError(t, err, "Unexpected error on DeleteSecret")

	// Get of a deleted key should fail
	_, err = v.s.GetSecret(testSecretId, nil)
	assert.EqualError(t, secrets.ErrInvalidSecretId, err.Error(), "Expected an error on GetSecret after the key is deleted")

	// Delete of a non-existent key should also succeed
	err = v.s.DeleteSecret("dummy", nil)
	assert.NoError(t, err, "Unepxected error on DeleteSecret")
	return nil
}

func (v *vaultTransitSecretTest) TestListSecrets(t *testing.T) error {
	ids, err := v.s.ListSecrets()
	assert.NoError(t, err, "Unexpected error on ListSecrets")
	assert.Equal(t, len(ids), v.totalPuts, "Unexpected number of secrets listed")
	return nil
}

func TestEnsureEncryptinKey(t *testing.T) {
	vaultClient, err := setupVaultClient()
	require.Nil(t, err)

	vaultTransit, err := transit.New(vaultClient.Logical())
	require.Nil(t, err)

	// create an encryption key if not provided
	encryptionKey, err := ensureEncryptionKey(vaultClient, "", "")
	require.Nil(t, err)
	require.Equal(t, defaultPxEncryptionKey, encryptionKey)

	s, err := vaultTransit.Read(transit.SecretKey{Name: defaultPxEncryptionKey})
	require.Nil(t, err)
	require.NotNil(t, s)

	err = vaultTransit.Delete(transit.SecretKey{Name: defaultPxEncryptionKey})
	require.Nil(t, err)

	// check existing key key
	testKey := "test-encryption-key"
	_, err = vaultTransit.Create(transit.SecretKey{Name: testKey}, "")
	require.Nil(t, err)

	encryptionKey, err = ensureEncryptionKey(vaultClient, testKey, "")
	require.Nil(t, err)
	require.Equal(t, testKey, encryptionKey)

	s, err = vaultTransit.Read(transit.SecretKey{Name: testKey})
	require.Nil(t, err)
	require.NotNil(t, s)

	err = vaultTransit.Delete(transit.SecretKey{Name: testKey})
	require.Nil(t, err)

	// check existing key key: not found
	testKey1 := "test-encryption-key1"

	s, err = vaultTransit.Read(transit.SecretKey{Name: testKey1})
	require.Nil(t, s)
	require.NotNil(t, err)

	encryptionKey, err = ensureEncryptionKey(vaultClient, testKey1, "")
	require.NotNil(t, err)
	require.Equal(t, encryptionKey, "")
}
