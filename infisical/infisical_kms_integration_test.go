//go:build integration

package infisical

import (
	"fmt"
	"os"
	"testing"

	"github.com/libopenstorage/secrets"
	memkv "github.com/portworx/kvdb/mem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func requiredEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if os.Getenv(k) == "" {
			t.Skipf("skipping integration test: env var %s is not set", k)
		}
	}
}

func newIntegrationBackend(t *testing.T) secrets.Secrets {
	t.Helper()
	requiredEnv(t,
		SiteURLKey,
		ClientIDKey,
		ClientSecretKey,
		KMSKeyIDKey,
	)

	kv, err := memkv.New("integration-test", nil, nil, nil)
	require.NoError(t, err)

	s, err := New(map[string]interface{}{
		KvdbKey: kv,
	})
	require.NoError(t, err, "New() should succeed with valid env config")
	return s
}

func uniqueID(t *testing.T, suffix string) string {
	return fmt.Sprintf("integration-test-%s-%s", t.Name(), suffix)
}

func TestIntegration_FullLifecycle(t *testing.T) {
	s := newIntegrationBackend(t)
	secretID := uniqueID(t, "lifecycle")

	original := map[string]interface{}{
		"passphrase": "super-secret-value",
		"extra":      "metadata",
	}

	t.Run("PutSecret", func(t *testing.T) {
		ver, err := s.PutSecret(secretID, original, nil)
		require.NoError(t, err)
		assert.Equal(t, secrets.NoVersion, ver)
	})

	t.Run("GetSecret", func(t *testing.T) {
		result, ver, err := s.GetSecret(secretID, nil)
		require.NoError(t, err)
		assert.Equal(t, secrets.NoVersion, ver)
		assert.Equal(t, original["passphrase"], result["passphrase"])
		assert.Equal(t, original["extra"], result["extra"])
	})

	t.Run("ListSecrets_Contains", func(t *testing.T) {
		ids, err := s.ListSecrets()
		require.NoError(t, err)
		assert.Contains(t, ids, secretID)
	})

	t.Run("DeleteSecret", func(t *testing.T) {
		err := s.DeleteSecret(secretID, nil)
		require.NoError(t, err)
	})

	t.Run("GetSecret_AfterDelete", func(t *testing.T) {
		_, _, err := s.GetSecret(secretID, nil)
		assert.ErrorIs(t, err, secrets.ErrInvalidSecretId)
	})

	t.Run("ListSecrets_NotContains_AfterDelete", func(t *testing.T) {
		ids, err := s.ListSecrets()
		require.NoError(t, err)
		assert.NotContains(t, ids, secretID)
	})
}

func TestIntegration_MultipleSecrets(t *testing.T) {
	s := newIntegrationBackend(t)

	entries := []struct {
		id   string
		data map[string]interface{}
	}{
		{uniqueID(t, "s1"), map[string]interface{}{"vol": "disk1"}},
		{uniqueID(t, "s2"), map[string]interface{}{"vol": "disk2"}},
		{uniqueID(t, "s3"), map[string]interface{}{"vol": "disk3"}},
	}

	for _, e := range entries {
		_, err := s.PutSecret(e.id, e.data, nil)
		require.NoError(t, err)
	}

	for _, e := range entries {
		result, _, err := s.GetSecret(e.id, nil)
		require.NoError(t, err)
		assert.Equal(t, e.data["vol"], result["vol"])
	}

	for _, e := range entries {
		require.NoError(t, s.DeleteSecret(e.id, nil))
	}
}

func TestIntegration_Overwrite(t *testing.T) {
	s := newIntegrationBackend(t)
	id := uniqueID(t, "overwrite")

	_, err := s.PutSecret(id, map[string]interface{}{"v": "original"}, nil)
	require.NoError(t, err)

	_, err = s.PutSecret(id, map[string]interface{}{"v": "new"}, nil)
	require.Error(t, err)
	assert.ErrorContains(t, err, "already exists")

	_, err = s.PutSecret(id, map[string]interface{}{"v": "updated"},
		map[string]string{secrets.OverwriteSecretDataInStore: "true"})
	require.NoError(t, err)

	result, _, err := s.GetSecret(id, nil)
	require.NoError(t, err)
	assert.Equal(t, "updated", result["v"])

	_ = s.DeleteSecret(id, nil)
}

func TestIntegration_Unsupported(t *testing.T) {
	s := newIntegrationBackend(t)

	_, err := s.Encrypt("id", "plaintext", nil)
	assert.ErrorIs(t, err, secrets.ErrNotSupported)

	_, err = s.Decrypt("id", "ciphertext", nil)
	assert.ErrorIs(t, err, secrets.ErrNotSupported)

	_, err = s.Rencrypt("a", "b", nil, nil, "data")
	assert.ErrorIs(t, err, secrets.ErrNotSupported)
}
