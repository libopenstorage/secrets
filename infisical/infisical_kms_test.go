package infisical

import (
	"errors"
	"testing"

	"github.com/libopenstorage/secrets"
	"github.com/portworx/kvdb"
	memkv "github.com/portworx/kvdb/mem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePersistenceStore is a minimal, in-memory implementation of
// store.PersistenceStore used exclusively in unit tests.
type fakePersistenceStore struct {
	data map[string][]byte
}

func newFakePersistenceStore() *fakePersistenceStore {
	return &fakePersistenceStore{data: make(map[string][]byte)}
}

func (f *fakePersistenceStore) GetPublic(secretId string) ([]byte, error) {
	v, ok := f.data[secretId]
	if !ok {
		return nil, secrets.ErrInvalidSecretId
	}
	return v, nil
}

func (f *fakePersistenceStore) GetSecretData(_ string, _ []byte) (map[string]interface{}, error) {
	return nil, secrets.ErrNotSupported
}

func (f *fakePersistenceStore) Exists(secretId string) (bool, error) {
	_, ok := f.data[secretId]
	return ok, nil
}

func (f *fakePersistenceStore) Set(secretId string, cipher, _ []byte, _ map[string]interface{}, override bool) error {
	if _, exists := f.data[secretId]; exists && !override {
		return secrets.ErrSecretExists
	}
	f.data[secretId] = cipher
	return nil
}

func (f *fakePersistenceStore) Delete(secretId string) error {
	delete(f.data, secretId)
	return nil
}

func (f *fakePersistenceStore) Name() string { return "fake" }

func (f *fakePersistenceStore) List() ([]string, error) {
	ids := make([]string, 0, len(f.data))
	for k := range f.data {
		ids = append(ids, k)
	}
	return ids, nil
}

type fakeClient struct {
	encryptFn func(plaintext string) (string, error)
	decryptFn func(ciphertext string) (string, error)
}

func (f *fakeClient) encrypt(plaintext string) (string, error) {
	return f.encryptFn(plaintext)
}

func (f *fakeClient) decrypt(ciphertext string) (string, error) {
	return f.decryptFn(ciphertext)
}

func newTestBackend(
	enc func(string) (string, error),
	dec func(string) (string, error),
) *infisicalKms {
	return &infisicalKms{
		client: &fakeClient{encryptFn: enc, decryptFn: dec},
		ps:     newFakePersistenceStore(),
	}
}

func newMemKvdb(t *testing.T) kvdb.Kvdb {
	t.Helper()
	kv, err := memkv.New("test", nil, nil, nil)
	require.NoError(t, err)
	return kv
}

// ---------------------------------------------------------------------------
// New() – error path tests
// ---------------------------------------------------------------------------

func TestNew_MissingKvdb(t *testing.T) {
	_, err := New(map[string]interface{}{
		ClientIDKey:     "x",
		ClientSecretKey: "x",
		KMSKeyIDKey:     "x",
	})
	assert.ErrorIs(t, err, ErrKvdbNotProvided)
}

func TestNew_WrongKvdbType(t *testing.T) {
	_, err := New(map[string]interface{}{
		KvdbKey:         "not-a-kvdb-instance",
		ClientIDKey:     "x",
		ClientSecretKey: "x",
		KMSKeyIDKey:     "x",
	})
	assert.ErrorIs(t, err, ErrKvdbNotProvided)
}

func TestNew_MissingClientID(t *testing.T) {
	t.Setenv(ClientIDKey, "")
	_, err := New(map[string]interface{}{
		KvdbKey:         newMemKvdb(t),
		ClientSecretKey: "x",
		KMSKeyIDKey:     "x",
	})
	assert.ErrorIs(t, err, ErrClientIDRequired)
}

func TestNew_MissingClientSecret(t *testing.T) {
	t.Setenv(ClientSecretKey, "")
	_, err := New(map[string]interface{}{
		KvdbKey:     newMemKvdb(t),
		ClientIDKey: "x",
		KMSKeyIDKey: "x",
	})
	assert.ErrorIs(t, err, ErrClientSecretRequired)
}

func TestNew_RejectsHTTPSiteURL(t *testing.T) {
	_, err := New(map[string]interface{}{
		KvdbKey:         newMemKvdb(t),
		SiteURLKey:      "http://infisical.internal",
		ClientIDKey:     "x",
		ClientSecretKey: "x",
		KMSKeyIDKey:     "x",
	})
	assert.ErrorIs(t, err, ErrInsecureSiteURL)
}

func TestNew_RejectsInvalidSiteURL(t *testing.T) {
	_, err := New(map[string]interface{}{
		KvdbKey:         newMemKvdb(t),
		SiteURLKey:      "not a url",
		ClientIDKey:     "x",
		ClientSecretKey: "x",
		KMSKeyIDKey:     "x",
	})
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrClientIDRequired)
}

func TestNew_MissingKMSKeyID(t *testing.T) {
	t.Setenv(KMSKeyIDKey, "")
	_, err := New(map[string]interface{}{
		KvdbKey:         newMemKvdb(t),
		ClientIDKey:     "x",
		ClientSecretKey: "x",
	})
	assert.ErrorIs(t, err, ErrKMSKeyIDRequired)
}

// ---------------------------------------------------------------------------
// PutSecret tests
// ---------------------------------------------------------------------------

func customCtx() map[string]string {
	return map[string]string{secrets.CustomSecretData: "true"}
}

func publicCtx() map[string]string {
	return map[string]string{secrets.PublicSecretData: "true"}
}

func TestPutSecret_HappyPath(t *testing.T) {
	k := newTestBackend(
		func(plaintext string) (string, error) {
			return "encrypted-blob", nil
		},
		nil,
	)

	ver, err := k.PutSecret("my-secret", map[string]interface{}{"password": "hunter2"}, customCtx())
	require.NoError(t, err)
	assert.Equal(t, secrets.NoVersion, ver)

	stored, err := k.ps.GetPublic("my-secret")
	require.NoError(t, err)
	assert.Equal(t, "encrypted-blob", string(stored))
}

func TestPutSecret_EmptySecretId(t *testing.T) {
	k := newTestBackend(nil, nil)
	_, err := k.PutSecret("", map[string]interface{}{"x": "y"}, customCtx())
	assert.ErrorIs(t, err, secrets.ErrEmptySecretId)
}

func TestPutSecret_NoFlagWithData(t *testing.T) {
	k := newTestBackend(nil, nil)
	_, err := k.PutSecret("my-secret", map[string]interface{}{"x": "y"}, nil)
	var kcErr *secrets.ErrInvalidKeyContext
	assert.ErrorAs(t, err, &kcErr)
}

func TestPutSecret_CustomDataWithoutData(t *testing.T) {
	k := newTestBackend(nil, nil)
	_, err := k.PutSecret("my-secret", map[string]interface{}{}, customCtx())
	var kcErr *secrets.ErrInvalidKeyContext
	assert.ErrorAs(t, err, &kcErr)
}

func TestPutSecret_BothFlagsSet(t *testing.T) {
	k := newTestBackend(nil, nil)
	_, err := k.PutSecret("my-secret", map[string]interface{}{"x": "y"}, map[string]string{
		secrets.CustomSecretData: "true",
		secrets.PublicSecretData: "true",
	})
	var kcErr *secrets.ErrInvalidKeyContext
	assert.ErrorAs(t, err, &kcErr)
}

func TestPutSecret_PublicData(t *testing.T) {
	encryptCalled := false
	k := newTestBackend(
		func(_ string) (string, error) {
			encryptCalled = true
			return "should-not-be-called", nil
		},
		nil,
	)

	raw := []byte("opaque-ciphertext-bytes")
	_, err := k.PutSecret("my-secret",
		map[string]interface{}{"my-secret": raw}, publicCtx())
	require.NoError(t, err)
	assert.False(t, encryptCalled, "PublicSecretData must not invoke encrypt")

	stored, err := k.ps.GetPublic("my-secret")
	require.NoError(t, err)
	assert.Equal(t, raw, stored)
}

func TestPutSecret_PublicData_NotByteSlice(t *testing.T) {
	k := newTestBackend(nil, nil)
	_, err := k.PutSecret("my-secret",
		map[string]interface{}{"my-secret": "a-string-not-bytes"}, publicCtx())
	var kcErr *secrets.ErrInvalidKeyContext
	assert.ErrorAs(t, err, &kcErr)
}

func TestPutSecret_PublicData_MissingSecretIdKey(t *testing.T) {
	k := newTestBackend(nil, nil)
	_, err := k.PutSecret("my-secret",
		map[string]interface{}{"other-key": []byte("x")}, publicCtx())
	assert.ErrorIs(t, err, secrets.ErrInvalidSecretData)
}

func TestPutSecret_EncryptError(t *testing.T) {
	encErr := errors.New("kms unavailable")
	k := newTestBackend(
		func(_ string) (string, error) { return "", encErr },
		nil,
	)
	_, err := k.PutSecret("my-secret", map[string]interface{}{"x": "y"}, customCtx())
	require.Error(t, err)
	assert.ErrorContains(t, err, "encryption failed")
}

func TestPutSecret_DuplicateWithoutOverride(t *testing.T) {
	k := newTestBackend(
		func(_ string) (string, error) { return "blob", nil },
		nil,
	)
	_, err := k.PutSecret("my-secret", map[string]interface{}{"x": "y"}, customCtx())
	require.NoError(t, err)

	_, err = k.PutSecret("my-secret", map[string]interface{}{"x": "z"}, customCtx())
	assert.ErrorIs(t, err, secrets.ErrSecretExists)
}

func TestPutSecret_OverwriteWithOverride(t *testing.T) {
	k := newTestBackend(
		func(_ string) (string, error) { return "new-blob", nil },
		nil,
	)
	_ = k.ps.Set("my-secret", []byte("old-blob"), nil, nil, false)

	_, err := k.PutSecret("my-secret", map[string]interface{}{"x": "z"},
		map[string]string{
			secrets.OverwriteSecretDataInStore: "true",
			secrets.CustomSecretData:           "true",
		})
	require.NoError(t, err)

	stored, _ := k.ps.GetPublic("my-secret")
	assert.Equal(t, "new-blob", string(stored))
}

// ---------------------------------------------------------------------------
// GetSecret tests
// ---------------------------------------------------------------------------

func TestGetSecret_HappyPath(t *testing.T) {
	k := newTestBackend(
		func(_ string) (string, error) { return "ct", nil },
		func(ciphertext string) (string, error) {
			assert.Equal(t, "ct", ciphertext)
			return `{"password":"hunter2"}`, nil
		},
	)

	_, _ = k.PutSecret("my-secret", map[string]interface{}{"password": "hunter2"}, customCtx())

	result, ver, err := k.GetSecret("my-secret", customCtx())
	require.NoError(t, err)
	assert.Equal(t, secrets.NoVersion, ver)
	assert.Equal(t, "hunter2", result["password"])
}

func TestGetSecret_EmptySecretId(t *testing.T) {
	k := newTestBackend(nil, nil)
	_, _, err := k.GetSecret("", nil)
	assert.ErrorIs(t, err, secrets.ErrEmptySecretId)
}

func TestGetSecret_NotFound(t *testing.T) {
	k := newTestBackend(nil, nil)
	_, _, err := k.GetSecret("nonexistent", customCtx())
	assert.ErrorIs(t, err, secrets.ErrInvalidSecretId)
}

func TestGetSecret_BothFlagsSet(t *testing.T) {
	k := newTestBackend(nil, nil)
	_, _, err := k.GetSecret("my-secret", map[string]string{
		secrets.CustomSecretData: "true",
		secrets.PublicSecretData: "true",
	})
	var kcErr *secrets.ErrInvalidKeyContext
	assert.ErrorAs(t, err, &kcErr)
}

func TestGetSecret_NoFlag_ReturnsPlaintextString(t *testing.T) {
	k := newTestBackend(
		func(_ string) (string, error) { return "ct", nil },
		func(_ string) (string, error) { return "the-plaintext", nil },
	)
	_, _ = k.PutSecret("my-secret", map[string]interface{}{"x": "y"}, customCtx())

	result, _, err := k.GetSecret("my-secret", nil)
	require.NoError(t, err)
	assert.Equal(t, "the-plaintext", result["my-secret"])
}

func TestGetSecret_PublicData(t *testing.T) {
	decryptCalled := false
	k := newTestBackend(
		nil,
		func(_ string) (string, error) {
			decryptCalled = true
			return "", nil
		},
	)
	raw := []byte("opaque-ciphertext-bytes")
	_, err := k.PutSecret("my-secret", map[string]interface{}{"my-secret": raw}, publicCtx())
	require.NoError(t, err)

	result, _, err := k.GetSecret("my-secret", publicCtx())
	require.NoError(t, err)
	assert.False(t, decryptCalled, "PublicSecretData must not invoke decrypt")
	assert.Equal(t, raw, result["my-secret"])
}

func TestGetSecret_DecryptError(t *testing.T) {
	decErr := errors.New("kms unavailable")
	k := newTestBackend(
		func(_ string) (string, error) { return "ct", nil },
		func(_ string) (string, error) { return "", decErr },
	)
	_, _ = k.PutSecret("my-secret", map[string]interface{}{"x": "y"}, customCtx())

	_, _, err := k.GetSecret("my-secret", customCtx())
	require.Error(t, err)
	assert.ErrorContains(t, err, "decryption failed")
}

func TestGetSecret_RoundTrip(t *testing.T) {
	original := map[string]interface{}{
		"key":    "my-passphrase",
		"number": float64(42),
	}

	var capturedPlaintext string
	k := newTestBackend(
		func(plaintext string) (string, error) {
			capturedPlaintext = plaintext
			return "ct", nil
		},
		func(_ string) (string, error) {
			return capturedPlaintext, nil
		},
	)

	_, err := k.PutSecret("rtrip", original, customCtx())
	require.NoError(t, err)

	result, _, err := k.GetSecret("rtrip", customCtx())
	require.NoError(t, err)
	assert.Equal(t, original, result)
}

// ---------------------------------------------------------------------------
// DeleteSecret tests
// ---------------------------------------------------------------------------

func TestDeleteSecret_HappyPath(t *testing.T) {
	k := newTestBackend(
		func(_ string) (string, error) { return "ct", nil },
		nil,
	)
	_, _ = k.PutSecret("my-secret", map[string]interface{}{"x": "y"}, customCtx())

	err := k.DeleteSecret("my-secret", nil)
	require.NoError(t, err)

	_, _, err = k.GetSecret("my-secret", nil)
	assert.ErrorIs(t, err, secrets.ErrInvalidSecretId)
}

func TestDeleteSecret_EmptySecretId(t *testing.T) {
	k := newTestBackend(nil, nil)
	err := k.DeleteSecret("", nil)
	assert.ErrorIs(t, err, secrets.ErrEmptySecretId)
}

func TestDeleteSecret_Idempotent(t *testing.T) {
	k := newTestBackend(nil, nil)
	err := k.DeleteSecret("does-not-exist", nil)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// ListSecrets tests
// ---------------------------------------------------------------------------

func TestListSecrets(t *testing.T) {
	k := newTestBackend(
		func(_ string) (string, error) { return "ct", nil },
		nil,
	)
	_, _ = k.PutSecret("secret-a", map[string]interface{}{"x": "y"}, customCtx())
	_, _ = k.PutSecret("secret-b", map[string]interface{}{"x": "y"}, customCtx())

	ids, err := k.ListSecrets()
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"secret-a", "secret-b"}, ids)
}

func TestListSecrets_Empty(t *testing.T) {
	k := newTestBackend(nil, nil)
	ids, err := k.ListSecrets()
	require.NoError(t, err)
	assert.Empty(t, ids)
}

// ---------------------------------------------------------------------------
// Unsupported methods
// ---------------------------------------------------------------------------

func TestEncrypt_NotSupported(t *testing.T) {
	k := newTestBackend(nil, nil)
	_, err := k.Encrypt("id", "data", nil)
	assert.ErrorIs(t, err, secrets.ErrNotSupported)
}

func TestDecrypt_NotSupported(t *testing.T) {
	k := newTestBackend(nil, nil)
	_, err := k.Decrypt("id", "data", nil)
	assert.ErrorIs(t, err, secrets.ErrNotSupported)
}

func TestRencrypt_NotSupported(t *testing.T) {
	k := newTestBackend(nil, nil)
	_, err := k.Rencrypt("a", "b", nil, nil, "data")
	assert.ErrorIs(t, err, secrets.ErrNotSupported)
}

// ---------------------------------------------------------------------------
// String()
// ---------------------------------------------------------------------------

func TestString(t *testing.T) {
	k := newTestBackend(nil, nil)
	assert.Equal(t, "infisical-kms", k.String())
}

// ---------------------------------------------------------------------------
// configString helper
// ---------------------------------------------------------------------------

func TestConfigString_ConfigTakesPrecedence(t *testing.T) {
	t.Setenv("MY_KEY", "from-env")
	result := configString(map[string]interface{}{"MY_KEY": "from-config"}, "MY_KEY", "fallback")
	assert.Equal(t, "from-config", result)
}

func TestConfigString_EnvFallback(t *testing.T) {
	t.Setenv("MY_KEY", "from-env")
	result := configString(nil, "MY_KEY", "fallback")
	assert.Equal(t, "from-env", result)
}

func TestConfigString_Default(t *testing.T) {
	t.Setenv("MY_KEY", "")
	result := configString(nil, "MY_KEY", "fallback")
	assert.Equal(t, "fallback", result)
}
