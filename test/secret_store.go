package test

import (
	"context"
	"testing"

	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/libopenstorage/secrets"
)

type storeTest struct {
	s                   secrets.SecretStore
	secretPrefix        string
	secretIdWithData    string
	secretIdWithoutData string
}

func RunForStore(store secrets.SecretStore, t *testing.T) {
	st := &storeTest{
		s:                   store,
		secretPrefix:        "openstorage_secret_prefix_" + uuid.New(),
		secretIdWithData:    "openstorage_secret_data_" + uuid.New(),
		secretIdWithoutData: "openstorage_secret_" + uuid.New(),
	}

	st.TestPutSecret(t)
	st.TestGetSecret(t)
	st.TestDeleteSecret(t)
}

func (a *storeTest) TestPutSecret(t *testing.T) {
	secretData := make(map[string]interface{})
	secretData["key1"] = "value1"
	secretData["key2"] = "value2"
	// Set with non-nil secretData
	err := a.s.Set(context.Background(), secrets.SecretKey{Name: a.secretIdWithData}, secretData)
	assert.NoError(t, err, "Error on Set with data")

	// Set with nil secretData
	err = a.s.Set(context.Background(), secrets.SecretKey{Name: a.secretIdWithoutData}, nil)
	assert.NoError(t, err, "Error on Set with nil data")

	// Set with prefix
	err = a.s.Set(context.Background(), secrets.SecretKey{Prefix: a.secretPrefix, Name: a.secretIdWithData}, secretData)
	assert.NoError(t, err, "Error on Set with prefix")
}

func (a *storeTest) TestGetSecret(t *testing.T) {
	// Get with non-existent name
	_, err := a.s.Get(context.Background(), secrets.SecretKey{Name: "dummy"})
	assert.Error(t, err, "Expected Get with name")

	// Get with non-existent name and prefix
	_, err = a.s.Get(context.Background(), secrets.SecretKey{Prefix: "dummy", Name: "dummy"})
	assert.Error(t, err, "Expected Get with name and prefix")

	// Get using a name with data
	plainText1, err := a.s.Get(context.Background(), secrets.SecretKey{Name: a.secretIdWithData})
	assert.NoError(t, err, "Get with name to succeed")
	assert.NotNil(t, plainText1, "Get with name expected plainText to not be nil")
	v, ok := plainText1["key1"]
	assert.True(t, ok, "Get with name unexpected secretData")
	str, ok := v.(string)
	assert.True(t, ok, "Get with name unexpected secretData")
	assert.Equal(t, str, "value1", "Get with name unexpected secretData")

	// Get using a name and prefix with data
	plainText1, err = a.s.Get(context.Background(), secrets.SecretKey{Prefix: a.secretPrefix, Name: a.secretIdWithData})
	assert.NoError(t, err, "Get with name and prefix to succeed")
	assert.NotNil(t, plainText1, "Get with name and prefix plainText to not be nil")
	v, ok = plainText1["key1"]
	assert.True(t, ok, "Get with name and prefix unexpected secretData")
	str, ok = v.(string)
	assert.True(t, ok, "Get with name and prefix unexpected secretData")
	assert.Equal(t, str, "value1", "Get with name and prefix unexpected secretData")

	// Get using a name without data
	_, err = a.s.Get(context.Background(), secrets.SecretKey{Name: a.secretIdWithoutData})
	assert.NoError(t, err, "Expected GetSecret to succeed")
}

func (a *storeTest) TestDeleteSecret(t *testing.T) {
	// Delete of a key that exists should succeed
	err := a.s.Delete(context.Background(), secrets.SecretKey{Name: a.secretIdWithData})
	assert.NoError(t, err, "Expected DeleteSecret to succeed")

	// Get of a deleted key should fail
	_, err = a.s.Get(context.Background(), secrets.SecretKey{Name: a.secretIdWithData})
	assert.EqualError(t, secrets.ErrInvalidSecretId, err.Error(), "Unexpected error on GetSecret after delete")

	// Delete of a key that exists should succeed
	err = a.s.Delete(context.Background(), secrets.SecretKey{Name: a.secretIdWithoutData})
	assert.NoError(t, err, "Expected DeleteSecret to succeed")

	// Get using a secretId without data
	_, err = a.s.Get(context.Background(), secrets.SecretKey{Name: a.secretIdWithoutData})
	assert.EqualError(t, secrets.ErrInvalidSecretId, err.Error(), "Unexpected error on GetSecret after delete")

	// Delete of existing name with prefix should succeed
	err = a.s.Delete(context.Background(), secrets.SecretKey{Prefix: a.secretPrefix, Name: a.secretIdWithoutData})
	assert.NoError(t, err, "Expected DeleteSecret to succeed")

	// Delete of a non-existent key should also succeed
	err = a.s.Delete(context.Background(), secrets.SecretKey{Name: "dummy"})
	assert.NoError(t, err, "Unexpected error on DeleteSecret")
}
