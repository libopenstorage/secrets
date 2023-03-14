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
	secretIdWithData    string
	secretIdWithoutData string
}

func RunForStore(store secrets.SecretStore, t *testing.T) {
	st := &storeTest{
		s:                   store,
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
	// PutSecret with non-nil secretData
	err := a.s.Set(context.Background(), secrets.SecretKey{Name: a.secretIdWithData}, secretData)
	assert.NoError(t, err, "Unexpected error on PutSecret")

	// PutSecret with nil secretData
	err = a.s.Set(context.Background(), secrets.SecretKey{Name: a.secretIdWithoutData}, nil)
	assert.NoError(t, err, "Expected PutSecret to succeed. Failed with error: %v", err)
}

func (a *storeTest) TestGetSecret(t *testing.T) {
	// GetSecret with non-existant id
	_, err := a.s.Get(context.Background(), secrets.SecretKey{Name: "dummy"})
	assert.Error(t, err, "Expected GetSecret to fail")

	// GetSecret using a secretId with data
	plainText1, err := a.s.Get(context.Background(), secrets.SecretKey{Name: a.secretIdWithData})
	assert.NoError(t, err, "Expected GetSecret to succeed")
	assert.NotNil(t, plainText1, "Expected plainText to not be nil")
	v, ok := plainText1["key1"]
	assert.True(t, ok, "Unexpected secretData")
	str, ok := v.(string)
	assert.True(t, ok, "Unexpected secretData")
	assert.Equal(t, str, "value1", "Unexpected secretData")

	// GetSecret using a secretId without data
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

	// GetSecret using a secretId without data
	_, err = a.s.Get(context.Background(), secrets.SecretKey{Name: a.secretIdWithoutData})
	assert.EqualError(t, secrets.ErrInvalidSecretId, err.Error(), "Unexpected error on GetSecret after delete")

	// Delete of a non-existent key should also succeed
	err = a.s.Delete(context.Background(), secrets.SecretKey{Name: "dummy"})
	assert.NoError(t, err, "Unexpected error on DeleteSecret")
}
