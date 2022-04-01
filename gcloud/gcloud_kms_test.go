package gcloud

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	os.Unsetenv(GoogleKmsResourceKey)
	// nil secret config
	_, err := New(nil)
	assert.EqualError(t, err, ErrInvalidKvdbProvided.Error(), "Unexpected error on nil secret config")

	// empty secret config
	secretConfig := make(map[string]interface{})
	_, err = New(secretConfig)
	assert.EqualError(t, err, ErrInvalidKvdbProvided.Error(), "Unexpected error on empty secret config")

	// kvdb key is incorrect
	secretConfig[KMSKvdbKey] = "dummy"
	_, err = New(secretConfig)
	assert.EqualError(t, err, ErrInvalidKvdbProvided.Error(), "Unepxected error when Kvdb Key not provided")
}

func TestSplit(t *testing.T) {
	input := []byte{1, 2, 3, 4, 5}
	expected := [][]byte{{1, 2}, {3, 4}, {5}}

	output := splitChunk(input, 2)
	assert.Equal(t, output, expected)

	output = splitChunk(input, 0)
	expected = [][]byte{{1, 2, 3, 4, 5}}
	assert.Equal(t, output, expected)
}
