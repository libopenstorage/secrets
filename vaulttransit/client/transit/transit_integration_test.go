// +build integration

package transit

import (
	"encoding/base64"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

func vaultClient() (*api.Client, error) {
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

func TestRead(t *testing.T) {
	client, err := vaultClient()
	require.Nil(t, err)

	transitClient, err := New(client.Logical())
	require.Nil(t, err)

	testKey := SecretKey{Name: "testkey"}

	s, err := transitClient.Read(testKey)
	require.NotNil(t, err)
	require.Nil(t, s)

	_, err = transitClient.Create(testKey, "")
	require.Nil(t, err)

	s, err = transitClient.Read(testKey)
	require.Nil(t, err)
	require.NotNil(t, s)
}

func TestE2E(t *testing.T) {
	client, err := vaultClient()
	require.Nil(t, err)

	transitClient, err := New(client.Logical())
	require.Nil(t, err)

	testKey := SecretKey{Name: "testkey"}
	expectedPassphrase := "secret"
	expectedPlaintext := base64.StdEncoding.EncodeToString([]byte(expectedPassphrase))

	// check: create/encrypt/decrypt
	secret1, err := transitClient.Create(testKey, "")
	require.Nil(t, err)

	secret2, err := transitClient.Create(testKey, "")
	require.Nil(t, err)
	require.Equal(t, secret1, secret2)

	secret3, err := transitClient.Read(testKey)
	require.Nil(t, err)
	require.NotNil(t, secret3)

	cipher, err := transitClient.Encrypt(testKey, expectedPlaintext)
	require.Nil(t, err)

	encodedPlaintext, err := transitClient.Decrypt(testKey, cipher)
	require.Nil(t, err)

	passphrase, err := base64.StdEncoding.DecodeString(encodedPlaintext)
	require.Nil(t, err)
	require.Equal(t, expectedPassphrase, string(passphrase))

	err = transitClient.Delete(testKey)
	require.Nil(t, err)

	// check: encrypt/decrypt (encryption create capability)
	cipher, err = transitClient.Encrypt(testKey, expectedPlaintext)
	require.Nil(t, err)

	encodedPlaintext, err = transitClient.Decrypt(testKey, cipher)
	require.Nil(t, err)

	passphrase, err = base64.StdEncoding.DecodeString(encodedPlaintext)
	require.Nil(t, err)
	require.Equal(t, expectedPassphrase, string(passphrase))

	err = transitClient.Delete(testKey)
	require.Nil(t, err)

	// check: generate data key, use an existing encryption key
	_, err = transitClient.Create(testKey, "")
	require.Nil(t, err)

	cipher, err = transitClient.GenerateDataKey(testKey)
	require.Nil(t, err)

	encodedPlaintext, err = transitClient.Decrypt(testKey, cipher)
	require.Nil(t, err)

	_, err = base64.StdEncoding.DecodeString(encodedPlaintext)
	require.Nil(t, err)

	err = transitClient.Delete(testKey)
	require.Nil(t, err)

	// check: generate data key, create an encryption key
	cipher, err = transitClient.GenerateDataKey(testKey)
	require.Nil(t, err)

	encodedPlaintext, err = transitClient.Decrypt(testKey, cipher)
	require.Nil(t, err)

	_, err = base64.StdEncoding.DecodeString(encodedPlaintext)
	require.Nil(t, err)

	err = transitClient.Delete(testKey)
	require.Nil(t, err)

	// TODO: ensure an encryption key has been removed
}
