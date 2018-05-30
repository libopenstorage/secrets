package vault

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

func setup() {
	os.Unsetenv(api.EnvVaultToken)
	os.Unsetenv(api.EnvVaultAddress)
	os.Unsetenv(api.EnvVaultMaxRetries)
	os.Unsetenv(api.EnvVaultInsecure)
}

func TestNew(t *testing.T) {
	setup()

	// error in vault default config, when no secrets config given
	os.Setenv(api.EnvVaultMaxRetries, "invalid_int")
	_, err := New(nil)

	assert.NotNil(t, err)
	os.Unsetenv(api.EnvVaultMaxRetries)

	os.Setenv(api.EnvVaultInsecure, "invalid_bool")
	_, err = New(nil)

	assert.NotNil(t, err)
	os.Unsetenv(api.EnvVaultInsecure)

	// vault address and token not provided
	_, err = New(nil)

	assert.NotNil(t, err)
	assert.Equal(t, ErrVaultTokenNotSet, err)

	// vault address not provided
	os.Setenv(api.EnvVaultToken, "token")

	_, err = New(nil)

	assert.NotNil(t, err)
	assert.Equal(t, ErrVaultAddressNotSet, err)
	os.Unsetenv(api.EnvVaultToken)

	// vault address not provided
	config := make(map[string]interface{})
	config[api.EnvVaultToken] = "token"

	_, err = New(config)

	assert.NotNil(t, err)
	assert.Equal(t, ErrVaultAddressNotSet, err)

	// vault token not provided
	os.Setenv(api.EnvVaultAddress, "http://127.0.0.1:8200")

	_, err = New(nil)

	assert.NotNil(t, err)
	assert.Equal(t, ErrVaultTokenNotSet, err)
	os.Unsetenv(api.EnvVaultAddress)

	// vault token not provided
	config = make(map[string]interface{})
	config[api.EnvVaultAddress] = "http://127.0.0.1:8200"

	_, err = New(config)

	assert.NotNil(t, err)
	assert.Equal(t, ErrVaultTokenNotSet, err)

	// vault address is not valid
	os.Setenv(api.EnvVaultToken, "token")
	os.Setenv(api.EnvVaultAddress, "invalid://127.0.0.1:8200")

	_, err = New(nil)

	assert.NotNil(t, err)
	assert.Equal(t, ErrInvalidVaultAddress, err)
	os.Unsetenv(api.EnvVaultToken)
	os.Unsetenv(api.EnvVaultAddress)

	// invalid VAULT_SKIP_VERIFY in the config
	config = make(map[string]interface{})
	config[api.EnvVaultAddress] = "http://127.0.0.1:8200"
	config[api.EnvVaultToken] = "token"
	config[api.EnvVaultInsecure] = "invalid_bool"

	_, err = New(config)

	assert.NotNil(t, err)
	assert.Equal(t, ErrInvalidSkipVerify, err)

	// error from TLS config
	config = make(map[string]interface{})
	config[api.EnvVaultAddress] = "http://127.0.0.1:8200"
	config[api.EnvVaultToken] = "token"
	config[api.EnvVaultInsecure] = "false"
	config[api.EnvVaultClientCert] = "path/does/not/exist"
	config[api.EnvVaultClientKey] = "path/does/not/exist"

	_, err = New(config)

	assert.NotNil(t, err)

	// error creating a new vault client
	config = make(map[string]interface{})
	config[api.EnvVaultAddress] = "http://127.0.0.1:8200"
	config[api.EnvVaultToken] = "token"
	oldNewClient := newVaultClient
	newVaultClient = func(*api.Config) (*api.Client, error) {
		return nil, fmt.Errorf("new client error")
	}

	_, err = New(config)

	assert.NotNil(t, err)
	assert.Equal(t, "new client error", err.Error())
	newVaultClient = oldNewClient

	// error getting kv backend version
	config = make(map[string]interface{})
	config[api.EnvVaultAddress] = "http://127.0.0.1:8200"
	config[api.EnvVaultToken] = "token"
	oldIsKvV2 := isKvV2
	isKvV2 = func(*api.Client, string) (bool, error) {
		return false, fmt.Errorf("unable to get kv version")
	}

	_, err = New(config)

	assert.NotNil(t, err)
	assert.Equal(t, "unable to get kv version", err.Error())

	// create client without error
	config = make(map[string]interface{})
	config[api.EnvVaultAddress] = "http://127.0.0.1:8200"
	config[api.EnvVaultToken] = "token"
	isKvV2 = func(*api.Client, string) (bool, error) {
		return true, nil
	}

	client, err := New(config)

	assert.Nil(t, err)
	assert.NotNil(t, client)
	isKvV2 = oldIsKvV2
}
