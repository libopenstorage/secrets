//go:build ci
// +build ci

package vault

import (
	"os"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/libopenstorage/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type VaultTestSuite struct {
	suite.Suite
	configV1 map[string]interface{}
	configV2 map[string]interface{}
}

func TestVaultSuite(t *testing.T) {
	suite.Run(t, new(VaultTestSuite))
}
func (suite *VaultTestSuite) SetupConnection() {
	token := os.Getenv("VAULT_TOKEN")
	assert.NotEmpty(suite.T(), token)

	// V1 CONFIG
	c := make(map[string]interface{})
	c[api.EnvVaultAddress] = "http://127.0.0.1:8200"
	c[api.EnvVaultToken] = token
	c[VaultBackendKey] = "v1"
	c[VaultBackendPathKey] = "secret/ver1"
	suite.configV1 = c

	// V2 CONFIG
	c[VaultBackendKey] = "v2"
	c[VaultBackendPathKey] = "secret/ver2"
	suite.configV2 = c
}

func (suite *VaultTestSuite) TestCRUD() {
	suite.SetupConnection()
	v1, err := New(suite.configV1)
	assert.NoError(suite.T(), err)

	suite.T().Run("create key v1", func(t *testing.T) {
		// Build Secret
		data := make(map[string]interface{})
		data["foo"] = "bar"
		_, err := v1.PutSecret("foo", data, nil)
		assert.NoError(suite.T(), err)
	})

	suite.T().Run("delete key v1", func(t *testing.T) {
		err := v1.DeleteSecret("foo", nil)
		assert.NoError(suite.T(), err)
	})

	v2, err := New(suite.configV2)
	assert.NoError(suite.T(), err)

	suite.T().Run("create key v2", func(t *testing.T) {
		// Build Secret
		data := make(map[string]interface{})
		data["foo"] = "bar"
		_, err := v2.PutSecret("foo", data, nil)
		assert.NoError(suite.T(), err)
	})

	suite.T().Run("destroy key v2", func(t *testing.T) {
		err := v2.DeleteSecret("foo", map[string]string{secrets.DestroySecret: "true"})
		assert.NoError(suite.T(), err)
	})
}
