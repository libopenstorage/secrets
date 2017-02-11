package vault

import (
	"testing"

	"github.com/libopenstorage/secrets/test"
)

func TestAll(t *testing.T) {
	config := make(map[string]interface{})
	config[VaultAddressKey] = "<vault_endpoint>"
	config[VaultTokenKey] = "<vault_token>"
	test.Run(New, config, t)
}
