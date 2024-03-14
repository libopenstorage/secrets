package azure

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	os.Unsetenv("AZURE_TENANT_ID")
	os.Unsetenv("AZURE_CLIENT_ID")
	os.Unsetenv("AZURE_CLIENT_SECRET")
	os.Unsetenv("AZURE_CLIENT_CERT_PATH")
	os.Unsetenv("AZURE_ENVIRONMENT")
	os.Unsetenv("AZURE_VAULT_URL")

	// nil secret config
	_, err := New(nil)
	assert.Equal(t, ErrAzureTenantIDNotSet, err)
	os.Setenv("AZURE_TENANT_ID", "invalid_tenant_id")

	_, err = New(nil)
	assert.Equal(t, ErrAzureClientIDNotSet, err)
	os.Setenv("AZURE_CLIENT_ID", "invalid-client-id")

	_, err = New(nil)
	assert.Equal(t, ErrAzureVaultURLNotSet, err)
	os.Setenv("AZURE_VAULT_URL", "invalid-vault-url")

	_, err = New(nil)
	assert.Equal(t, ErrAzureAuthMedhodNotSet, err)
	os.Setenv("AZURE_CLIENT_SECRET", "invalid-secret-id")
}
