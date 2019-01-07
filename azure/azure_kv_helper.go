package azure

import (
	"net/url"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
)

func getAzureKVParams(secretConfig map[string]interface{}, name string) string {
	if tokenIntf, exists := secretConfig[name]; exists {
		return tokenIntf.(string)
	} else {
		return os.Getenv(name)
	}
}

func getAzureVaultClient(clientID, secretID, tenantID, envName string) (keyvault.BaseClient, error) {
	var environment *azure.Environment
	alternateEndpoint, _ := url.Parse(
		"https://login.windows.net/" + tenantID + "/oauth2/token")

	keyClient := keyvault.New()
	env, err := azure.EnvironmentFromName(envName)
	if err != nil {
		return keyClient, err
	}
	environment = &env
	oauthconfig, err := adal.NewOAuthConfig(
		environment.ActiveDirectoryEndpoint, tenantID)
	if err != nil {
		return keyClient, err
	}
	oauthconfig.AuthorizeEndpoint = *alternateEndpoint

	token, err := adal.NewServicePrincipalToken(
		*oauthconfig, clientID, secretID, strings.TrimSuffix(environment.KeyVaultEndpoint, "/"))
	if err != nil {
		return keyClient, err
	}
	keyClient.Authorizer = autorest.NewBearerAuthorizer(token)
	return keyClient, nil
}
