package azure

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/libopenstorage/secrets"
)

const (
	Name       = "AzureKV"
	AzureCloud = "AzurePublicCloud"
)

var (
	ErrAzureTenantIDNotSet   = errors.New("AZURE_TENANT_ID not set.")
	ErrAzureClientIDNotSet   = errors.New("AZURE_CLIENT_ID not set.")
	ErrAzureSecretIDNotSet   = errors.New("AZURE_SECRET_ID not set.")
	ErrAzureVaultURLNotSet   = errors.New("AZURE_VAULT_URL not set.")
	ErrAzureEnviromentNotset = errors.New("AZURE_ENVIORMENT not set.")
	ErrAzureConfigMissing    = errors.New("AzureConfig is not provided")
	ErrAzureAuthentication   = errors.New("Azure authentication failed")
)

type azureSecrets struct {
	kv      keyvault.BaseClient
	baseURL string
}

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {
	if len(secretConfig) == 0 {
		return nil, ErrAzureConfigMissing
	}
	tenantID := getAzureKVParams(secretConfig, "AZURE_TENANT_ID")
	if tenantID == "" {
		return nil, ErrAzureTenantIDNotSet
	}
	clientID := getAzureKVParams(secretConfig, "AZURE_CLIENT_ID")
	if clientID == "" {
		return nil, ErrAzureClientIDNotSet
	}
	secretID := getAzureKVParams(secretConfig, "AZURE_CLIENT_SECRET")
	if secretID == "" {
		return nil, ErrAzureSecretIDNotSet
	}
	envName := getAzureKVParams(secretConfig, "AZURE_ENVIORNMENT")
	if envName == "" {
		//	return nil, ErrAzureEnviromentNotset
		envName = AzureCloud
	}
	vaultURL := getAzureKVParams(secretConfig, "AZURE_VAULT_URL")
	if vaultURL == "" {
		return nil, ErrAzureVaultURLNotSet
	}

	client, err := getAzureVaultClient(clientID, secretID, tenantID, envName)
	if err != nil {
		return nil, ErrAzureAuthentication
	}

	return &azureSecrets{
		kv:      client,
		baseURL: vaultURL,
	}, nil
}

func (az *azureSecrets) GetSecret(
	secretID string,
	keyContext map[string]string,
) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 6000*time.Second)
	defer cancel()

	// TODO: check if version param is mandetory
	// right now its work if we don't provide secret version
	secretResp, err := az.kv.GetSecret(ctx, az.baseURL, secretID, "")
	if err != nil {
		return nil, err
	}
	secretData := make(map[string]interface{})
	secretData[secretID] = *secretResp.Value

	return secretData, nil
}

func (az *azureSecrets) PutSecret(
	secretName string,
	secretData map[string]interface{},
	keyContext map[string]string,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), 6000*time.Second)
	defer cancel()
	// should call update here
	_, err := az.kv.SetSecret(ctx, az.baseURL, secretName, keyvault.SecretSetParameters{
		Value: to.StringPtr(secretData[secretName].(string)),
	})
	if err != nil {
		return err
	}
	return nil
}
func (az *azureSecrets) DeleteSecret(
	secretName string,
	keyContext map[string]string,
) error {
	return nil
}

func (az *azureSecrets) ListSecrets() ([]string, error) {
	return nil, secrets.ErrNotSupported
}

func (az *azureSecrets) Encrypt(
	secretId string,
	plaintTextData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (az *azureSecrets) Decrypt(
	secretId string,
	encryptedData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (az *azureSecrets) Rencrypt(
	originalSecretId string,
	newSecretId string,
	originalKeyContext map[string]string,
	newKeyContext map[string]string,
	encryptedData string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (az *azureSecrets) String() string {
	return Name
}

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

func init() {
	if err := secrets.Register(Name, New); err != nil {
		panic(err.Error())
	}
}
