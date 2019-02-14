package azure

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Azure/go-autorest/autorest/to"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/libopenstorage/secrets"
	"github.com/portworx/sched-ops/task"
)

const (
	Name       = "azure-kv"
	AzureCloud = "AzurePublicCloud"
	// AzureTenantID for Azure Active Directory
	AzureTenantID = "AZURE_TENANT_ID"
	// AzureClientID of service principal account
	AzureClientID = "AZURE_CLIENT_ID"
	// AzureClientSecret of service principal account
	AzureClientSecret = "AZURE_CLIENT_SECRET"
	// AzureEnviornment to connect
	AzureEnviornment = "AZURE_ENVIORNMENT"
	// AzureVaultURI of azure key vault
	AzureVaultURL = "AZURE_VAULT_URL"
	// Default context timeout for Azure SDK API's
	defaultTimeout = 30 * time.Second
	// timeout
	timeout = 8 * time.Second
	// retrytimeout
	retryTimeout = 4 * time.Second
)

var (
	ErrAzureTenantIDNotSet    = errors.New("AZURE_TENANT_ID not set.")
	ErrAzureClientIDNotSet    = errors.New("AZURE_CLIENT_ID not set.")
	ErrAzureSecretIDNotSet    = errors.New("AZURE_SECRET_ID not set.")
	ErrAzureVaultURLNotSet    = errors.New("AZURE_VAULT_URL not set.")
	ErrAzureEnvironmentNotset = errors.New("AZURE_ENVIRONMENT not set.")
	ErrAzureConfigMissing     = errors.New("AzureConfig is not provided")
	ErrAzureAuthentication    = errors.New("Azure authentication failed")
	ErrInvalidSecretResp      = errors.New("Secret Data received from secrets provider is either empty/invalid")
)

type azureSecrets struct {
	kv      keyvault.BaseClient
	baseURL string
}

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {

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
		// we set back to default AzurePublicCloud
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
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	if secretID == "" {
		return nil, secrets.ErrEmptySecretId
	}

	t := func() (interface{}, bool, error) {
		secretResp, err := az.kv.GetSecret(ctx, az.baseURL, secretID, "")
		if err != nil {
			return nil, true, err
		}
		return secretResp, false, nil
	}
	resp, err := task.DoRetryWithTimeout(t, timeout, retryTimeout)
	if err != nil {
		return nil, err
	}

	secretResp := resp.(keyvault.SecretBundle)
	if secretResp.Value == nil {
		return nil, ErrInvalidSecretResp
	}
	secretData := make(map[string]interface{})
	err = json.Unmarshal([]byte(*secretResp.Value), &secretData)
	if err != nil {
		secretData = make(map[string]interface{})
		secretData[secretID] = *secretResp.Value
	}

	return secretData, nil
}

func (az *azureSecrets) PutSecret(
	secretName string,
	secretData map[string]interface{},
	keyContext map[string]string,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	var secretResp keyvault.SecretBundle
	if secretName == "" {
		return secrets.ErrEmptySecretId
	}
	if len(secretData) == 0 {
		return secrets.ErrEmptySecretData
	}

	value, err := json.Marshal(secretData)
	if err != nil {
		return err
	}

	t := func() (interface{}, bool, error) {
		secretResp, err = az.kv.SetSecret(ctx, az.baseURL, secretName, keyvault.SecretSetParameters{
			Value: to.StringPtr(string(value)),
		})
		if err != nil {
			return nil, true, err
		}
		return secretResp, false, nil
	}
	_, err = task.DoRetryWithTimeout(t, timeout, retryTimeout)

	return err
}
func (az *azureSecrets) DeleteSecret(
	secretName string,
	keyContext map[string]string,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	if secretName == "" {
		return secrets.ErrEmptySecretId
	}
	_, err := az.kv.DeleteSecret(ctx, az.baseURL, secretName)

	return err
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

func init() {
	if err := secrets.Register(Name, New); err != nil {
		panic(err.Error())
	}
}
