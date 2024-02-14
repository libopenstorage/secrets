package azure

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"golang.org/x/crypto/pkcs12"
)

func getAzureKVParams(secretConfig map[string]interface{}, name string) string {
	if tokenIntf, exists := secretConfig[name]; exists {
		return tokenIntf.(string)
	} else {
		return os.Getenv(name)
	}
}

func getAzureVaultClient(clientID, secretID, certPath, certPassword, tenantID, envName string) (keyvault.BaseClient, error) {
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

	var token *adal.ServicePrincipalToken
	if secretID != "" {
		token, err = adal.NewServicePrincipalToken(
			*oauthconfig, clientID, secretID, strings.TrimSuffix(environment.KeyVaultEndpoint, "/"))
		if err != nil {
			return keyClient, err
		}
	} else if certPath != "" {
		certData, err := os.ReadFile(certPath)
		if err != nil {
			return keyClient, fmt.Errorf("reading the client certificate from file %s: %v", certPath, err)
		}
		certificate, privateKey, err := decodePkcs12(certData, certPassword)
		if err != nil {
			return keyClient, fmt.Errorf("failed to decode the client certificate: %v", err)
		}
		token, err = adal.NewServicePrincipalTokenFromCertificate(
			*oauthconfig, clientID, certificate, privateKey, strings.TrimSuffix(environment.KeyVaultEndpoint, "/"))
		if err != nil {
			return keyClient, err
		}
	}

	keyClient.Authorizer = autorest.NewBearerAuthorizer(token)
	return keyClient, nil
}

// decodePkcs12 decodes a PKCS#12 client certificate by extracting the public certificate and
// the private RSA key
func decodePkcs12(pkcs []byte, password string) (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, certificate, err := pkcs12.Decode(pkcs, password)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding the PKCS#12 client certificate: %v", err)
	}
	rsaPrivateKey, isRsaKey := privateKey.(*rsa.PrivateKey)
	if !isRsaKey {
		return nil, nil, fmt.Errorf("PKCS#12 certificate must contain a RSA private key")
	}

	return certificate, rsaPrivateKey, nil
}
