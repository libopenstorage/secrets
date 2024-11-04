package multikms

import (
	"fmt"

	"github.com/libopenstorage/secrets"
	awsscm "github.com/libopenstorage/secrets/aws/aws_secrets_manager"
	"github.com/libopenstorage/secrets/azure"
	"github.com/libopenstorage/secrets/vault"
	coreops "github.com/portworx/sched-ops/k8s/core"
)



const (
	// KMSTypeKey is a kubernetes secret key used to set a kms type for a tenant
	KMSTypeKey = "KMS_TYPE"
)

func ClientFor(secretname, namespace string) (secrets.Secrets, error) {
	if c := getCachedClient(secretname); c != nil {
		return c, nil
	}

	cfg, err := getConfigFor(secretname, namespace)
	if err != nil {
		return nil, err
	}
	secretType := ""
	if cfg != nil {
		secretType = cfg[KMSTypeKey]
	}

	s, err := Login(secretname, secretType, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build a secrets client for the %s secret: %s", secretname, err)
	}

	return s, nil
}

func getConfigFor(secretname, namespace string) (map[string]string, error) {
	secret, err := coreops.Instance().GetSecret(secretname, namespace)
	if err != nil {
		return nil, fmt.Errorf("get secret %s/%s failed: %s", secretname, namespace, err)
	}

	out := make(map[string]string, len(secret.Data))
	for k, v := range secret.Data {
		out[k] = string(v)
	}

	return out, nil
}

func getCachedClient(name string) secrets.Secrets {
	t := secrets.MultipleInstance(name)
	if t != nil {
		return t
	}
	return nil
}

func Login(secretname, stype string, secretConfig map[string]string) (secrets.Secrets, error) {
	sc := toSecretConfig(secretConfig)
	switch stype {
	case secrets.TypeVault:
		s, err := vault.New(sc)
		if err != nil {
			return nil, fmt.Errorf("failed to create vault client: %s", err)
		}
		secrets.SetMultipleInstance(secretname, s)
	case secrets.TypeAWSSecretsManager:
		s, err := awsscm.New(sc)
		if err != nil {
			return nil, fmt.Errorf("failed to create aws secrets manager client: %s", err)
		}
		secrets.SetMultipleInstance(secretname, s)
	case secrets.TypeAzure:
		s, err := azure.New(sc)
		if err != nil {
			return nil, fmt.Errorf("failed to create azure client: %s", err)
		}
		secrets.SetMultipleInstance(secretname, s)
	}
	return nil, fmt.Errorf("unsupported secret endpoint")
}

func toSecretConfig(secretConfig map[string]string) map[string]interface{} {
	sc := make(map[string]interface{})
	for k, v := range secretConfig {
		sc[k] = v
	}
	return sc
}
