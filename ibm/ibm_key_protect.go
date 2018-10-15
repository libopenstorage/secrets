package ibm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/pkg/ibm"
	"github.com/libopenstorage/secrets/pkg/store"
	"github.com/portworx/kvdb"
	"github.com/sirupsen/logrus"
)

const (
	// Name of the secret store
	Name = "ibm-kp"
	// IbmServiceApiKey is the service ID API Key
	IbmServiceApiKey = "IBM_SERVICE_API_KEY"
	// IbmInstanceIdKey is the Key Protect Service's Instance ID
	IbmInstanceIdKey = "IBM_INSTANCE_ID"
	// IbmBaseUrlKey is the Key Protect Service's Base URL
	IbmBaseUrlKey = "IBM_BASE_URL"
	// IbmTokenUrlKey is the Key Protect Service's Token URL
	IbmTokenUrlKey = "IBM_TOKEN_URL"
	// IbmCustomerRootKey is the Customer Root Key used for obtaining DEKs
	IbmCustomerRootKey = "IBM_CUSTOMER_ROOT_KEY"
	// IbmKvdbKey is used to setup IBM Key Protect Secret Store with kvdb for persistence.
	IbmKvdbKey         = "IBM_KVDB"
	kvdbPublicBasePath = "ibm_kp/secrets/public/"
	kvdbDataBasePath   = "ibm_kp/secrets/data/"
	// kpClientTimeout is the http client timeout in seconds
	kpClientTimeout = 10
	// CustomSecretData is a constant used as a key context in the secrets APIs
	CustomSecretData = "custom_secret_data"
)

var (
	// ErrIbmServiceApiKeyNotSet is returned when IBM_SERVICE_API_KEY is not set
	ErrIbmServiceApiKeyNotSet = errors.New("IBM_SERVICE_API_KEY not set.")
	// ErrIbmInstanceIdKeyNotSet is returned when IBM_INSTANCE_ID is not set
	ErrIbmInstanceIdKeyNotSet = errors.New("IBM_INSTANCE_ID not set.")
	// ErrCRKNotProvided is returned when Customer Root Key is not provided.
	ErrCRKNotProvided = errors.New("IBM Customer Root Key not provided. Cannot perform Key Protect operations.")
	// ErrInvalidKvdbProvided is returned when an incorrect KVDB implementation is provided for persistence store.
	ErrInvalidKvdbProvided = errors.New("Invalid kvdb provided. IBM Key Protect secret store works in conjuction with a kvdb")
	// ErrInvalidSecretData is returned when no secret data is found
	ErrInvalidSecretData = errors.New("Secret Data cannot be empty when CustomSecretData flag is set")
	// ErrInvalidKeyContext is returned when secret data is provided without CustomSecretData key context
	ErrInvalidKeyContext = errors.New("Secret Data cannot be provided when CustomSecretData flag is not set")
)

type ibmKPSecret struct {
	kp  *ibm.API
	ps  store.PersistenceStore
	crk string
}

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {
	var (
		kv kvdb.Kvdb
	)
	v, ok := secretConfig[IbmKvdbKey]
	if ok {
		kv, ok = v.(kvdb.Kvdb)
		if !ok || kv == nil {
			return nil, ErrInvalidKvdbProvided
		}
	} else {
		return nil, ErrInvalidKvdbProvided
	}

	ps := store.NewKvdbPersistenceStore(kv, kvdbPublicBasePath, kvdbDataBasePath)

	crk := getIbmParam(secretConfig, IbmCustomerRootKey)
	if crk == "" {
		return nil, ErrCRKNotProvided
	}

	serviceApiKey := getIbmParam(secretConfig, IbmServiceApiKey)
	if serviceApiKey == "" {
		return nil, ErrIbmServiceApiKeyNotSet
	}

	instanceId := getIbmParam(secretConfig, IbmInstanceIdKey)
	if instanceId == "" {
		return nil, ErrIbmInstanceIdKeyNotSet
	}

	baseUrl := getIbmParam(secretConfig, IbmBaseUrlKey)
	if baseUrl == "" {
		baseUrl = ibm.DefaultBaseURL
	}

	tokenUrl := getIbmParam(secretConfig, IbmTokenUrlKey)
	if tokenUrl == "" {
		tokenUrl = ibm.DefaultTokenURL
	}

	cc := ibm.ClientConfig{
		BaseURL:    baseUrl,
		APIKey:     serviceApiKey,
		TokenURL:   tokenUrl,
		InstanceID: instanceId,
		Verbose:    ibm.VerboseAll,
		Timeout:    kpClientTimeout,
	}
	kp, err := ibm.NewAPIWithLogger(cc, nil, logrus.StandardLogger())
	if err != nil {
		return nil, err
	}
	return &ibmKPSecret{
		kp:  kp,
		crk: crk,
		ps:  ps,
	}, nil
}

func (i *ibmKPSecret) String() string {
	return Name
}

func (i *ibmKPSecret) GetSecret(
	secretId string,
	keyContext map[string]string,
) (map[string]interface{}, error) {
	if exists, err := i.ps.Exists(secretId); err != nil {
		return nil, err
	} else if !exists {
		return nil, secrets.ErrInvalidSecretId
	}

	// Get the DEK (Data Encryption Key) from kvdb
	dek, err := i.ps.GetPublic(secretId)
	if err != nil {
		return nil, err
	}
	// Use the CRK to unwrap the DEK and get the secret passphrase
	encodedPassphrase, err := i.kp.Unwrap(
		context.Background(),
		i.crk,
		dek,
		nil,
	)
	if err != nil {
		return nil, err
	}
	decodedPassphrase, err := base64.StdEncoding.DecodeString(string(encodedPassphrase))
	if err != nil {
		return nil, err
	}
	secretData := make(map[string]interface{})
	if _, ok := keyContext[CustomSecretData]; ok {
		if err := json.Unmarshal(decodedPassphrase, &secretData); err != nil {
			return nil, err
		}
	} else {
		secretData[secretId] = string(decodedPassphrase)
	}
	return secretData, nil
}

func (i *ibmKPSecret) PutSecret(
	secretId string,
	secretData map[string]interface{},
	keyContext map[string]string,
) error {
	var (
		dek []byte
		err error
	)
	exists, err := i.ps.Exists(secretId)
	if err != nil {
		return err
	}
	if exists {
		return secrets.ErrSecretExists
	}
	_, customData := keyContext[CustomSecretData]

	if customData && len(secretData) == 0 {
		return ErrInvalidSecretData
	} else if len(secretData) > 0 && !customData {
		return ErrInvalidKeyContext
	} else if len(secretData) > 0 && customData {
		value, err := json.Marshal(secretData)
		if err != nil {
			return err
		}
		encodedPassphrase := base64.StdEncoding.EncodeToString(value)
		dek, err = i.kp.Wrap(
			context.Background(),
			i.crk,
			[]byte(encodedPassphrase),
			nil,
		)
	} else {
		_, dek, err = i.kp.WrapCreateDEK(
			context.Background(),
			i.crk,
			nil,
		)
	}
	if err != nil {
		return err
	}
	return i.ps.Set(
		secretId,
		dek,
		nil,
		nil,
	)
}

func (i *ibmKPSecret) DeleteSecret(
	secretId string,
	keyContext map[string]string,
) error {
	return i.ps.Delete(secretId)
}

func (i *ibmKPSecret) Encrypt(
	secretId string,
	plaintTextData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (i *ibmKPSecret) Decrypt(
	secretId string,
	encryptedData string,
	keyContext map[string]string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func (i *ibmKPSecret) Rencrypt(
	originalSecretId string,
	newSecretId string,
	originalKeyContext map[string]string,
	newKeyContext map[string]string,
	encryptedData string,
) (string, error) {
	return "", secrets.ErrNotSupported
}

func getIbmParam(secretConfig map[string]interface{}, name string) string {
	if tokenIntf, exists := secretConfig[name]; exists {
		return tokenIntf.(string)
	} else {
		return os.Getenv(name)
	}
}

func init() {
	if err := secrets.Register(Name, New); err != nil {
		panic(err.Error())
	}
}