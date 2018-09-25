package ibm

import (
	"context"
	"encoding/base64"
	"errors"

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
	ErrInvalidSecretData = errors.New("Secret Data cannot be empty")
)

type ibmKPSecret struct {
	kp  *ibm.API
	ps  store.PersistenceStore
	crk string
}

func New(
	secretConfig map[string]interface{},
) (secrets.Secrets, error) {
	if secretConfig == nil {
		return nil, ErrIbmServiceApiKeyNotSet
	}
	v, _ := secretConfig[IbmCustomerRootKey]
	crk, _ := v.(string)
	if crk == "" {
		return nil, ErrCRKNotProvided
	}
	v, _ = secretConfig[IbmServiceApiKey]
	serviceApiKey, _ := v.(string)
	if serviceApiKey == "" {
		return nil, ErrIbmServiceApiKeyNotSet
	}
	v, _ = secretConfig[IbmInstanceIdKey]
	instanceId, _ := v.(string)
	if instanceId == "" {
		return nil, ErrIbmInstanceIdKeyNotSet
	}

	var kv kvdb.Kvdb
	v, ok := secretConfig[IbmKvdbKey]
	if ok {
		kv, ok = v.(kvdb.Kvdb)
		if !ok {
			return nil, ErrInvalidKvdbProvided
		}
	}
	ps := store.NewKvdbPersistenceStore(kv, kvdbPublicBasePath, kvdbDataBasePath)

	v, _ = secretConfig[IbmBaseUrlKey]
	baseUrl, _ := v.(string)
	if baseUrl == "" {
		baseUrl = ibm.DefaultBaseURL
	}

	v, _ = secretConfig[IbmTokenUrlKey]
	tokenUrl, _ := v.(string)
	if tokenUrl == "" {
		tokenUrl = ibm.DefaultTokenURL
	}

	cc := ibm.ClientConfig{
		BaseURL:    baseUrl,
		APIKey:     serviceApiKey,
		TokenURL:   tokenUrl,
		InstanceID: instanceId,
		Verbose:    ibm.VerboseAll,
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
	decodedPassphrase, err := base64.StdEncoding.DecodeString(string(encodedPassphrase))
	if err != nil {
		return nil, err
	}

	secretData := make(map[string]interface{})
	secretData[secretId] = string(decodedPassphrase)
	return secretData, nil
}

func (i *ibmKPSecret) PutSecret(
	secretId string,
	secretData map[string]interface{},
	keyContext map[string]string,
) error {
	if len(secretData) == 0 {
		return ErrInvalidSecretData
	}
	v, _ := secretData[secretId]
	passphrase := v.(string)
	if passphrase == "" {
		return ErrInvalidSecretData
	}

	encodedPassphrase := base64.StdEncoding.EncodeToString([]byte(passphrase))
	dek, err := i.kp.Wrap(
		context.Background(),
		i.crk,
		[]byte(encodedPassphrase),
		nil,
	)
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

func init() {
	if err := secrets.Register(Name, New); err != nil {
		panic(err.Error())
	}
}
