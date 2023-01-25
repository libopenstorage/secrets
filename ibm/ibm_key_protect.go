package ibm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	ibm "github.com/IBM/keyprotect-go-client"
	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/pkg/store"
	"github.com/portworx/kvdb"
	"github.com/sirupsen/logrus"
)

const (
	// Name of the secret store
	Name = secrets.TypeIBM
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
	kp, err := ibm.NewWithLogger(cc, nil, logrus.StandardLogger())
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
) (map[string]interface{}, secrets.Version, error) {

	_, customData := keyContext[secrets.CustomSecretData]
	_, publicData := keyContext[secrets.PublicSecretData]
	if customData && publicData {
		return nil, secrets.NoVersion, &secrets.ErrInvalidKeyContext{
			Reason: "both CustomSecretData and PublicSecretData flags cannot be set",
		}
	}

	dek, err := i.getDekFromStore(secretId)
	if err != nil {
		return nil, secrets.NoVersion, err
	}

	secretData := make(map[string]interface{})
	if publicData {
		secretData[secretId] = dek
		return secretData, secrets.NoVersion, nil
	}

	// Use the CRK to unwrap the DEK and get the secret passphrase
	encodedPassphrase, err := i.kp.Unwrap(
		context.Background(),
		i.crk,
		dek,
		nil,
	)
	if err != nil {
		return nil, secrets.NoVersion, handleError(err)
	}
	decodedPassphrase, err := base64.StdEncoding.DecodeString(string(encodedPassphrase))
	if err != nil {
		return nil, secrets.NoVersion, err
	}
	if customData {
		if err := json.Unmarshal(decodedPassphrase, &secretData); err != nil {
			return nil, secrets.NoVersion, err
		}
	} else {
		secretData[secretId] = string(decodedPassphrase)
	}
	return secretData, secrets.NoVersion, nil
}

func (i *ibmKPSecret) PutSecret(
	secretId string,
	secretData map[string]interface{},
	keyContext map[string]string,
) (secrets.Version, error) {
	var (
		dek []byte
		err error
	)

	_, override := keyContext[secrets.OverwriteSecretDataInStore]
	_, customData := keyContext[secrets.CustomSecretData]
	_, publicData := keyContext[secrets.PublicSecretData]

	if err := secrets.KeyContextChecks(keyContext, secretData); err != nil {
		return secrets.NoVersion, err
	} else if publicData && len(secretData) > 0 {
		publicDek, ok := secretData[secretId]
		if !ok {
			return secrets.NoVersion, secrets.ErrInvalidSecretData
		}
		dek, ok = publicDek.([]byte)
		if !ok {
			return secrets.NoVersion, &secrets.ErrInvalidKeyContext{
				Reason: "secret data when PublicSecretData flag is set should be of the type []byte",
			}
		}

	} else if len(secretData) > 0 && customData {
		// Wrap the custom secret data and create a new entry in store
		// with the input secretID and the returned dek
		value, err := json.Marshal(secretData)
		if err != nil {
			return secrets.NoVersion, err
		}
		encodedPassphrase := base64.StdEncoding.EncodeToString(value)
		dek, err = i.kp.Wrap(
			context.Background(),
			i.crk,
			[]byte(encodedPassphrase),
			nil,
		)
	} else {
		// Generate a new dek and create a new entry in store
		// with the input secretID and the generated dek
		_, dek, err = i.kp.WrapCreateDEK(
			context.Background(),
			i.crk,
			nil,
		)
	}
	if err != nil {
		return secrets.NoVersion, handleError(err)
	}
	return secrets.NoVersion, i.ps.Set(
		secretId,
		dek,
		nil,
		nil,
		override,
	)
}

func (i *ibmKPSecret) DeleteSecret(
	secretId string,
	keyContext map[string]string,
) error {
	return i.ps.Delete(secretId)
}

func (i *ibmKPSecret) ListSecrets() ([]string, error) {
	return i.ps.List()
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

func (i *ibmKPSecret) getDekFromStore(secretId string) ([]byte, error) {
	if exists, err := i.ps.Exists(secretId); err != nil {
		return nil, err
	} else if !exists {
		return nil, secrets.ErrInvalidSecretId
	}

	// Get the DEK (Data Encryption Key) from kvdb
	return i.ps.GetPublic(secretId)
}

func getIbmParam(secretConfig map[string]interface{}, name string) string {
	if tokenIntf, exists := secretConfig[name]; exists {
		return tokenIntf.(string)
	} else {
		return os.Getenv(name)
	}
}

func handleError(err error) error {
	// Strip the keys and CRK from the error Output
	// TODO: This needs to be handled at the IBM SDK level
	// Once the SDK is updated this code will be removed.
	// An example error looks like this
	// Post https://keyprotect.us-south.bluemix.net/api/v2/keys/<crk>?action=wrap: net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers)""
	if strings.Contains(err.Error(), "api/v2/keys") {
		errTokens := strings.Split(err.Error(), "?")
		if len(errTokens) > 1 {
			return fmt.Errorf("ibm error: %v", errTokens[1])
		} else {
			// unable to parse the errors
			return fmt.Errorf("ibm error: cannot perform requested action")
		}
	}
	return err
}

func init() {
	if err := secrets.Register(Name, New); err != nil {
		panic(err.Error())
	}
}
