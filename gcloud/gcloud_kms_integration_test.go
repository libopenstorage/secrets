//go:build integration
// +build integration

package gcloud

import (
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"testing"

	"github.com/libopenstorage/secrets"
	"github.com/libopenstorage/secrets/test"
	"github.com/pborman/uuid"
	"github.com/portworx/kvdb"
	"github.com/portworx/kvdb/mem"
	"github.com/stretchr/testify/assert"
)

const (
	testSecretIdWithPassphrase           = "openstorage_secret_with_passphrase"
	testSecretIdWithLargePassphrase      = "openstorage_secret_with_large_passpharse"
	testSecretIdWithRSASizePassphrase    = "openstorage_secret_with_rsa_size_passphrase"
	testSecretId                         = "openstorage_secret"
	testSecretIdForBackwardCompatibility = "openstorage_secret_backward_compatible"
	testSecretIdWithPublic               = "openstorage_secret_with_public"
)

var (
	secretConfig map[string]interface{}
)

func TestAll(t *testing.T) {
	// Set the relevant environmnet fields for google cloud.
	secretConfig = make(map[string]interface{})
	// Fill in the appropriate keys and values
	secretConfig[GoogleKmsResourceKey] = os.Getenv(GoogleKmsResourceKey)

	kv, err := kvdb.New(mem.Name, "openstorage/", nil, nil, nil)
	if err != nil {
		t.Fatalf("Unable to create a gcloud secret instance: %v", err)
		return
	}
	secretConfig[KMSKvdbKey] = kv
	gs, err := NewGcloudSecretTest(secretConfig)
	if err != nil {
		t.Fatalf("Unable to create a gcloud secret instance: %v", err)
		return
	}
	test.Run(gs, t)
}

type gcloudSecretTest struct {
	s               secrets.Secrets
	testPassphrases map[string]string
	testSecretIds   []string
}

func NewGcloudSecretTest(secretConfig map[string]interface{}) (test.SecretTest, error) {
	s, err := New(secretConfig)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string)
	return &gcloudSecretTest{s, m, []string{}}, nil
}

func (i *gcloudSecretTest) TestPutSecret(t *testing.T) error {
	secretData := make(map[string]interface{})
	i.testPassphrases[testSecretIdWithPassphrase] = uuid.New()
	secretData[testSecretIdWithPassphrase] = i.testPassphrases[testSecretIdWithPassphrase]

	// PutSecret with non-nil secretData and no key context
	_, err := i.s.PutSecret(testSecretIdWithPassphrase, secretData, nil)
	assert.Error(t, err, "Expected error on PutSecret")
	errInvalidContext, ok := err.(*secrets.ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "when none of", "Unexpected error on PutSecret")

	keyContext := make(map[string]string)
	keyContext[secrets.CustomSecretData] = "true"

	// PutSecret with nil secretData and key context
	_, err = i.s.PutSecret(testSecretIdWithPassphrase, nil, keyContext)
	errInvalidContext, ok = err.(*secrets.ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "secret data needs to be provided", "Unexpected error on PutSecret")

	// Successful PutSecret with custom secret data
	_, err = i.s.PutSecret(testSecretIdWithPassphrase, secretData, keyContext)
	assert.NoError(t, err, "Unexpected error on PutSecret")
	i.testSecretIds = append(i.testSecretIds, testSecretIdWithPassphrase)

	// PutSecret with nil secretData
	_, err = i.s.PutSecret(testSecretId, nil, nil)
	assert.Error(t, secrets.ErrEmptySecretData, err.Error(), "Unexpected error on PutSecret")

	// Both CustomSecretData and PublicSecretData cannot be set
	keyContext[secrets.PublicSecretData] = "true"
	_, err = i.s.PutSecret(testSecretIdWithPublic, nil, keyContext)
	errInvalidContext, ok = err.(*secrets.ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "both", "Unexpected error on PutSecret")

	delete(keyContext, secrets.CustomSecretData)

	// PublicSecretData with no data
	_, err = i.s.PutSecret(testSecretIdWithPublic, nil, keyContext)
	errInvalidContext, ok = err.(*secrets.ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "secret data needs to be provided", "Unexpected error on PutSecret")

	// Successful PutSecret with PublicSecretData
	getKC := make(map[string]string)
	getKC[secrets.PublicSecretData] = "true"
	secretData, _, err = i.s.GetSecret(testSecretIdWithPassphrase, getKC)
	dek := secretData[testSecretIdWithPassphrase]
	putSecretData := make(map[string]interface{})
	putSecretData[testSecretIdWithPublic] = dek
	_, err = i.s.PutSecret(testSecretIdWithPublic, putSecretData, keyContext)
	assert.NoError(t, err, "Unexpected error on PutSecret")
	i.testSecretIds = append(i.testSecretIds, testSecretIdWithPublic)

	// adding test cases for different input size
	// 1. passphrase == rsa limit
	// 2. passphrase < rsa limit (covered by above)
	// 3. passphrase > rsa limit
	i.TestPutEqualTextSecrets(t)
	i.TestPutLargeTextSecrets(t)
	// adding test case for backward compatibility
	i.TestPutSecretBackwardCompatible(t)

	return nil
}

func (i *gcloudSecretTest) TestPutEqualTextSecrets(t *testing.T) {
	secretData := make(map[string]interface{})

	keyContext := make(map[string]string)
	keyContext[secrets.CustomSecretData] = "true"

	// calculate the text size to generate
	// since we serialize the entire map, we need to count in the empty map size
	g := i.s.(*gcloudKmsSecrets)
	limit, err := calculateRSALimit(g)
	assert.NoError(t, err, "Unexpected error on calculating RSA message limit")
	secretData[testSecretIdWithRSASizePassphrase] = ""
	emptySecretData, err := json.Marshal(secretData)
	assert.NoError(t, err, "Unexpected error on Serializing empty data")
	i.testPassphrases[testSecretIdWithRSASizePassphrase] = randSeq(limit - len(emptySecretData))

	secretData[testSecretIdWithRSASizePassphrase] = i.testPassphrases[testSecretIdWithRSASizePassphrase]
	_, err = i.s.PutSecret(testSecretIdWithRSASizePassphrase, secretData, keyContext)
	assert.NoError(t, err, "Unexpected error on PutEqualTextSecrets")
	i.testSecretIds = append(i.testSecretIds, testSecretIdWithRSASizePassphrase)
}

func (i *gcloudSecretTest) TestPutLargeTextSecrets(t *testing.T) {
	secretData := make(map[string]interface{})

	keyContext := make(map[string]string)
	keyContext[secrets.CustomSecretData] = "true"

	// Put Secret with large secret data text
	i.testPassphrases[testSecretIdWithLargePassphrase] = randSeq(2000)
	secretData[testSecretIdWithLargePassphrase] = i.testPassphrases[testSecretIdWithLargePassphrase]
	_, err := i.s.PutSecret(testSecretIdWithLargePassphrase, secretData, keyContext)
	assert.NoError(t, err, "Unexpected error on PutLargeTextSecrets")
	i.testSecretIds = append(i.testSecretIds, testSecretIdWithLargePassphrase)
}

func (i *gcloudSecretTest) TestPutSecretBackwardCompatible(t *testing.T) {
	secretData := make(map[string]interface{})

	keyContext := make(map[string]string)
	keyContext[secrets.CustomSecretData] = "true"

	i.testPassphrases[testSecretIdForBackwardCompatibility] = uuid.New()
	secretData[testSecretIdForBackwardCompatibility] = i.testPassphrases[testSecretIdForBackwardCompatibility]
	g := i.s.(*gcloudKmsSecrets)
	err := g.putSecret(testSecretIdForBackwardCompatibility, secretData, keyContext)
	assert.NoError(t, err, "Unexpected error on PutSecret for backward ompatibility")
	i.testSecretIds = append(i.testSecretIds, testSecretIdForBackwardCompatibility)
}

func (i *gcloudSecretTest) TestGetSecret(t *testing.T) error {
	// GetSecret with non-existant id
	_, _, err := i.s.GetSecret("dummy", nil)
	assert.Error(t, err, "Expected GetSecret to fail")

	// GetSecret using a secretId with data for custom data
	i.TestGetCustomSecrets(t)

	// GetSecret using a secretId without data
	_, _, err = i.s.GetSecret(testSecretId, nil)
	assert.Error(t, secrets.ErrInvalidSecretId, err.Error(), "Unexpected error on GetSecret")

	keyContext := make(map[string]string)
	// Both the flags are set
	keyContext[secrets.CustomSecretData] = "true"
	keyContext[secrets.PublicSecretData] = "true"
	_, _, err = i.s.GetSecret(testSecretIdWithPublic, keyContext)
	errInvalidContext, ok := err.(*secrets.ErrInvalidKeyContext)
	assert.True(t, ok, "Unexpected error on PutSecret")
	assert.Contains(t, errInvalidContext.Error(), "both", "Unexpected error on PutSecret")

	// GetSecret using the secretID for public
	delete(keyContext, secrets.CustomSecretData)

	// deks for both secrets should match
	sec1, _, err := i.s.GetSecret(testSecretIdWithPassphrase, keyContext)
	assert.NoError(t, err, "Unexpected error on GetSecret")
	dek1, ok := sec1[testSecretIdWithPassphrase]
	assert.True(t, ok, "Unexpected secret returned")

	sec2, _, err := i.s.GetSecret(testSecretIdWithPublic, keyContext)
	assert.NoError(t, err, "Unexpected error on GetSecret")
	dek2, ok := sec2[testSecretIdWithPublic]
	assert.True(t, ok, "Unexpected secret returned")

	assert.Equal(t, dek1, dek2, "Unequal secrets returned.")
	return nil
}

func (i *gcloudSecretTest) TestGetCustomSecrets(t *testing.T) {

	keyContext := make(map[string]string)
	keyContext[secrets.CustomSecretData] = "true"

	for _, secretId := range i.testSecretIds {
		fmt.Println("Getting secret from: ", secretId)
		// skip public data
		if secretId == testSecretIdWithPublic {
			continue
		}

		plaintext, _, err := i.s.GetSecret(secretId, keyContext)
		assert.NoError(t, err, "Unexpected error on GetSecret")
		// We have got secretData
		assert.NotNil(t, plaintext, "Invalid plainText was returned")
		v, ok := plaintext[secretId]
		assert.True(t, ok, "Unexpected plainText")
		str, ok := v.(string)
		assert.True(t, ok, "Unexpected plainText")
		assert.Equal(t, str, i.testPassphrases[secretId], "Unexpected passphrase")
	}
}

func (i *gcloudSecretTest) TestListSecrets(t *testing.T) error {
	ids, err := i.s.ListSecrets()
	assert.NoError(t, err, "Unexpected error on ListSecrets")
	assert.Equal(t, len(ids), len(i.testSecretIds), "Unexpected number of secrets listed")
	return nil
}

func (i *gcloudSecretTest) TestDeleteSecret(t *testing.T) error {

	for _, secretId := range i.testSecretIds {
		fmt.Println("Deleting secret in: ", secretId)
		// Delete of a key that exists should succeed
		err := i.s.DeleteSecret(secretId, nil)
		assert.NoError(t, err, "Unexpected error on DeleteSecret")

		// Get of a deleted key should fail
		_, _, err = i.s.GetSecret(secretId, nil)
		assert.EqualError(t, secrets.ErrInvalidSecretId, err.Error(), "Expected an error on GetSecret after the key is deleted")
	}

	// Delete of a non-existent key should also succeed
	err := i.s.DeleteSecret("dummy", nil)
	assert.NoError(t, err, "Unepxected error on DeleteSecret")
	return nil
}

// putSerect is the previous implementation without handling on large plaintext
// this is used for backward compatibility
func (g *gcloudKmsSecrets) putSecret(
	secretId string,
	secretData map[string]interface{},
	keyContext map[string]string,
) error {
	var (
		dek []byte
	)
	_, override := keyContext[secrets.OverwriteSecretDataInStore]
	_, customData := keyContext[secrets.CustomSecretData]
	_, publicData := keyContext[secrets.PublicSecretData]

	if err := secrets.KeyContextChecks(keyContext, secretData); err != nil {
		return err
	} else if publicData && len(secretData) > 0 {
		publicDek, ok := secretData[secretId]
		if !ok {
			return secrets.ErrInvalidSecretData
		}
		dek, ok = publicDek.([]byte)
		if !ok {
			return &secrets.ErrInvalidKeyContext{
				Reason: "secret data when PublicSecretData flag is set should be of the type []byte",
			}
		}
	} else if len(secretData) > 0 && customData {
		// Wrap the custom secret data and create a new entry in store
		// with the input secretID and the returned dek
		plainTextByte, err := json.Marshal(secretData)
		if err != nil {
			return err
		}
		publicKey, err := g.getAsymmetricPublicKey()
		if err != nil {
			return err
		}
		// encrypt the plain text
		rsaKey := publicKey.(*rsa.PublicKey)
		dek, err = rsa.EncryptOAEP(sha256.New(), crand.Reader, rsaKey, plainTextByte, nil)
		if err != nil {
			return fmt.Errorf("encryption for secret failed: %v", err)
		}

	} else {
		return secrets.ErrEmptySecretData
	}

	return g.ps.Set(
		secretId,
		dek,
		nil,
		nil,
		override,
	)
}

// calculateRSALimit returns the RSA Limit given the gcloudKmsSecrets object
func calculateRSALimit(g *gcloudKmsSecrets) (int, error) {
	publicKey, err := g.getAsymmetricPublicKey()
	if err != nil {
		return 0, err
	}
	// encrypt the plain text
	rsaKey := publicKey.(*rsa.PublicKey)

	hash := sha256.New()
	return getRSALimit(rsaKey, &hash), nil
}

func TestNewWithKVDB(t *testing.T) {
	secretConfig = make(map[string]interface{})
	// With kvdbPersistenceStore
	kv, err := kvdb.New(mem.Name, "openstorage/", nil, nil, nil)
	if err != nil {
		t.Fatalf("Unable to create a IBM Key Protect Secret instance: %v", err)
		return
	}

	// kvdb key is correct
	secretConfig[KMSKvdbKey] = kv
	kp, err := New(secretConfig)
	// assert.EqualError(t, err, ErrGoogleKmsResourceKeyNotProvided.Error(), "Unepxected error when Kvdb Key not provided")

	secretConfig[GoogleKmsResourceKey] = "crk"
	kp, err = New(secretConfig)
	assert.NotNil(t, kp, "Expected New API to succeed")
	assert.NoError(t, err, "Unepxected error on New")
	return
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
