package kp

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	gock "gopkg.in/h2non/gock.v1"
)

// NewTestClientConfig returns a new ClientConfig suitable for testing.
//
func NewTestClientConfig() ClientConfig {
	return ClientConfig{
		BaseURL:    "http://example.com",
		InstanceID: "test instance id",
		APIKey:     "test api key",
		TokenURL:   "https://iam.bluemix.net/oidc/token",
	}
}

// NewTestURL returns the shared, invalid url for tests.  Given paths are
// joined to the base, separted with /.
//
func NewTestURL(paths ...string) string {
	return NewTestClientConfig().BaseURL + strings.Join(paths, "/")
}

// NewTestAPI constructs and returns a new API and request ccontext.
//
func NewTestAPI(t *testing.T, c *ClientConfig) (*API, context.Context, error) {
	if c == nil {
		cp := NewTestClientConfig()
		c = &cp
	}
	api, err := New(*c, DefaultTransport())
	return api, context.Background(), err
}

// MockAuth tells `gock` to respond to token auth requests.
//
func MockAuth() *gock.Response {
	return MockURL("https://iam.bluemix.net/oidc/token", http.StatusOK, "{}")
}

// MockAuthURL mocks an auth endpoint and an api endpoint.
//
func MockAuthURL(url string, status int, json interface{}) *gock.Response {
	MockAuth()
	return MockURL(url, status, json)
}

// MockAuthURL mocks an api endpoint.
//
func MockURL(url string, status int, json interface{}) *gock.Response {
	return gock.New(url).Reply(status).JSON(json)
}

// Tests the API methods for keys.
//
func TestKeys(t *testing.T) {
	testKey := "2n4y2-4ko2n-4m23f-23j3r"
	newRootKey := &Key{
		ID:          "48bn3-3h4o-o4in5-34in9",
		Name:        "RootKey1",
		Extractable: false,
	}
	newStandardKey := &Key{
		ID:          "h934h-a984h-50jir-4903",
		Name:        "StandardKey1",
		Extractable: true,
	}

	testKeys := &Keys{
		Metadata: KeysMetadata{
			CollectionType: "json",
			NumberOfKeys:   2,
		},
		Keys: []Key{
			Key{
				ID:          testKey,
				Name:        "Key1",
				Extractable: false,
			},
			Key{
				ID:          "5ngy2-kko9n-4mj5f-w3jer",
				Name:        "Key2",
				Extractable: true,
			},
		},
	}

	keysActionDEK := KeysActionRequest{
		PlainText:  "YWJjZGVmZ2hpamtsbW5vCg==",
		CipherText: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA==",
	}

	keysActionCT := KeysActionRequest{
		CipherText: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA==",
	}

	keysActionPT := KeysActionRequest{
		PlainText: "YWJjZGVmZw==",
	}

	keysActionPTReWrap := KeysActionRequest{
		PlainText:  "YWJjZGVmZw==",
		CipherText: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA==",
	}

	keyActionAADPT := KeysActionRequest{
		PlainText: "dGhpcyBpcyBteSBrZXkgZm9yIGFhZAo=",
		AAD:       []string{"key1", "key2", "key3"},
	}

	keyActionAADCT := KeysActionRequest{
		AAD:        []string{"key1", "key2", "key3"},
		CipherText: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA==",
	}

	accessToken := "Bearer eyJraWQiOiIyMDE3MTAzMC0wMDowMDowMCIsImFsZyI6IlJTMjU2In0.eyJpYW1faWQiOiJpYW0tU2VydmljZUlkLWIwMDk1ZDFlLWMyNDUtNGFhZC04NmJlLTQ1ZmM3YzIxOTllMCIsImlkIjoiaWFtLVNlcnZpY2VJZC1iMDA5NWQxZS1jMjQ1LTRhYWQtODZiZS00NWZjN2MyMTk5ZTAiLCJyZWFsbWlkIjoiaWFtIiwiaWRlbnRpZmllciI6IlNlcnZpY2VJZC1iMDA5NWQxZS1jMjQ1LTRhYWQtODZiZS00NWZjN2MyMTk5ZTAiLCJzdWIiOiJTZXJ2aWNlSWQtYjAwOTVkMWUtYzI0NS00YWFkLTg2YmUtNDVmYzdjMjE5OWUwIiwic3ViX3R5cGUiOiJTZXJ2aWNlSWQiLCJhY2NvdW50Ijp7ImJzcyI6ImZiNDc0ODU1YTNlNzZjMWNlM2FhZWJmNTdlMGYxYTlmIn0sImlhdCI6MTUxODU1MDQ2NSwiZXhwIjoxNTE4NTU0MDY1LCJpc3MiOiJodHRwczovL2lhbS5uZy5ibHVlbWl4Lm5ldC9vaWRjL3Rva2VuIiwiZ3JhbnRfdHlwZSI6InVybjppYm06cGFyYW1zOm9hdXRoOmdyYW50LXR5cGU6YXBpa2V5Iiwic2NvcGUiOiJvcGVuaWQiLCJjbGllbnRfaWQiOiJkZWZhdWx0In0.XhXq7KT1CvuLekorCS_-YPkOCyx9unuj0JMIu7QYrJdRhLqC4VW5967kjllLVdvejZuEa7Nb7Anyoztcy-4VikhR5-wJx-eG4I6qf92QbLukXpRwFUaL7Y5qqJXsluxOOUsPOyeVNlUcpPPjkCHO79-Z2X68E7HV_XZr7T78Et-ea3MPW5fSF8112JbDGBbcPuzD7gtCtoHR9_MSjG7OU4b_LD_rkjR0tCaEClT9u7HM584FokXHSRCqE89IfkmRAlNcGMyMaYm6NDGuui81rna2lczR9IrkCHYluNNjrIEIUcz0g3xY2qdnSXcQFi7T8Ehaedj2mC3M4bQJ8DSbLQ"
	payload := "test string"
	keyURL := NewTestURL("/api/v2/key")
	keysURL := NewTestURL("/api/v2/keys")

	cases := TestCases{
		{
			"New API",
			func(t *testing.T, _ *API, _ context.Context) error {
				testapi, err := New(NewTestClientConfig(), DefaultTransport())
				assert.NotNil(t, testapi)
				return err
			},
		},
		{
			"New API with Logger",
			func(t *testing.T, _ *API, _ context.Context) error {
				var l Logger
				testapi, err := NewWithLogger(NewTestClientConfig(), DefaultTransport(), l)
				assert.NotNil(t, testapi)

				// hard-to-reach bits:
				c := NewTestClientConfig()
				c.BaseURL = ":"
				_, err = NewWithLogger(c, nil, l)
				assert.EqualError(t, err, "parse :/api/v2/: missing protocol scheme")

				return nil
			},
		},
		{
			"Timeout",
			func(t *testing.T, _ *API, _ context.Context) error {
				cfg := NewTestClientConfig()
				cfg.Timeout = 0.001
				api, err := New(cfg, DefaultTransport())
				assert.NoError(t, err)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
				defer cancel()

				mux := http.NewServeMux()
				server := httptest.NewServer(mux)
				route := "/"
				u, err := url.Parse(server.URL + route)
				assert.NoError(t, err)

				done := make(chan struct{})
				mux.HandleFunc(route,
					func(w http.ResponseWriter, r *http.Request) {
						<-done
					},
				)

				actual := make(chan error)
				go func() {
					req := &http.Request{
						URL: u,
					}
					_, err := api.HttpClient.Do(req)
					actual <- err
				}()

				select {
				case <-ctx.Done():
					t.Log("didn't time out")
					t.Fail()
					<-actual
				case err := <-actual:
					netErr, ok := err.(net.Error)
					assert.True(t, ok)
					assert.True(t, netErr.Timeout())
				}

				close(done)
				return nil
			},
		},
		{
			"Get Keys",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keysURL, http.StatusOK, testKeys)

				keys, err := api.GetKeys(ctx, 10, 0)
				assert.NoError(t, err)
				assert.NotZero(t, keys.Metadata.NumberOfKeys)

				return nil
			},
		},
		{
			"Wrap Create DEK",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, keysActionDEK)
				MockAuthURL(keyURL, http.StatusOK, keysActionDEK)

				unwrappedDEK, cipherText, err := api.WrapCreateDEK(ctx, testKey, nil)
				assert.NoError(t, err)
				assert.NotEqual(t, unwrappedDEK, cipherText)

				plainText, err := api.Unwrap(ctx, testKey, cipherText, nil)
				assert.NoError(t, err)
				assert.Equal(t, string(unwrappedDEK), string(plainText))

				return nil
			},
		},
		{
			"Wrap Unwrap v2",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, keysActionCT)
				MockAuthURL(keyURL, http.StatusOK, keysActionPT)

				cipherText, err := api.Wrap(ctx, testKey, []byte(keysActionPT.PlainText), nil)
				assert.NoError(t, err)
				assert.NotEqual(t, keysActionPT.PlainText, cipherText)

				plainText, rewrap, err := api.UnwrapV2(ctx, testKey, cipherText, nil)
				assert.NoError(t, err)
				assert.Equal(t, keysActionPT.PlainText, string(plainText))
				assert.Equal(t, "", string(rewrap))

				return nil
			},
		},
		{
			"Imported Create Delete",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, testKeys)
				ks, err := api.GetKeys(ctx, 100, 0)
				assert.NoError(t, err)
				startCount := ks.Metadata.NumberOfKeys
				testKeys.Keys = append([]Key{*newRootKey}, testKeys.Keys...)
				testKeys.Metadata.NumberOfKeys++

				MockAuthURL(keyURL, http.StatusCreated, testKeys)
				k, err := api.CreateImportedRootKey(ctx, "test", nil, payload, "", "")
				assert.NoError(t, err)
				key1 := k.ID
				testKeys.Keys = append([]Key{*newStandardKey}, testKeys.Keys...)
				testKeys.Metadata.NumberOfKeys++

				MockAuthURL(keyURL, http.StatusCreated, testKeys)
				expiration := time.Now().Add(24 * time.Hour)
				k, err = api.CreateImportedRootKey(ctx, "testtimeout", &expiration, "asdfqwerasdfqwerasdfqwerasdfqwer", "", "")
				assert.NoError(t, err)
				key2 := k.ID

				MockAuthURL(keyURL, http.StatusOK, testKeys)
				ks, err = api.GetKeys(ctx, 100, 0)
				assert.NoError(t, err)
				assert.Equal(t, startCount+2, ks.Metadata.NumberOfKeys, "Created 2 keys, counts don't match")
				testKeys.Keys = append(testKeys.Keys[:1], testKeys.Keys[2:]...)
				testKeys.Metadata.NumberOfKeys--

				MockAuthURL(keyURL, http.StatusOK, "{}")
				k, err = api.DeleteKey(ctx, key1, ReturnMinimal)
				assert.NoError(t, err)

				MockAuthURL(keyURL, http.StatusOK, testKeys)
				testKeys.Keys = append(testKeys.Keys[:0], testKeys.Keys[1:]...)
				testKeys.Metadata.NumberOfKeys--
				k, err = api.DeleteKey(ctx, key2, ReturnRepresentation)
				assert.NoError(t, err)

				MockAuthURL(keyURL, http.StatusOK, testKeys)
				ks, err = api.GetKeys(ctx, 0, 0)
				assert.NoError(t, err)
				assert.Equal(t, startCount, ks.Metadata.NumberOfKeys, "Deleted 2 keys, counts don't match")
				return nil
			},
		},
		{
			"Create Delete",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, testKeys)
				ks, err := api.GetKeys(ctx, 100, 0)
				assert.NoError(t, err)
				startCount := ks.Metadata.NumberOfKeys
				testKeys.Keys = append([]Key{*newRootKey}, testKeys.Keys...)
				testKeys.Metadata.NumberOfKeys++

				MockAuthURL(keyURL, http.StatusCreated, testKeys)
				k, err := api.CreateRootKey(ctx, "test", nil)
				assert.NoError(t, err)
				key1 := k.ID
				testKeys.Keys = append([]Key{*newStandardKey}, testKeys.Keys...)
				testKeys.Metadata.NumberOfKeys++

				MockAuthURL(keyURL, http.StatusCreated, testKeys)
				expiration := time.Now().Add(24 * time.Hour)
				k, err = api.CreateRootKey(ctx, "testtimeout", &expiration)
				assert.NoError(t, err)
				key2 := k.ID

				MockAuthURL(keyURL, http.StatusOK, testKeys)
				ks, err = api.GetKeys(ctx, 100, 0)
				assert.NoError(t, err)
				assert.Equal(t, startCount+2, ks.Metadata.NumberOfKeys, "Created 2 keys, counts don't match")
				testKeys.Keys = append(testKeys.Keys[:1], testKeys.Keys[2:]...)
				testKeys.Metadata.NumberOfKeys--

				MockAuthURL(keyURL, http.StatusOK, "{}")
				k, err = api.DeleteKey(ctx, key1, ReturnMinimal)
				assert.NoError(t, err)

				MockAuthURL(keyURL, http.StatusOK, testKeys)
				testKeys.Keys = append(testKeys.Keys[:0], testKeys.Keys[1:]...)
				testKeys.Metadata.NumberOfKeys--
				k, err = api.DeleteKey(ctx, key2, ReturnRepresentation)
				assert.NoError(t, err)

				MockAuthURL(keyURL, http.StatusOK, testKeys)
				ks, err = api.GetKeys(ctx, 0, 0)
				assert.NoError(t, err)
				assert.Equal(t, startCount, ks.Metadata.NumberOfKeys, "Deleted 2 keys, counts don't match")

				return nil
			},
		},
		{
			"Imported Rotate",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, testKeys)
				MockAuthURL(keyURL, http.StatusCreated, testKeys)

				k, err := api.CreateImportedRootKey(ctx, "test", nil, "asdfqwerasdfqwerasdfqwerasdfqwer", "", "")
				assert.NoError(t, err)
				key1 := k.ID

				return api.Rotate(ctx, key1, "qwerasdfqwerasdfqwerasdfqwerasdf")

			},
		},
		{
			"Imported Rotate Unwrap",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, testKeys)
				MockAuthURL(keyURL, http.StatusCreated, testKeys)
				MockAuthURL(keyURL, http.StatusOK, keysActionPT)
				MockAuthURL(keyURL, http.StatusOK, keysActionPTReWrap)

				k, err := api.CreateImportedRootKey(ctx, "test", nil, "asdfqwerasdfqwerasdfqwerasdfqwer", "", "")
				assert.NoError(t, err)
				key1 := k.ID
				cipherText, err := api.Wrap(ctx, key1, []byte(keysActionPT.PlainText), nil)
				assert.NoError(t, err)
				assert.NotEqual(t, keysActionPT.PlainText, cipherText)

				errRotate := api.Rotate(ctx, key1, "qwerasdfqwerasdfqwerasdfqwerasdf")
				assert.NoError(t, errRotate)

				plainText, rewrap, err := api.UnwrapV2(ctx, key1, cipherText, nil)
				assert.NoError(t, err)
				assert.Equal(t, keysActionPTReWrap.PlainText, string(plainText))
				assert.Equal(t, keysActionPTReWrap.CipherText, string(rewrap))
				return nil
			},
		},
		{
			"Rotate Unwrap",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, testKeys)
				MockAuthURL(keyURL, http.StatusCreated, testKeys)
				MockAuthURL(keyURL, http.StatusOK, keysActionPT)
				MockAuthURL(keyURL, http.StatusOK, keysActionPTReWrap)

				k, err := api.CreateRootKey(ctx, "test", nil)
				assert.NoError(t, err)
				key1 := k.ID

				cipherText, err := api.Wrap(ctx, key1, []byte(keysActionPT.PlainText), nil)
				assert.NoError(t, err)
				assert.NotEqual(t, keysActionPT.PlainText, cipherText)

				errRotate := api.Rotate(ctx, key1, "")
				assert.NoError(t, errRotate)

				plainText, rewrap, err := api.UnwrapV2(ctx, key1, cipherText, nil)
				assert.NoError(t, err)
				assert.Equal(t, keysActionPTReWrap.PlainText, string(plainText))
				assert.Equal(t, keysActionPTReWrap.CipherText, string(rewrap))
				return nil
			},
		},
		{
			"Timeout",
			func(t *testing.T, api *API, ctx context.Context) error {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
				defer cancel()
				c := NewTestClientConfig()
				c.BaseURL = DefaultBaseURL + ":22"
				c.Verbose = VerboseAll

				a, ctx, err := NewTestAPI(t, nil)
				assert.NoError(t, err)
				gock.InterceptClient(&a.HttpClient)

				body := "context deadline exceeded"
				MockAuthURL(keyURL, http.StatusRequestTimeout, "").BodyString(body)
				_, err = a.GetKeys(ctx, 0, 0)
				assert.EqualError(t, err, body)
				return nil
			},
		},

		{
			"Auth Context",
			func(t *testing.T, api *API, ctx context.Context) error {
				ctx = NewContextWithAuth(ctx, accessToken)
				body := "Bad Request: Token is expired"
				MockAuthURL(keyURL, http.StatusBadRequest, "").BodyString(body)
				_, err := api.GetKeys(ctx, 0, 0)
				assert.EqualError(t, err, body)
				return nil
			},
		},
		{
			"Auth in Config",
			func(t *testing.T, api *API, ctx context.Context) error {
				c := &ClientConfig{
					BaseURL:       NewTestURL(),
					Authorization: accessToken,
					InstanceID:    "0647c737-906d-438a-8a68-2c187e11b29b",
					Verbose:       VerboseAllNoRedact,
				}

				a, ctx, err := NewTestAPI(t, c)
				assert.NoError(t, err)
				gock.InterceptClient(&a.HttpClient)

				body := "Bad Request: Token is expired"
				MockAuthURL(keyURL, http.StatusBadRequest, "").BodyString(body)
				_, err = a.GetKeys(ctx, 0, 0)
				assert.EqualError(t, err, body)
				return nil
			},
		},
		{
			"Wrap and Unwrap AAD",
			func(t *testing.T, api *API, ctx context.Context) error {
				body := "Unprocessable Entity: Invalid ciphertext"

				MockAuthURL(keyURL, http.StatusOK, keyActionAADCT)
				MockAuthURL(keyURL, http.StatusOK, keysActionPT)
				MockAuthURL(keyURL, http.StatusUnprocessableEntity, "").BodyString(body)

				ciphertext, err := api.Wrap(ctx, testKey, []byte(keyActionAADPT.PlainText), &keyActionAADPT.AAD)
				assert.NoError(t, err)

				plainText, err := api.Unwrap(ctx, testKey, ciphertext, &keyActionAADCT.AAD)
				assert.NoError(t, err)
				assert.Equal(t, keysActionPT.PlainText, string(plainText))

				// Test bad aad
				aad := []string{"key44", "key55"}
				_, err = api.Unwrap(ctx, testKey, ciphertext, &aad)
				assert.EqualError(t, err, body)
				return nil
			},
		},
		{
			"API Key Timeout",
			func(t *testing.T, api *API, ctx context.Context) error {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
				defer cancel()
				defer gock.Off()

				c := NewTestClientConfig()
				c.TokenURL = "https://iam.bluemix.net:22/oidc/token"

				gock.New(keyURL).Reply(http.StatusOK).JSON(keyActionAADCT)
				a, _, err := NewTestAPI(t, &c)
				assert.NoError(t, err)

				body := "context deadline exceeded"
				gock.New("https://iam.bluemix.net/oidc/token").Reply(http.StatusRequestTimeout).BodyString(body)
				gock.InterceptClient(&a.HttpClient)

				_, err = a.GetKeys(ctx, 0, 0)
				// failing ATM:
				//assert.EqualError(t, err, "context deadline exceeded")
				return nil
			},
		},

		{
			"Bad Config",
			func(t *testing.T, api *API, ctx context.Context) error {
				c := NewTestClientConfig()
				c.Verbose = 5

				_, _, err := NewTestAPI(t, &c)
				assert.EqualError(t, err, "verbose value is out of range")

				return nil
			},
		},
		{
			"Bad API Key",
			func(t *testing.T, api *API, ctx context.Context) error {
				api, ctx, err := NewTestAPI(t, nil)
				ctx, cancel := context.WithTimeout(ctx, time.Second*2)
				defer cancel()
				defer gock.Off()

				c := NewTestClientConfig()
				c.APIKey = "BadOne"

				gock.New(keyURL).Reply(http.StatusOK).JSON(testKeys)
				a, ctx, _ := NewTestAPI(t, &c)

				body := "BXNIM0415E:Provided API key could not be found"
				gock.New("https://iam.bluemix.net/oidc/token").Reply(http.StatusBadRequest).BodyString(body)
				gock.InterceptClient(&a.HttpClient)

				_, err = api.GetKeys(ctx, 0, 0)
				assert.EqualError(t, err, body)

				return nil
			},
		},
		{
			"Create Key Without Expiration",
			func(t *testing.T, api *API, ctx context.Context) error {
				// expectedReq := `{"metadata":{"collectionType":"application/vnd.ibm.kms.key+json","collectionTotal":1},"resources":[{"name":"test","type":"application/vnd.ibm.kms.key+json","extractable":false}]}`
				api.AuthToken = AuthToken{
					AccessToken: "token",
					expiration:  time.Now().Add(time.Minute),
				}
				gock.New(keysURL).
					// This is busted ATM, causes one of the *next* tests to segfault:
					//
					// AddMatcher(func(req *http.Request, greq *gock.Request) (bool, error) {
					//	body, merr := ioutil.ReadAll(req.Body)
					//	if merr != nil {
					//		return false, merr
					//	}
					//	return string(body) == expectedReq, nil // No expiration in req body.
					// }).
					Reply(http.StatusCreated).
					JSON(testKeys)

				_, err := api.CreateRootKey(ctx, "test", nil)
				return err
			},
		},
		{
			"Create",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusCreated, testKeys)
				MockAuthURL(keyURL, http.StatusServiceUnavailable, "{}")
				MockAuthURL(keyURL, http.StatusServiceUnavailable, "{}")

				_, err := api.CreateImportedRootKey(ctx, "test", nil, payload, "abc", "")
				assert.NoError(t, err)

				_, err = api.CreateKey(ctx, "test", nil, false)
				assert.Error(t, err)

				_, err = api.CreateImportedKey(ctx, "test", nil, "", false, "", "")
				assert.Error(t, err)

				return nil
			},
		},
		{
			"Rotate",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, testKeys)
				MockAuthURL(keyURL, http.StatusCreated, testKeys)
				MockAuthURL(keyURL, http.StatusServiceUnavailable, testKeys)

				k, err := api.CreateRootKey(ctx, "test", nil)
				assert.NoError(t, err)

				key1 := k.ID
				err = api.Rotate(ctx, key1, "")
				assert.NoError(t, err)

				err = api.Rotate(ctx, key1, "")
				assert.Error(t, err)

				return nil

			},
		},
		{
			"Get Key",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, testKeys)
				MockAuthURL(keyURL, http.StatusServiceUnavailable, "{}")

				key, err := api.GetKey(ctx, testKey)
				assert.NoError(t, err)
				assert.Equal(t, testKey, key.ID)

				key, err = api.GetKey(ctx, testKey)
				assert.Error(t, err)

				return nil
			},
		},

		{
			"Wrap Unwrap",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, keysActionCT)
				MockAuthURL(keyURL, http.StatusOK, keysActionPT)
				MockAuthURL(keyURL, http.StatusServiceUnavailable, "")

				cipherText, err := api.Wrap(ctx, testKey, []byte(keysActionPT.PlainText), nil)
				assert.NoError(t, err)
				assert.NotEqual(t, keysActionPT.PlainText, cipherText)

				plainText, err := api.Unwrap(ctx, testKey, cipherText, nil)
				assert.NoError(t, err)
				assert.Equal(t, keysActionPT.PlainText, string(plainText))

				_, err = api.Wrap(ctx, testKey, []byte("a"), nil)
				assert.EqualError(t, err, "illegal base64 data at input byte 0")

				_, _, err = api.WrapCreateDEK(ctx, testKey, &[]string{"a"})
				assert.Error(t, err)

				return nil
			},
		},
		{
			"Delete Key",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusServiceUnavailable, "{}")
				_, err := api.DeleteKey(ctx, testKey, ReturnMinimal)
				assert.Error(t, err)
				return nil
			},
		},
		{
			"Create Standard Key",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keysURL, http.StatusOK, testKeys)
				_, err := api.CreateStandardKey(ctx, "", nil)
				return err
			},
		},
		{
			"Create Imported Standard Key",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keysURL, http.StatusOK, testKeys)
				_, err := api.CreateImportedStandardKey(ctx, "", nil, payload)
				return err
			},
		},
	}
	cases.Run(t)
}

// Tests the API for misc. funcionality.
//
func TestMisc(t *testing.T) {
	cases := TestCases{
		{
			"Merge Headers",
			func(t *testing.T, _ *API, _ context.Context) error {
				h1 := http.Header{
					"keyh1": {"v1, v2"},
				}
				h2 := http.Header{
					"keyh2": {"v2.1, v2.2"},
				}

				expectedResult := http.Header{
					"keyh1": {"v1, v2"},
					"keyh2": {"v2.1, v2.2"},
				}

				hm := mergeHeaders(h1, h2)
				assert.Equal(t, hm, expectedResult)
				return nil
			},
		},
		{
			"Clone Headers",
			func(t *testing.T, _ *API, _ context.Context) error {
				h1 := http.Header{
					"keyh1": {"v1", "v2"},
				}

				hc := cloneHeader(h1)
				assert.Equal(t, hc, h1)
				return nil
			},
		},
		{
			"Redact Values",
			func(t *testing.T, _ *API, _ context.Context) error {
				s1 := "a:b,c:d,e:f"
				r := []string{"b", "d"}
				s := redact(s1, r)
				assert.Equal(t, "a:***Value redacted***,c:***Value redacted***,e:f", s)
				assert.Equal(t, s1, redact(s1, []string{}))
				assert.Equal(t, s1, noredact(s1, r))
				return nil
			},
		},
	}
	cases.Run(t)
}

// Tests the API methods for policies.
//
func TestPolicies(t *testing.T) {
	testKey := "2n4y2-4ko2n-4m23f-23j3r"
	testKeys := &Keys{
		Metadata: KeysMetadata{
			CollectionType: "json",
			NumberOfKeys:   2,
		},
		Keys: []Key{
			Key{
				ID:          testKey,
				Name:        "Key1",
				Extractable: false,
			},
			Key{
				ID:          "5ngy2-kko9n-4mj5f-w3jer",
				Name:        "Key2",
				Extractable: true,
			},
		},
	}
	keyURL := NewTestURL("/api/v2/key")

	cases := TestCases{
		{
			"Policy Replace",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, testKeys)
				MockAuthURL("/api/v2/keys/"+testKey+"/policy", http.StatusOK, testKeys)

				_, err := api.SetPolicy(ctx, testKey, ReturnMinimal, 3)
				assert.NoError(t, err)

				_, err = api.SetPolicy(ctx, "", ReturnMinimal, 3)
				assert.Error(t, err)

				return nil
			},
		},
		{
			"Policy Get",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, testKeys)
				MockAuthURL("/api/v2/keys/"+testKey+"/policy", http.StatusOK, testKeys)

				_, err := api.GetPolicy(ctx, testKey)
				assert.NoError(t, err)

				_, err = api.GetPolicy(ctx, "")
				assert.Error(t, err)

				return nil
			},
		},
	}
	cases.Run(t)

}

// Tests the API methods for lockers.
//
func TestLockers(t *testing.T) {
	locker := "5a03c407-f170-4ce8-885f-1d376e82f4b6"
	endpoint := "/api/v2/lockers"

	cases := TestCases{
		{
			"Locker Create",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(NewTestURL()+endpoint, http.StatusOK, &LockerCreateRequest{600, 600})
				MockAuthURL(NewTestURL()+endpoint, http.StatusServiceUnavailable, "")

				_, err := api.CreateLocker(ctx, "", 600, 600)
				assert.NoError(t, err)

				_, err = api.CreateLocker(ctx, "", 600, 600)
				assert.Error(t, err)

				return nil
			},
		},
		{
			"Locker Transport Key Get",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(NewTestURL()+endpoint+"/"+locker, http.StatusOK, &LockerKeyResponse{})
				MockAuthURL(NewTestURL()+endpoint+"/"+locker, http.StatusOK, "")

				_, err := api.GetLockerTransportKey(ctx, "", locker)
				assert.NoError(t, err)

				_, err = api.GetLockerTransportKey(ctx, "", locker)
				assert.Error(t, err)

				return nil
			},
		},
		{
			"Locker Metadata Get",
			func(t *testing.T, api *API, ctx context.Context) error {
				md := []*LockerMetadata{&LockerMetadata{}}
				MockAuthURL(NewTestURL()+endpoint, http.StatusOK, md)
				MockAuthURL(NewTestURL()+endpoint, http.StatusServiceUnavailable, "")

				_, err := api.GetLockerMetadata(ctx, "", locker)
				assert.NoError(t, err)

				_, err = api.GetLockerMetadata(ctx, "", locker)
				assert.Error(t, err)

				return nil
			},
		},
		{
			"HTTP internals",
			func(t *testing.T, api *API, ctx context.Context) error {
				gock.New(NewTestURL()).Get("/").Reply(http.StatusOK).JSON("")
				s := ""
				err := api.doHTTPRequest(ctx, http.MethodGet, ":", &s, nil, nil, "", "")
				assert.Error(t, err)

				gock.New(NewTestURL()).Get("/").Reply(http.StatusOK).JSON("")
				MockAuth()
				badObj := func() {}
				err = api.doHTTPRequest(ctx, http.MethodGet, "/", &s, nil, nil, badObj, "")
				assert.EqualError(t, err, "json: unsupported type: func()")

				gock.New(NewTestURL()).Get("/").Reply(http.StatusOK).JSON("{}")
				MockAuth()
				c, cancel := context.WithCancel(ctx)
				cancel()
				err = api.doHTTPRequest(c, http.MethodGet, "/", &s, nil, nil, nil, "")
				assert.EqualError(t, err, "context canceled")

				return nil
			},
		},
		{
			"API Internals",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(NewTestURL()+endpoint, http.StatusNoContent, "")
				MockAuthURL(NewTestURL()+endpoint, http.StatusServiceUnavailable, "{'resources':[{'errorMsg':'none'}]}")

				_, err := api.GetLockerMetadata(ctx, "", locker)
				assert.NoError(t, err)

				_, err = api.GetLockerMetadata(ctx, "", locker)
				assert.Error(t, err)

				// hard-to-reach bits:
				orig := ""
				tok, err := api.getAccessToken(context.WithValue(ctx, authContextKey, orig))
				assert.NoError(t, err)
				assert.Exactly(t, tok, orig)

				api.Config.TokenURL = ":"
				_, err = api.getAccessToken(ctx)
				assert.Error(t, err)

				return nil
			},
		},
		{
			"Dump Implementations",
			func(t *testing.T, api *API, ctx context.Context) error {
				codes := []int{
					http.StatusOK,
					http.StatusCreated,
					http.StatusNoContent,
					http.StatusTeapot,
				}
				rs := []string{}
				rb := []byte("access_token")
				log := NewLogger(func(args ...interface{}) {})
				req := func() *http.Request {
					req, err := http.NewRequest(http.MethodGet, NewTestURL(), nil)
					assert.NoError(t, err)
					return req
				}
				for _, dump := range dumpers {
					for _, code := range codes {
						res := http.Response{StatusCode: code}
						dump(req(), &res, []byte{}, rb, log, rs)
					}
				}
				return nil
			},
		},
	}
	cases.Run(t)
}

// TestCase holds a subtest name and callable.
//
type TestCase struct {
	Name string
	Call func(*testing.T, *API, context.Context) error
}

// TestCases are a slice of TestCase structs.
//
type TestCases []TestCase

// Run executes all of the test cases, with a handy setup beforehand.
//
func (cases TestCases) Run(t *testing.T) {
	defer gock.Off()

	for _, test := range cases {
		api, ctx := cases.Setup(t)
		defer gock.RestoreClient(&api.HttpClient)

		t.Run(test.Name, func(t *testing.T) {
			assert.NoError(t, test.Call(t, api, ctx))
		})
		gock.Flush()
	}
}

// Setup creates and returns an API and a request context.
//
func (cases TestCases) Setup(t *testing.T) (*API, context.Context) {
	api, ctx, err := NewTestAPI(t, nil)
	assert.NoError(t, err)
	gock.InterceptClient(&api.HttpClient)
	return api, ctx
}
