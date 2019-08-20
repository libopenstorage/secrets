package kp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// API combines the necessary members for interacting with the KP API.
type API struct {
	URL        *url.URL
	HttpClient http.Client
	Headers    http.Header
	Dump       Dump
	Config     ClientConfig
	AuthToken  AuthToken
	Logger     Logger
}

// New creates and returns an API without logging.
func New(config ClientConfig, transport http.RoundTripper) (*API, error) {
	return NewWithLogger(config, transport, nil)
}

// NewWithLogger creates and returns an API with logging.  The
// error value will be non-nil if the config is invalid.
func NewWithLogger(config ClientConfig, transport http.RoundTripper, logger Logger) (*API, error) {
	//TODO Add some config validation
	if transport == nil {
		transport = DefaultTransport()
	}
	if logger == nil {
		logger = NewLogger(func(args ...interface{}) {
			fmt.Println(args...)
		})
	}
	if config.Verbose > len(dumpers)-1 || config.Verbose < 0 {
		return nil, errors.New("verbose value is out of range")
	}
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	keysURL := fmt.Sprintf("%s/api/v2/", config.BaseURL)
	u, err := url.Parse(keysURL)
	if err != nil {
		return nil, err
	}
	return &API{
		URL: u,
		HttpClient: http.Client{
			Timeout:   time.Duration(config.Timeout * float64(time.Second)),
			Transport: transport,
		},
		Headers: http.Header{
			"bluemix-instance": {config.InstanceID},
			"accept":           {"application/vnd.ibm.collection+json"},
		},
		Dump:   dumpers[config.Verbose],
		Config: config,
		Logger: logger,
	}, nil
}

// CreateRootKey creates a new, non-extractable key resource without
// key material.
func (a *API) CreateRootKey(ctx context.Context, name string, expiration *time.Time) (*Key, error) {
	return a.CreateKey(ctx, name, expiration, false)
}

// CreateStandardKey creates a new, extractable key resource without
// key material.
func (a *API) CreateStandardKey(ctx context.Context, name string, expiration *time.Time) (*Key, error) {
	return a.CreateKey(ctx, name, expiration, true)
}

// CreateImportedRootKey creates a new, non-extractable key resource
// with the given key material.
func (a *API) CreateImportedRootKey(ctx context.Context, name string, expiration *time.Time, payload, lockerID, importToken string) (*Key, error) {
	return a.CreateImportedKey(ctx, name, expiration, payload, false, lockerID, importToken)
}

// CreateStandardKey creates a new, extractable key resource with the
// given key material.
func (a *API) CreateImportedStandardKey(ctx context.Context, name string, expiration *time.Time, payload string) (*Key, error) {
	return a.CreateImportedKey(ctx, name, expiration, payload, true, "", "")
}

// Delete deletes a key resource by specifying the ID of the key.
func (a *API) DeleteKey(ctx context.Context, id string, prefer PreferReturn) (*Key, error) {
	additionalHeader := http.Header{
		"Prefer": {preferHeaders[prefer]},
	}
	keys := Keys{}
	err := a.doHTTPRequest(ctx, "DELETE", keysBase, &id, nil, additionalHeader, nil, &keys)
	if err != nil {
		return nil, err
	}

	if len(keys.Keys) > 0 {
		return &keys.Keys[0], nil
	}

	return nil, nil
}

// GetKeys retrieves a collection of keys that can be paged through.
func (a *API) GetKeys(ctx context.Context, limit int, offset int) (*Keys, error) {
	keys := Keys{}
	v := url.Values{}
	if limit == 0 {
		limit = 2000
	}
	v.Set("limit", strconv.Itoa(limit))
	v.Set("offset", strconv.Itoa(offset))

	err := a.doHTTPRequest(ctx, "GET", keysBase, nil, v, nil, nil, &keys)
	return &keys, err
}

// GetKey retrieves a key by ID.
func (a *API) GetKey(ctx context.Context, id string) (*Key, error) {
	keys := Keys{}
	err := a.doHTTPRequest(ctx, "GET", keysBase, &id, nil, nil, nil, &keys)
	if err != nil {
		return nil, err
	}
	return &keys.Keys[0], nil
}

// Wrap calls the wrap action with the given plain text.
func (a *API) Wrap(ctx context.Context, id string, plainText []byte, additionalAuthData *[]string) ([]byte, error) {
	keysAction, err := a.wrapIt(ctx, id, plainText, additionalAuthData)
	if err != nil {
		return nil, err
	}
	return ([]byte)(keysAction.CipherText), nil
}

// WrapCreateDEK calls the wrap action without plain text.
func (a *API) WrapCreateDEK(ctx context.Context, id string, additionalAuthData *[]string) (DEK, cipherText []byte, err error) {
	keysAction, err := a.wrapIt(ctx, id, nil, additionalAuthData)
	if err != nil {
		return nil, nil, err
	}
	DEK = []byte(keysAction.PlainText)
	return DEK, ([]byte)(keysAction.CipherText), nil
}

// Unwrap is deprecated since it returns only plaintext and doesn't know how to handle rotation.
func (a *API) Unwrap(ctx context.Context, id string, cipherText []byte, additionalAuthData *[]string) (plainText []byte, err error) {
	if plainText, _, err = a.UnwrapV2(ctx, id, cipherText, additionalAuthData); err != nil {
		return nil, err
	}
	return plainText, nil
}

// Unwrap with rotation support.
func (a *API) UnwrapV2(ctx context.Context, id string, cipherText []byte, additionalAuthData *[]string) (plainText []byte, rewrapped []byte, err error) {
	keysAction := &KeysActionRequest{
		CipherText: string(cipherText),
	}

	if additionalAuthData != nil {
		keysAction.AAD = *additionalAuthData
	}

	respAction, err := a.doKeysAction(ctx, &id, "unwrap", keysAction)
	if err != nil {
		return nil, nil, err
	}
	plainText = []byte(respAction.PlainText)
	rewrapped = []byte(respAction.CipherText)
	return plainText, rewrapped, nil
}

// Rotate rotates a CRK.
func (a *API) Rotate(ctx context.Context, id, payload string) (err error) {
	_, err = a.doKeysAction(ctx, &id, "rotate", &KeysActionRequest{
		Payload: payload,
	})
	if err != nil {
		return err
	}
	return nil
}

// Create creates a new KP key.
func (a *API) CreateKey(ctx context.Context, name string, expiration *time.Time, extractable bool) (*Key, error) {
	key := Key{
		Name:        name,
		Type:        keyType,
		Extractable: extractable,
	}
	if expiration != nil {
		key.Expiration = expiration
	}
	keysRequest := Keys{
		Metadata: KeysMetadata{
			CollectionType: keyType,
			NumberOfKeys:   1,
		},
		Keys: []Key{key},
	}
	keysResponse := Keys{}
	if err := a.doHTTPRequest(ctx, "POST", keysBase, nil, nil, nil, &keysRequest, &keysResponse); err != nil {
		return nil, err
	}
	return &keysResponse.Keys[0], nil
}

// CreateImportedKey creates a new KP key from the given key material.
func (a *API) CreateImportedKey(ctx context.Context, name string, expiration *time.Time, payload string, extractable bool, lockerID, importToken string) (*Key, error) {
	key := Key{
		Name:        name,
		Type:        keyType,
		Extractable: extractable,
		Payload:     payload,
		LockerKeyId: lockerID,
		ImportToken: importToken,
	}
	if expiration != nil {
		key.Expiration = expiration
	}
	if lockerID != "" {
		key.EncryptionAlgorithm = lockerEncAlgo
	}
	keysRequest := Keys{
		Metadata: KeysMetadata{
			CollectionType: keyType,
			NumberOfKeys:   1,
		},
		Keys: []Key{key},
	}
	keysResponse := Keys{}
	if err := a.doHTTPRequest(ctx, "POST", keysBase, nil, nil, nil, &keysRequest, &keysResponse); err != nil {
		return nil, err
	}
	return &keysResponse.Keys[0], nil
}

// CreateLocker creates a key locker.
func (a *API) CreateLocker(ctx context.Context, id string, expiration, maxAllowedRetrievals int) (*LockerMetadata, error) {
	req := LockerCreateRequest{
		MaxAllowedRetrievals: maxAllowedRetrievals,
		ExpiresInSeconds:     expiration,
	}
	res := LockerMetadata{}
	if err := a.doHTTPRequest(ctx, "POST", lockersBase, nil, nil, nil, &req, &res); err != nil {
		return nil, err
	} else {
		return &res, nil
	}
}

// GetLockerTransportKey retrieves the locker transport key.
func (a *API) GetLockerTransportKey(ctx context.Context, id, locker string) (*LockerKeyResponse, error) {
	res := LockerKeyResponse{}
	url := fmt.Sprintf("%s/%s", lockersBase, locker)
	if err := a.doHTTPRequest(ctx, "GET", url, nil, nil, nil, nil, &res); err != nil {
		return nil, err
	} else {
		return &res, nil
	}
}

// GetLockerMetadata retrieves the metadata of a locker.
func (a *API) GetLockerMetadata(ctx context.Context, id, locker string) ([]*LockerMetadata, error) {
	res := []*LockerMetadata{}
	if err := a.doHTTPRequest(ctx, "GET", lockersBase, nil, nil, nil, nil, &res); err != nil {
		return nil, err
	} else {
		return res, nil
	}
}

// GetPolicy retrieves a policy by Key ID.
func (a *API) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	policyresponse := Policies{}
	err := a.doPolicyHTTPRequest(ctx, "GET", keysBase, &id, policyBase, nil, nil, nil, &policyresponse)
	if err != nil {
		return nil, err
	}
	return &policyresponse.Policies[0], nil
}

// SetPolicy updates a policy resource by specifying the ID of the key and the rotation interval needed.
func (a *API) SetPolicy(ctx context.Context, id string, prefer PreferReturn, rotationInterval int) (*Policy, error) {
	additionalHeader := http.Header{
		"Prefer": {preferHeaders[prefer]},
	}

	policy := Policy{
		Type: policyType,
	}
	policy.Rotation.Interval = rotationInterval

	policyRequest := Policies{
		Metadata: PoliciesMetadata{
			CollectionType:   keyType,
			NumberOfPolicies: 1,
		},
		Policies: []Policy{policy},
	}

	policyresponse := Policies{}
	err := a.doPolicyHTTPRequest(ctx, "PUT", keysBase, &id, policyBase, nil, additionalHeader, &policyRequest, &policyresponse)
	if err != nil {
		return nil, err
	}
	return &policyresponse.Policies[0], nil
}

// wrapIt is a helper for performing an action on a key.
func (a *API) wrapIt(ctx context.Context, id string, plainText []byte, additionalAuthData *[]string) (*KeysActionRequest, error) {
	keysAction := &KeysActionRequest{}

	if plainText != nil {
		_, err := base64.StdEncoding.DecodeString(string(plainText))
		if err != nil {
			return nil, err
		}
		keysAction.PlainText = string(plainText)
	}
	if additionalAuthData != nil {
		keysAction.AAD = *additionalAuthData
	}
	keysAction, err := a.doKeysAction(ctx, &id, "wrap", keysAction)
	if err != nil {
		return nil, err
	}
	return keysAction, nil
}

// doKeysAction calls the KP API to perform an action on a key.
func (a *API) doKeysAction(ctx context.Context, id *string, action string, keysActionReq *KeysActionRequest) (*KeysActionRequest, error) {
	keyActionRsp := KeysActionRequest{}

	v := url.Values{}
	v.Set("action", action)

	err := a.doHTTPRequest(ctx, "POST", keysBase, id, v, nil, keysActionReq, &keyActionRsp)
	if err != nil {
		return nil, err
	}
	return &keyActionRsp, nil
}

// doHTTPRequest is a helper for calling the KP HTTP API.
func (a *API) doHTTPRequest(ctx context.Context, method, base string, id *string, queryParms url.Values, additionalHeaders http.Header, requestBody, responseBody interface{}) error {
	url, err := a.apiURL(base, id)
	if err != nil {
		return err
	}

	if queryParms != nil {
		url.RawQuery = queryParms.Encode()
	}

	var headers http.Header
	acccesToken, err := a.getAccessToken(ctx)
	if err != nil {
		return err
	}
	if additionalHeaders != nil {
		headers = cloneHeader(a.Headers)
		headers = mergeHeaders(additionalHeaders, headers)
	} else {
		headers = a.Headers
	}
	headers.Set("authorization", acccesToken)

	request := &http.Request{
		Method: method,
		URL:    url,
		Header: headers,
	}

	var reqBody []byte
	if requestBody != nil {
		reqBody, err = json.Marshal(requestBody)
		if err != nil {
			return err
		}
		request.Header.Add("Content-Length", strconv.Itoa(len(reqBody)))
		request.Body = ioutil.NopCloser(bytes.NewReader(reqBody))

		defer request.Body.Close()
	}

	c := make(chan error, 1)
	go func() { c <- a.sendRequest(request.WithContext(ctx), reqBody, responseBody) }()
	select {
	case <-ctx.Done():
		<-c // Wait for sendRequest to return.
		return ctx.Err()
	case err := <-c:
		return err
	}
}

// doHTTPRequest is a helper for calling the KP HTTP API.
func (a *API) doPolicyHTTPRequest(ctx context.Context, method, base string, id *string, policyBase string, queryParms url.Values, additionalHeaders http.Header, requestBody, responseBody interface{}) error {
	var err error
	var url *url.URL

	url, err = a.getPolicyApiURL(base, id, policyBase)

	if err != nil {
		return err
	}

	if queryParms != nil {
		url.RawQuery = queryParms.Encode()
	}

	var headers http.Header
	acccesToken, err := a.getAccessToken(ctx)
	if err != nil {
		return err
	}
	if additionalHeaders != nil {
		headers = cloneHeader(a.Headers)
		headers = mergeHeaders(additionalHeaders, headers)
	} else {
		headers = a.Headers
	}
	headers.Set("authorization", acccesToken)

	request := &http.Request{
		Method: method,
		URL:    url,
		Header: headers,
	}

	var reqBody []byte
	if requestBody != nil {
		reqBody, err = json.Marshal(requestBody)
		if err != nil {
			return err
		}
		request.Header.Add("Content-Length", strconv.Itoa(len(reqBody)))
		request.Body = ioutil.NopCloser(bytes.NewReader(reqBody))
		defer request.Body.Close()
	}

	c := make(chan error, 1)
	go func() { c <- a.sendRequest(request.WithContext(ctx), reqBody, responseBody) }()
	select {
	case <-ctx.Done():
		<-c // Wait for sendRequest to return.
		return ctx.Err()
	case err := <-c:
		return err
	}
}

// sendRequest calls the HTTP API.
func (a *API) sendRequest(request *http.Request, requestBody []byte, responseBody interface{}) error {
	// Error structure for KP.
	type KPErrorMsg struct {
		Message string `json:"errorMsg,omitempty"`
	}
	type KPError struct {
		Resources []KPErrorMsg `json:"resources,ommitempty"`
	}

	// Error structure for IAM.
	type IAMError struct {
		Code    string `json:"errorCode,omitempty"`
		Message string `json:"errorMessage,omitempty"`
	}

	response, err := a.HttpClient.Do(request)
	if err != nil {
		return err
	}

	defer response.Body.Close()
	resBody, err := ioutil.ReadAll(response.Body)
	redact := []string{a.AuthToken.AccessToken, a.Config.APIKey, request.Header.Get("authorization")}
	a.Dump(request, response, requestBody, resBody, a.Logger, redact)
	//fmt.Printf("Request:  %s %s Body: %s\n", request.Method, request.URL, requestBody)
	//fmt.Printf("Response: %v Body: %s\n", response.StatusCode, resBody)
	if err != nil {
		return err
	}

	switch response.StatusCode {
	case http.StatusOK, http.StatusCreated:
		if err := json.Unmarshal(resBody, responseBody); err != nil {
			return err
		}
		return nil
	case http.StatusNoContent:
		return nil
	default:
		if strings.Contains(string(resBody), "errorMsg") {
			kperr := KPError{}
			json.Unmarshal(resBody, &kperr)
			if len(kperr.Resources) > 0 && len(kperr.Resources[0].Message) > 0 {
				return errors.New(kperr.Resources[0].Message)
			}
		}
		if strings.Contains(string(resBody), "errorCode") {
			iamerr := IAMError{}
			json.Unmarshal(resBody, &iamerr)
			if len(iamerr.Message) > 0 {
				return fmt.Errorf("%s:%s", iamerr.Code, iamerr.Message)
			}
		}
		return errors.New(string(resBody))
	}
}

// apiURL constructs an API URL.
func (a *API) apiURL(base string, id *string) (*url.URL, error) {
	keysURI := base
	if id != nil {
		keysURI = fmt.Sprintf(keysURI+"/%s", *id)
	}
	u, err := url.Parse(keysURI)
	if err != nil {
		return nil, err
	}
	return a.URL.ResolveReference(u), nil
}

// apiURL constructs an API URL.
// policyBase is the policy base for calls involving key policies
func (a *API) getPolicyApiURL(base string, id *string, secondBase string) (*url.URL, error) {
	keysURI := base
	policyURI := secondBase
	if id != nil {
		keysURI = fmt.Sprintf(keysURI+"/%s/"+policyURI, *id)
	}
	u, err := url.Parse(keysURI)
	if err != nil {
		return nil, err
	}
	return a.URL.ResolveReference(u), nil
}

// getAccessToken returns the auth context from the given Context, or
// calls the KP API to retrieve a new auth token.
func (a *API) getAccessToken(ctx context.Context) (string, error) {
	if ctx.Value(authContextKey) != nil {
		return ctx.Value(authContextKey).(string), nil
	}

	if len(a.Config.Authorization) > 0 {
		return a.Config.Authorization, nil
	}

	if len(a.AuthToken.AccessToken) > 0 && time.Now().Before(a.AuthToken.expiration) {
		return fmt.Sprintf("%s %s", a.AuthToken.Type, a.AuthToken.AccessToken), nil
	}

	v := url.Values{}
	v.Set("grant_type", "urn:ibm:params:oauth:grant-type:apikey")
	v.Set("apikey", a.Config.APIKey)
	reqBody := []byte(v.Encode())

	u, err := url.Parse(a.Config.TokenURL)
	if err != nil {
		return "", err
	}
	request := &http.Request{
		Method: "POST",
		URL:    u,
		Header: http.Header{
			"Content-Type":   {"application/x-www-form-urlencoded"},
			"Accept":         {"application/json"},
			"Content-Length": {strconv.Itoa(len(reqBody))},
		},
		Body: ioutil.NopCloser(bytes.NewReader(reqBody)),
	}
	defer request.Body.Close()

	c := make(chan error, 1)
	go func() { c <- a.sendRequest(request.WithContext(ctx), reqBody, &a.AuthToken) }()
	select {
	case <-ctx.Done():
		<-c // Wait for sendRequest to return.
		return "", ctx.Err()
	case err := <-c:
		if err != nil {
			return "", err
		}
		// Set the expiration time for 1 min less than the
		// actual time to prevent timeout errors
		a.AuthToken.expiration = time.Now().Add(time.Second * time.Duration(a.AuthToken.ExpiresInSeconds-60))
		return fmt.Sprintf("%s %s", a.AuthToken.Type, a.AuthToken.AccessToken), nil
	}
}

// cloneHeader makes a deep clone of the given HTTP headers.
func cloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

// mergeHeaders copies the source headers to the destination headers.
// Returns destination headers.
func mergeHeaders(src, dst http.Header) http.Header {
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
