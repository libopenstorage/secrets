package ibm

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

type dumpFunction func(*http.Request, *http.Response, []byte, []byte, logger, []string)
type contextKey int
type redactFunction func(string, []string) string

const (
	// ReturnMinimal ...
	ReturnMinimal ReturnInfo = 0
	// ReturnRepresentation ...
	ReturnRepresentation ReturnInfo = 1
	authContextKey       contextKey = 0
	keyType                         = "application/vnd.ibm.kms.key+json"
	defaultTimeout                  = 5 // in seconds.
)

var preferHeader = [...]string{"return=minimal", "return=representation"}
var dumpFunctions = [...]dumpFunction{dumpNone, dumpBodyOnly, dumpAll, dumpFailOnly, dumpAllNoRedact}

// ReturnInfo ...
type ReturnInfo int

// Logger Interface
type logger interface {
	Info(args ...interface{})
}

// API ..
type API struct {
	URL        *url.URL
	HttpClient http.Client
	Headers    http.Header
	Dump       dumpFunction
	Config     ClientConfig
	AuthToken  AuthToken
	Logger     logger
}

// Key ...
type Key struct {
	ID            string     `json:"id,omitempty"`
	Name          string     `json:"name,omitempty"`
	Description   string     `json:"description,omitempty"`
	Type          string     `json:"type,omitempty"`
	Tags          []string   `json:"Tags,omitempty"`
	AlgorithmType string     `json:"algorithmType,omitempty"`
	CreatedBy     string     `json:"createdBy,omitempty"`
	CreationDate  *time.Time `json:"creationDate,omitempty"`
	Extractable   bool       `json:"extractable"`
	Expiration    *time.Time `json:"expirationDate,omitempty"`
	Payload       string     `json:"payload,omitempty"`
	State         int        `json:"state,omitempty"`
}

// KeysMetaData ...
type KeysMetaData struct {
	CollectionType string `json:"collectionType"`
	NumberOfKeys   int    `json:"collectionTotal"`
}

// Keys ...
type Keys struct {
	Metadata KeysMetaData `json:"metadata"`
	Keys     []Key        `json:"resources"`
}

// KeysAction ...
type KeysAction struct {
	PlainText  string   `json:"plaintext,omitempty"`
	AAD        []string `json:"aad,omitempty"`
	CipherText string   `json:"ciphertext,omitempty"`
}

// AuthToken ...
type AuthToken struct {
	AccessToken      string `json:"access_token,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	ExpiresInSeconds int    `json:"expires_in"`
	Type             string `json:"token_type"`
	expiration       time.Time
}

// NewAPI ...
func NewAPI(config ClientConfig, transport http.RoundTripper) (*API, error) {
	return NewAPIWithLogger(config, transport, nil)
}

// NewAPIWithLogger ...
func NewAPIWithLogger(config ClientConfig, transport http.RoundTripper, logger logger) (*API, error) {
	//TODO Add some config validation
	if transport == nil {
		transport = DefaultTransport()
	}
	if logger == nil {
		logger = &BasicLogger{}
	}
	if config.Verbose > len(dumpFunctions)-1 || config.Verbose < 0 {
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
		Dump:   dumpFunctions[config.Verbose],
		Config: config,
		Logger: logger,
	}, nil
}

// CreateRootKey ...
func (a *API) CreateRootKey(ctx context.Context, name string, expiration *time.Time) (*Key, error) {

	return a.Create(ctx, name, expiration, false)
}

// CreateStandardKey ...
func (a *API) CreateStandardKey(ctx context.Context, name string, expiration *time.Time) (*Key, error) {
	return a.Create(ctx, name, expiration, true)
}

// Delete ...
func (a *API) Delete(ctx context.Context, id string, returnInfo ReturnInfo) (*Key, error) {
	additionalHeader := http.Header{
		"Prefer": {preferHeader[returnInfo]},
	}

	var keys Keys
	err := a.doHTTPRequest(ctx, "DELETE", &id, nil, additionalHeader, nil, &keys)
	if err != nil {
		return nil, err
	}

	if len(keys.Keys) > 0 {
		return &keys.Keys[0], nil
	}

	return nil, nil
}

// GetKeys ...
func (a *API) GetKeys(ctx context.Context, limit int, offset int) (*Keys, error) {

	var keys Keys
	v := url.Values{}
	if limit == 0 {
		limit = 2000
	}
	v.Set("limit", strconv.Itoa(limit))
	v.Set("offset", strconv.Itoa(offset))

	err := a.doHTTPRequest(ctx, "GET", nil, v, nil, nil, &keys)
	return &keys, err
}

// GetKey ...
func (a *API) GetKey(ctx context.Context, id string) (*Key, error) {

	var keys Keys
	err := a.doHTTPRequest(ctx, "GET", &id, nil, nil, nil, &keys)
	if err != nil {
		return nil, err
	}
	return &keys.Keys[0], nil
}

// Wrap ...
func (a *API) Wrap(ctx context.Context, id string, plainText []byte, additionalAuthData *[]string) ([]byte, error) {

	keysAction, err := a.wrapIt(ctx, id, plainText, additionalAuthData)
	if err != nil {
		return nil, err
	}
	return ([]byte)(keysAction.CipherText), nil
}

// WrapCreateDEK ...
func (a *API) WrapCreateDEK(ctx context.Context, id string, additionalAuthData *[]string) (DEK, cipherText []byte, err error) {
	keysAction, err := a.wrapIt(ctx, id, nil, additionalAuthData)
	if err != nil {
		return nil, nil, err
	}
	DEK = []byte(keysAction.PlainText)
	return DEK, ([]byte)(keysAction.CipherText), nil
}

// Unwrap ...
func (a *API) Unwrap(ctx context.Context, id string, cipherText []byte, additionalAuthData *[]string) (plainText []byte, err error) {
	keysAction := &KeysAction{
		CipherText: string(cipherText),
	}

	if additionalAuthData != nil {
		keysAction.AAD = *additionalAuthData
	}

	keysAction, err = a.doKeysAction(ctx, &id, "unwrap", keysAction)
	if err != nil {
		return nil, err
	}
	plainText = []byte(keysAction.PlainText)
	return plainText, nil
}

func (a *API) Create(ctx context.Context, name string, expiration *time.Time, extractable bool) (*Key, error) {

	key := Key{
		Name:        name,
		Type:        keyType,
		Extractable: extractable,
	}
	if expiration != nil {
		key.Expiration = expiration
	}
	keysRequest := Keys{
		Metadata: KeysMetaData{
			CollectionType: keyType,
			NumberOfKeys:   1,
		},
		Keys: make([]Key, 1),
	}
	keysRequest.Keys[0] = key
	var keysResponse Keys
	err := a.doHTTPRequest(ctx, "POST", nil, nil, nil, &keysRequest, &keysResponse)
	if err != nil {
		return nil, err
	}
	return &keysResponse.Keys[0], nil
}

func (a *API) wrapIt(ctx context.Context, id string, plainText []byte, additionalAuthData *[]string) (*KeysAction, error) {
	keysAction := &KeysAction{}

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

func (a *API) doKeysAction(ctx context.Context, id *string, action string, keysActionReq *KeysAction) (*KeysAction, error) {
	var keyActionRsp KeysAction

	v := url.Values{}
	v.Set("action", action)

	err := a.doHTTPRequest(ctx, "POST", id, v, nil, keysActionReq, &keyActionRsp)
	if err != nil {
		return nil, err
	}
	return &keyActionRsp, nil
}

func (a *API) doHTTPRequest(ctx context.Context, method string, id *string, queryParms url.Values, additionalHeaders http.Header, requestBody, responseBody interface{}) error {

	url, err := a.keysURL(id)
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
		headers = mergeHeaders(headers, additionalHeaders)
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
		Message string `json:"errorMessage, omitempty"`
	}

	response, err := a.HttpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	resBody, err := ioutil.ReadAll(response.Body)
	redact := []string{a.AuthToken.AccessToken, a.Config.APIKey, request.Header.Get("authorization")}
	a.Dump(request, response, requestBody, resBody, a.Logger, redact)
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

func (a *API) keysURL(id *string) (*url.URL, error) {
	keysURI := "keys"
	if id != nil {
		keysURI = fmt.Sprintf(keysURI+"/%s", *id)
	}
	u, err := url.Parse(keysURI)
	if err != nil {
		return nil, err
	}

	return a.URL.ResolveReference(u), nil
}

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
			"Content-Type": {"application/x-www-form-urlencoded"},
			"Accept":       {"application/json"},
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
		//Set the expiration time for 1 min less than the actual time to prevent timeout errors
		a.AuthToken.expiration = time.Now().Add(time.Second * time.Duration(a.AuthToken.ExpiresInSeconds-60))
		return fmt.Sprintf("%s %s", a.AuthToken.Type, a.AuthToken.AccessToken), nil
	}
}

func dumpFailOnly(req *http.Request, rsp *http.Response, reqBody, resBody []byte, log logger, redactStrings []string) {
	switch rsp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		return
	}
	dumpAll(req, rsp, reqBody, resBody, log, redactStrings)
}

func dumpAll(req *http.Request, rsp *http.Response, reqBody, resBody []byte, log logger, redactStrings []string) {
	dumpRequest(req, rsp, log, redactStrings, doRedact)
	dumpBody(reqBody, resBody, log, redactStrings, doRedact)
}

func dumpAllNoRedact(req *http.Request, rsp *http.Response, reqBody, resBody []byte, log logger, redactStrings []string) {
	dumpRequest(req, rsp, log, redactStrings, noRedact)
	dumpBody(reqBody, resBody, log, redactStrings, noRedact)
}

func dumpBodyOnly(req *http.Request, rsp *http.Response, reqBody, resBody []byte, log logger, redactStrings []string) {
	dumpBody(reqBody, resBody, log, redactStrings, doRedact)
}

func dumpNone(req *http.Request, rsp *http.Response, reqBody, resBody []byte, log logger, redactStrings []string) {
}

func dumpRequest(req *http.Request, rsp *http.Response, log logger, redactStrings []string, redact redactFunction) {
	// log.Info(redact(fmt.Sprint(req), redactStrings))
	// log.Info(redact(fmt.Sprint(rsp), redactStrings))
}

func dumpBody(reqBody, resBody []byte, log logger, redactStrings []string, redact redactFunction) {
	// log.Info(string(redact(string(reqBody), redactStrings)))
	// Redact the access token and refresh token if it shows up in the reponnse body.  This will happen
	// when using an API Key
	var auth AuthToken
	if strings.Contains(string(resBody), "access_token") {
		err := json.Unmarshal(resBody, &auth)
		if err != nil {
			log.Info(err)
		}
		redactStrings = append(redactStrings, auth.AccessToken)
		redactStrings = append(redactStrings, auth.RefreshToken)
	}
	// log.Info(string(redact(string(resBody), redactStrings)))
}

func cloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

func mergeHeaders(h1, h2 http.Header) http.Header {
	for k, v := range h2 {
		h1[k] = v
	}
	return h1
}

func doRedact(s string, redactStrings []string) string {
	if len(redactStrings) < 1 {
		return s
	}
	var a []string
	for _, s1 := range redactStrings {
		if s1 != "" {
			a = append(a, s1)
			a = append(a, "***Value redacted***")
		}
	}
	r := strings.NewReplacer(a...)
	return r.Replace(s)
}

func noRedact(s string, redactStrings []string) string {
	return s
}

func testLogger() logger {
	var l logger
	return l
}
