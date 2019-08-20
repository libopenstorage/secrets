package kp

import (
	"context"
	"crypto/tls"
	"net/http"
)

const (
	// DefaultBaseURL ...
	DefaultBaseURL = "https://keyprotect.us-south.bluemix.net"
	// DefaultTokenURL ..
	DefaultTokenURL = "https://iam.bluemix.net/oidc/token"

	// VerboseNone ...
	VerboseNone = 0
	// VerboseBodyOnly ...
	VerboseBodyOnly = 1
	// VerboseAll ...
	VerboseAll = 2
	// VerboseFailOnly ...
	VerboseFailOnly = 3
	// VerboseAllNoRedact ...
	VerboseAllNoRedact = 4
)

// ClientConfig ...
type ClientConfig struct {
	BaseURL       string
	Authorization string  //The IBM Cloud (Bluemix) access token
	APIKey        string  //Service ID API key, can be used instead of an access token
	TokenURL      string  //The URL used to get an access token from the API key
	InstanceID    string  //The IBM Cloud (Bluemix) instance ID that identifies your Key Protect service instance.
	Verbose       int     //See verbose values above
	Timeout       float64 //KP request timeout in seconds.
}

// DefaultTransport ...
func DefaultTransport() http.RoundTripper {
	transport := &http.Transport{
		DisableKeepAlives:   true,
		MaxIdleConnsPerHost: -1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	}
	return transport
}

// NewContextWithAuth ...
func NewContextWithAuth(parent context.Context, auth string) context.Context {
	return context.WithValue(parent, authContextKey, auth)
}
