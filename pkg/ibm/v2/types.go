package kp

import (
	"net/http"
	"time"
)

// Key represents a key as returned by the KP API.
type Key struct {
	ID                  string     `json:"id,omitempty"`
	Name                string     `json:"name,omitempty"`
	Description         string     `json:"description,omitempty"`
	Type                string     `json:"type,omitempty"`
	Tags                []string   `json:"Tags,omitempty"`
	AlgorithmType       string     `json:"algorithmType,omitempty"`
	CreatedBy           string     `json:"createdBy,omitempty"`
	CreationDate        *time.Time `json:"creationDate,omitempty"`
	Extractable         bool       `json:"extractable"`
	Expiration          *time.Time `json:"expirationDate,omitempty"`
	Payload             string     `json:"payload,omitempty"`
	State               int        `json:"state,omitempty"`
	EncryptionAlgorithm string     `json:"encryptionAlgorithm,omitempty"`
	LockerKeyId         string     `json:"lockerKeyId,omitempty"`
	ImportToken         string     `json:"importToken,omitempty"`
	CRN                 string     `json:"crn,omitempty"`
}

// KeysMetadata represents the metadata of a collection of keys.
type KeysMetadata struct {
	CollectionType string `json:"collectionType"`
	NumberOfKeys   int    `json:"collectionTotal"`
}

// Keys represents a collection of Keys.
type Keys struct {
	Metadata KeysMetadata `json:"metadata"`
	Keys     []Key        `json:"resources"`
}

// KeysActionRequest represents request parameters for a key action
// API call.
type KeysActionRequest struct {
	PlainText  string   `json:"plaintext,omitempty"`
	AAD        []string `json:"aad,omitempty"`
	CipherText string   `json:"ciphertext,omitempty"`
	Payload    string   `json:"payload,omitempty"`
}

// AuthToken represents KP API auth tokens.
type AuthToken struct {
	AccessToken      string `json:"access_token,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	ExpiresInSeconds int    `json:"expires_in"`
	Type             string `json:"token_type"`
	expiration       time.Time
}

// LockerCreateRequest represents request parameters for creating a
// locker.
type LockerCreateRequest struct {
	MaxAllowedRetrievals int `json:"maxAllowedRetrievals,omitempty"`
	ExpiresInSeconds     int `json:"expiration,omitempty"`
}

// LockerKeyResponse represents the response body for various locker
// API calls.
type LockerKeyResponse struct {
	ID             string     `json:"id"`
	CreationDate   *time.Time `json:"creationDate"`
	ExpirationDate *time.Time `json:"expirationDate"`
	Payload        string     `json:"payload"`
	ImportToken    string     `json:"importToken"`
}

// LockerMetadata represents the metadata of a locker.
type LockerMetadata struct {
	ID                   string     `json:"id"`
	CreationDate         *time.Time `json:"creationDate"`
	ExpirationDate       *time.Time `json:"expirationDate"`
	MaxAllowedRetrievals int        `json:"maxAllowedRetrievals"`
	RemainingRetrievals  int        `json:"remainingRetrievals"`
}

// Policy represents a policy as returned by the KP API.
type Policy struct {
	Type           string     `json:"type,omitempty"`
	CreatedBy      string     `json:"createdby,omitempty"`
	CreationDate   *time.Time `json:"createdat,omitempty"`
	CRN            string     `json:"crn,omitempty"`
	LastUpdateDate *time.Time `json:"updatedat,omitempty"`
	UpdatedBy      string     `json:"updatedby,omitempty"`
	Rotation       struct {
		Interval int `json:"interval_month,omitEmpty"`
	} `json:"rotation,omitEmpty"`
}

// PoliciesMetadata represents the metadata of a collection of keys.
type PoliciesMetadata struct {
	CollectionType   string `json:"collectionType"`
	NumberOfPolicies int    `json:"collectionTotal"`
}

// Policies represents a collection of Policies.
type Policies struct {
	Metadata PoliciesMetadata `json:"metadata"`
	Policies []Policy         `json:"resources"`
}

// Dump writes various parts of an HTTP request and an HTTP response.
type Dump func(*http.Request, *http.Response, []byte, []byte, Logger, []string)

// ContextKey provides a type to auth context keys.
type ContextKey int

// Redact replaces various pieces of output.
type Redact func(string, []string) string

// PreferReturn designates the value for the "Prefer" header.
type PreferReturn int
