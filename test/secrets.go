package test

import (
	"testing"

	"github.com/libopenstorage/secrets"
)

func Run(secretBackendInit secrets.BackendInit, secretConfig map[string]interface{}, t *testing.T) {
	secret, err := secretBackendInit("", secretConfig)
	if err != nil {
		t.Fatalf("Unable to initialize secret backend: %v", err)
	}
	getPutKey(secret, t)
}

func getPutKey(s secrets.Secrets, t *testing.T) {
	data := make(map[string]interface{})
	keyId := "hello"
	data["key1"] = "value1"
	data["key2"] = "value2"

	if s == nil {
		t.Fatalf("secrets is nil")
	}
	err := s.PutKey(keyId, data, nil)
	if err != nil {
		t.Fatalf("Unable to put key into secrets: %v", err)
	}

	plainText, err := s.GetKey(keyId, nil)
	if err != nil {
		t.Fatalf("Unable to get key from secrets: %v", err)
	}
	if len(data) != len(plainText) {
		t.Errorf("Put and Get keys do not match")
	}
	for k, v := range plainText {
		if o, exists := data[k]; !exists || o != v {
			t.Errorf("Put and Get values do not match")
		}
	}
}
