//go:build integration
// +build integration

package aws_secrets_manager

import (
	"os"
	"testing"

	"github.com/libopenstorage/secrets/aws/utils"
	"github.com/libopenstorage/secrets/test"
)

func TestStore(t *testing.T) {
	// Set the relevant environmnet fields for aws.
	secretConfig := make(map[string]interface{})

	// Fill in the appropriate keys and values
	secretConfig[utils.AwsRegionKey] = os.Getenv(utils.AwsRegionKey)
	secretConfig[utils.AwsSecretAccessKey] = os.Getenv(utils.AwsSecretAccessKey)
	secretConfig[utils.AwsAccessKey] = os.Getenv(utils.AwsAccessKey)

	store, err := New(secretConfig)
	if err != nil {
		t.Fatalf("Unable to create a AWS Secrets Store instance: %v", err)
		return
	}
	test.RunForStore(store, t)
}
