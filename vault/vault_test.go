package vault

import (
	"testing"

	"github.com/libopenstorage/secrets/test"
)

func TestAll(t *testing.T) {
	// Set the relevant environmnet fields for vault.
	test.Run(New, nil, t)
}
