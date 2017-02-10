package vault

import (
	"testing"

	"github.com/libopenstorage/secrets/test"
)

func TestAll(t *testing.T) {
	config := make(map[string]interface{})
	config[ReadEnvironment] = ""
	test.Run(New, config, t)
}
