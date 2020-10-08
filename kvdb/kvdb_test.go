package kvdb

import (
	"testing"

	"github.com/libopenstorage/secrets"
	"github.com/portworx/kvdb"
	"github.com/stretchr/testify/require"
)

func TestAll(t *testing.T) {
	_, err := kvdb.New("notfound", "pwx/", []string{"http://127.0.0.1:2379"}, nil, nil)
	require.Equal(t, secrets.ErrNotSupported, err)
}
