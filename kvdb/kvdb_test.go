package kvdb

import (
	"testing"

	"github.com/libopenstorage/secrets/test"
	"github.com/portworx/kvdb"
	e2 "github.com/portworx/kvdb/etcd/v2"
)

func TestAll(t *testing.T) {
	config := make(map[string]interface{})

	kv, _ := kvdb.New(e2.Name, "pwx/", []string{"http://127.0.0.1:2379"}, nil, nil)
	config[KvdbKey] = kv
	test.Run(New, config, t)
}
