package vault

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	dummySecret = map[string]interface{}{"bar": "baz987"}
	vaultREST   = map[string]struct {
		code int
		body []byte
	}{
		"login":   {http.StatusOK, []byte(`{"auth":{"accessor":"nRIuE<REDACTED>","client_token":"hvs.CAESIMUue6<REDACTED>","entity_id":"3cd92537-67cf-d6bc-88fa-b6a516501597","lease_duration":300,"metadata":{"role":"portworx","service_account_name":"portworx","service_account_namespace":"portworx","service_account_secret_name":"","service_account_uid":"2e323bc4-<REDACTED>"},"mfa_requirement":null,"num_uses":0,"orphan":true,"policies":["default","portworx"],"renewable":true,"token_policies":["default","portworx"],"token_type":"service"},"data":null,"lease_duration":0,"lease_id":"","renewable":false,"request_id":"07aabda2-2489-d096-57e2-351aa41391a1","warnings":null,"wrap_info":null}`)},
		"mounts":  {http.StatusOK, []byte(`{"auth":null,"cubbyhole/":{"accessor":"cubbyhole_fd861c58","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"per-token private secret storage","external_entropy_access":false,"local":true,"options":null,"plugin_version":"","running_plugin_version":"v1.15.6+builtin.vault","running_sha256":"","seal_wrap":false,"type":"cubbyhole","uuid":"0e392759-9504-60cb-da7f-f023a62c49b2"},"data":{"cubbyhole/":{"accessor":"cubbyhole_fd861c58","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"per-token private secret storage","external_entropy_access":false,"local":true,"options":null,"plugin_version":"","running_plugin_version":"v1.15.6+builtin.vault","running_sha256":"","seal_wrap":false,"type":"cubbyhole","uuid":"0e392759-9504-60cb-da7f-f023a62c49b2"},"identity/":{"accessor":"identity_7deff750","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0,"passthrough_request_headers":["Authorization"]},"description":"identity store","external_entropy_access":false,"local":false,"options":null,"plugin_version":"","running_plugin_version":"v1.15.6+builtin.vault","running_sha256":"","seal_wrap":false,"type":"identity","uuid":"7d9e696e-1bd5-6288-38d9-3bc304e1f2bc"},"secrets/":{"accessor":"kv_fbdfa522","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"deprecation_status":"supported","description":"","external_entropy_access":false,"local":false,"options":{"version":"2"},"plugin_version":"","running_plugin_version":"v0.16.1+builtin","running_sha256":"","seal_wrap":false,"type":"kv","uuid":"75f0941b-eb5b-e6d1-299b-98d8b05d3bda"},"static_secrets/":{"accessor":"kv_26744f08","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"deprecation_status":"supported","description":"","external_entropy_access":false,"local":false,"options":{"version":"2"},"plugin_version":"","running_plugin_version":"v0.16.1+builtin","running_sha256":"","seal_wrap":false,"type":"kv","uuid":"11a128bc-f97e-0c5d-774f-7223bacfa59e"},"sys/":{"accessor":"system_01c5a91b","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0,"passthrough_request_headers":["Accept"]},"description":"system endpoints used for control, policy and debugging","external_entropy_access":false,"local":false,"options":null,"plugin_version":"","running_plugin_version":"v1.15.6+builtin.vault","running_sha256":"","seal_wrap":true,"type":"system","uuid":"56790f9b-0647-a453-7839-96c427cb78c4"}},"identity/":{"accessor":"identity_7deff750","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0,"passthrough_request_headers":["Authorization"]},"description":"identity store","external_entropy_access":false,"local":false,"options":null,"plugin_version":"","running_plugin_version":"v1.15.6+builtin.vault","running_sha256":"","seal_wrap":false,"type":"identity","uuid":"7d9e696e-1bd5-6288-38d9-3bc304e1f2bc"},"lease_duration":0,"lease_id":"","renewable":false,"request_id":"b1733849-6f12-192e-479d-46f14d1727d4","secrets/":{"accessor":"kv_fbdfa522","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"deprecation_status":"supported","description":"","external_entropy_access":false,"local":false,"options":{"version":"2"},"plugin_version":"","running_plugin_version":"v0.16.1+builtin","running_sha256":"","seal_wrap":false,"type":"kv","uuid":"75f0941b-eb5b-e6d1-299b-98d8b05d3bda"},"static_secrets/":{"accessor":"kv_26744f08","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"deprecation_status":"supported","description":"","external_entropy_access":false,"local":false,"options":{"version":"2"},"plugin_version":"","running_plugin_version":"v0.16.1+builtin","running_sha256":"","seal_wrap":false,"type":"kv","uuid":"11a128bc-f97e-0c5d-774f-7223bacfa59e"},"sys/":{"accessor":"system_01c5a91b","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0,"passthrough_request_headers":["Accept"]},"description":"system endpoints used for control, policy and debugging","external_entropy_access":false,"local":false,"options":null,"plugin_version":"","running_plugin_version":"v1.15.6+builtin.vault","running_sha256":"","seal_wrap":true,"type":"system","uuid":"56790f9b-0647-a453-7839-96c427cb78c4"},"warnings":null,"wrap_info":null}`)},
		"put-key": {http.StatusOK, []byte(`{"auth":null,"data":{"created_time":"2024-04-12T07:40:32.759558919Z","custom_metadata":null,"deletion_time":"","destroyed":false,"version":3},"lease_duration":0,"lease_id":"","renewable":false,"request_id":"df20e3de-1728-c223-a23b-0b8893f4a189","warnings":null,"wrap_info":null}`)},
		"get-key": {http.StatusOK, []byte(`{"auth":null,"data":{"data":{"bar":"baz987"},"metadata":{"created_time":"2024-04-12T07:40:32.759558919Z","custom_metadata":null,"deletion_time":"","destroyed":false,"version":3}},"lease_duration":0,"lease_id":"","renewable":false,"request_id":"2915b7e5-73a5-3cdb-36b5-2ccf142de848","warnings":null,"wrap_info":null}`)},
		"perm":    {http.StatusForbidden, []byte(`{"errors":["permission denied"]}`)},
	}
)

func setupK8sTests(t *testing.T) {
	setup()
	tokFile := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	if _, err := os.Stat(tokFile); os.IsNotExist(err) {
		if err := os.MkdirAll(path.Dir(tokFile), 0755); err != nil {
			t.Skipf("Skipping test because - %s", err)
		}
		t.Logf("Creating dummy token file: %s", tokFile)
		_, err = os.OpenFile(tokFile, os.O_RDONLY|os.O_CREATE, 0666) // "touch" the file
		require.NoError(t, err)
	}
}

func TestVaultK8sHappyPath(t *testing.T) {
	setupK8sTests(t)
	var (
		mockReplies = []string{
			"login", "mounts", // vault-client.New
			"login", "mounts", // vault-client.New
			"login", "mounts", // vault-client.New
			"put-key",
			"get-key",
		}
		cnt       = 0
		mockVault = httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			t.Log("mockVault: REQ[", req.Method, req.URL.Path, "] - RESP[", mockReplies[cnt], "]   (cnt", cnt, ")")
			resp.WriteHeader(vaultREST[mockReplies[cnt]].code)
			resp.Write(vaultREST[mockReplies[cnt]].body)
			cnt++
		}))
		m map[string]interface{}
	)
	require.NotNil(t, mockVault)

	// note-- os.Setenv("VAULT_HTTP_PROXY", "http://10.13.1.20:8080")

	// default init
	v, err := New(map[string]interface{}{
		"VAULT_ADDR":                 mockVault.URL,
		"VAULT_AUTH_KUBERNETES_ROLE": "portworx",
		"VAULT_AUTH_METHOD":          "kubernetes",
		"VAULT_BACKEND_PATH":         "static_secrets/",
	})
	require.NoError(t, err)
	require.NotNil(t, v)
	assert.Equal(t, defaultCooldownPeriod, confCooldownPeriod)

	// test with custom cooldown period   (legal value)
	v, err = New(map[string]interface{}{
		"VAULT_ADDR":                 mockVault.URL,
		"VAULT_AUTH_KUBERNETES_ROLE": "portworx",
		"VAULT_AUTH_METHOD":          "kubernetes",
		"VAULT_BACKEND_PATH":         "static_secrets/",
		"VAULT_COOLDOWN_PERIOD":      "987s",
	})
	require.NoError(t, err)
	require.NotNil(t, v)
	assert.Equal(t, 987*time.Second, confCooldownPeriod)

	// test with disabling cooldown period
	v, err = New(map[string]interface{}{
		"VAULT_ADDR":                 mockVault.URL,
		"VAULT_AUTH_KUBERNETES_ROLE": "portworx",
		"VAULT_AUTH_METHOD":          "kubernetes",
		"VAULT_BACKEND_PATH":         "static_secrets/",
		"VAULT_COOLDOWN_PERIOD":      "0",
	})
	require.NoError(t, err)
	require.NotNil(t, v)
	assert.Equal(t, time.Duration(0), confCooldownPeriod)

	// quick put/get test

	_, err = v.PutSecret("portworx/sikret", dummySecret, nil)
	assert.NoError(t, err)

	m, _, err = v.GetSecret("portworx/sikret", nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, m)

	assert.Equal(t, 8, cnt)
}

func TestVaultCooldown(t *testing.T) {
	setupK8sTests(t)
	var (
		mockReplies = []string{
			"login", "mounts", // vault-client.New
			"perm",
			"perm",
			"put-key",
			"perm",
			"perm",
			"get-key",
		}
		cnt       = 0
		mockVault = httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			t.Log("mockVault: REQ[", req.Method, req.URL.Path, "] - RESP[", mockReplies[cnt], "]   (cnt", cnt, ")")
			resp.WriteHeader(vaultREST[mockReplies[cnt]].code)
			resp.Write(vaultREST[mockReplies[cnt]].body)
			cnt++
		}))
		m map[string]interface{}
	)
	require.NotNil(t, mockVault)

	v, err := New(map[string]interface{}{
		"VAULT_ADDR":                 mockVault.URL,
		"VAULT_AUTH_KUBERNETES_ROLE": "portworx",
		"VAULT_AUTH_METHOD":          "kubernetes",
		"VAULT_BACKEND_PATH":         "static_secrets/",
	})
	require.NoError(t, err)
	require.NotNil(t, v)
	assert.Equal(t, defaultCooldownPeriod, confCooldownPeriod)
	confCooldownPeriod = 100 * time.Millisecond // force-override for testing

	_, err = v.PutSecret("portworx/sikret", dummySecret, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	assert.Equal(t, 4, cnt) // expect 4 calls to Vault: 2 for New(), 1 Put and 1 RenewToken

	for i := 0; i < 10; i++ {
		_, err = v.PutSecret("portworx/sikret", dummySecret, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "vault client is in cooldown")
	}
	assert.Equal(t, 4, cnt) // expect no extra calls to Vault since cooldown in effect

	time.Sleep(confCooldownPeriod + 50*time.Millisecond)
	_, err = v.PutSecret("portworx/sikret", dummySecret, nil)
	assert.NoError(t, err)
	assert.Equal(t, 5, cnt) // +1 call to Vault

	// now let's do Get
	m, _, err = v.GetSecret("portworx/sikret", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	assert.Empty(t, m)
	assert.Equal(t, 7, cnt) // +1 Get and +1 RenewToken

	for i := 0; i < 20; i++ {
		m, _, err = v.GetSecret("portworx/sikret", nil)
		require.Error(t, err)
		assert.Empty(t, m)
		assert.Contains(t, err.Error(), "vault client is in cooldown")

		_, err = v.PutSecret("portworx/sikret", dummySecret, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "vault client is in cooldown")

		err = v.DeleteSecret("portworx/sikret", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "vault client is in cooldown")
	}
	assert.Equal(t, 7, cnt) // expect no extra calls to Vault since cooldown in effect

	time.Sleep(confCooldownPeriod + 50*time.Millisecond)
	m, _, err = v.GetSecret("portworx/sikret", nil)
	assert.NoError(t, err)
	assert.Equal(t, 8, cnt) // +1 call to Vault
	assert.NotEmpty(t, m)
}

func TestVaultK8sDisabledCooldown(t *testing.T) {
	setupK8sTests(t)
	var (
		mockReplies = []string{
			"login", "mounts", // vault-client.New
			"perm", "perm", // failed Put
			"perm", "login", "put-key", // recovered Put
			"perm", "perm", // failed Get
			"perm", "login", "get-key", // recovered Get
		}
		cnt       = 0
		mockVault = httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			t.Log("mockVault: REQ[", req.Method, req.URL.Path, "] - RESP[", mockReplies[cnt], "]   (cnt", cnt, ")")
			resp.WriteHeader(vaultREST[mockReplies[cnt]].code)
			resp.Write(vaultREST[mockReplies[cnt]].body)
			cnt++
		}))
		m map[string]interface{}
	)
	require.NotNil(t, mockVault)

	// test with disabling cooldown period
	v, err := New(map[string]interface{}{
		"VAULT_ADDR":                 mockVault.URL,
		"VAULT_AUTH_KUBERNETES_ROLE": "portworx",
		"VAULT_AUTH_METHOD":          "kubernetes",
		"VAULT_BACKEND_PATH":         "static_secrets/",
		"VAULT_COOLDOWN_PERIOD":      "0",
	})
	require.NoError(t, err)
	require.NotNil(t, v)
	assert.Equal(t, time.Duration(0), confCooldownPeriod)
	assert.Equal(t, 2, cnt)

	_, err = v.PutSecret("portworx/sikret", dummySecret, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	assert.Equal(t, 4, cnt)

	_, err = v.PutSecret("portworx/sikret", dummySecret, nil)
	assert.NoError(t, err)
	assert.Equal(t, 7, cnt)

	m, _, err = v.GetSecret("portworx/sikret", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	assert.Empty(t, m)
	assert.Equal(t, 9, cnt)

	m, _, err = v.GetSecret("portworx/sikret", nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, m)

	assert.Equal(t, 12, cnt)
}
