package infisical

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, base string) *kmsClient {
	t.Helper()
	// newKmsClient enforces https, so build the struct directly for httptest URLs.
	return &kmsClient{
		httpClient:   http.DefaultClient,
		baseURL:      strings.TrimRight(base, "/") + "/api",
		kmsKeyID:     "k-1",
		clientID:     "id",
		clientSecret: "secret",
	}
}

func writeLogin(w http.ResponseWriter, token string) {
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(loginResponse{AccessToken: token, ExpiresIn: 3600})
}

func writeEncrypt(w http.ResponseWriter, ciphertext string) {
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(encryptResponse{Ciphertext: ciphertext})
}

func retryServer(t *testing.T, firstStatus int, firstBody string) (*httptest.Server, *int32, *int32) {
	t.Helper()
	var loginCalls, encryptCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/v1/auth/universal-auth/login"):
			n := atomic.AddInt32(&loginCalls, 1)
			writeLogin(w, "token-"+string(rune('0'+n)))
		case strings.Contains(r.URL.Path, "/v1/kms/keys/"):
			n := atomic.AddInt32(&encryptCalls, 1)
			if n == 1 {
				w.WriteHeader(firstStatus)
				_, _ = w.Write([]byte(firstBody))
				return
			}
			assert.Equal(t, "Bearer token-2", r.Header.Get("Authorization"))
			writeEncrypt(w, "ct-ok")
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	return srv, &loginCalls, &encryptCalls
}

func TestDoKmsRequest_Retries401WithReLogin(t *testing.T) {
	srv, loginCalls, encryptCalls := retryServer(t, http.StatusUnauthorized,
		`{"statusCode":401,"error":"UnauthorizedError","message":"token revoked"}`)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	require.NoError(t, c.login())

	ct, err := c.encrypt("hello")
	require.NoError(t, err)
	assert.Equal(t, "ct-ok", ct)
	assert.EqualValues(t, 2, atomic.LoadInt32(loginCalls), "should re-login after 401")
	assert.EqualValues(t, 2, atomic.LoadInt32(encryptCalls), "should retry the encrypt call once")
}

func TestDoKmsRequest_Retries403TokenErrorWithReLogin(t *testing.T) {
	srv, loginCalls, encryptCalls := retryServer(t, http.StatusForbidden,
		`{"statusCode":403,"error":"TokenError","message":"Your token has expired. Please re-authenticate."}`)
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	require.NoError(t, c.login())

	ct, err := c.encrypt("hello")
	require.NoError(t, err)
	assert.Equal(t, "ct-ok", ct)
	assert.EqualValues(t, 2, atomic.LoadInt32(loginCalls), "should re-login after 403 TokenError")
	assert.EqualValues(t, 2, atomic.LoadInt32(encryptCalls), "should retry once on 403 TokenError")
}

func TestDoKmsRequest_DoesNotInfiniteLoopOnRepeated403(t *testing.T) {
	var loginCalls, encryptCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/v1/auth/universal-auth/login"):
			atomic.AddInt32(&loginCalls, 1)
			writeLogin(w, "tkn")
		case strings.Contains(r.URL.Path, "/v1/kms/keys/"):
			atomic.AddInt32(&encryptCalls, 1)
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"statusCode":403,"error":"PermissionDenied","message":"missing KMS permission"}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	require.NoError(t, c.login())

	_, err := c.encrypt("hello")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
	assert.EqualValues(t, 2, atomic.LoadInt32(&encryptCalls), "should retry exactly once on persistent 403")
	assert.EqualValues(t, 2, atomic.LoadInt32(&loginCalls), "should re-login once before giving up")
}

func TestDoKmsRequest_DoesNotInfiniteLoopOnRepeated401(t *testing.T) {
	var encryptCalls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/v1/auth/universal-auth/login"):
			writeLogin(w, "any-token")
		case strings.Contains(r.URL.Path, "/v1/kms/keys/"):
			atomic.AddInt32(&encryptCalls, 1)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`unauthorized`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	require.NoError(t, c.login())

	_, err := c.encrypt("hello")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
	assert.EqualValues(t, 2, atomic.LoadInt32(&encryptCalls), "should retry exactly once on persistent 401")
}

func TestDoKmsRequest_HappyPath_NoRetry(t *testing.T) {
	var loginCalls, encryptCalls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/v1/auth/universal-auth/login"):
			atomic.AddInt32(&loginCalls, 1)
			writeLogin(w, "good-token")
		case strings.Contains(r.URL.Path, "/v1/kms/keys/"):
			atomic.AddInt32(&encryptCalls, 1)
			writeEncrypt(w, "ct")
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	require.NoError(t, c.login())

	ct, err := c.encrypt("hello")
	require.NoError(t, err)
	assert.Equal(t, "ct", ct)
	assert.EqualValues(t, 1, atomic.LoadInt32(&loginCalls), "no extra login when first call succeeds")
	assert.EqualValues(t, 1, atomic.LoadInt32(&encryptCalls))
}

func TestNewKmsClient_RejectsHTTP(t *testing.T) {
	_, err := newKmsClient("http://infisical.internal", "k", "id", "sec")
	assert.ErrorIs(t, err, ErrInsecureSiteURL)
}

func TestNewKmsClient_AcceptsHTTPS(t *testing.T) {
	c, err := newKmsClient("https://app.infisical.com", "k", "id", "sec")
	require.NoError(t, err)
	assert.Equal(t, "https://app.infisical.com/api", c.baseURL)
}
