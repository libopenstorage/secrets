package aws_secrets_manager

import (
	"fmt"
	"github.com/libopenstorage/secrets/aws/utils"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	testCases := []struct {
		name        string
		cfg         map[string]interface{}
		expectedErr error
		exactMatch  bool
	}{
		{
			name:        "config is not provided",
			expectedErr: utils.ErrAWSCredsNotProvided,
			exactMatch:  true,
		},
		{
			name: "region is not provided",
			cfg: map[string]interface{}{
				"aws_secret_key": "key1",
				"aws_access_key": "key2",
			},
			expectedErr: utils.ErrAWSRegionNotProvided,
			exactMatch:  true,
		},
		{
			name: "region is provided but no credentials",
			cfg: map[string]interface{}{
				utils.AwsRegionKey: "us-east-1",
			},
			// we don't expect an error since these credentials can be provided as env variables or instance roles
			expectedErr: fmt.Errorf("NoCredentialProviders"),
			exactMatch:  false,
		},
	}

	for _, tc := range testCases {
		_, err := New(tc.cfg)
		if tc.exactMatch {
			require.Equal(t, tc.expectedErr, err, tc.name)
		} else {
			require.True(t, strings.Contains(err.Error(), tc.expectedErr.Error()), "unexpected error")
		}
	}
}
