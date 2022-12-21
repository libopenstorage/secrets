package aws_secrets_manager

import (
	"github.com/libopenstorage/secrets/aws/utils"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	testCases := []struct {
		name        string
		cfg         map[string]interface{}
		expectedErr error
	}{
		{
			name:        "config is not provided",
			expectedErr: utils.ErrAWSCredsNotProvided,
		},
		{
			name: "region is not provided",
			cfg: map[string]interface{}{
				"aws_secret_key": "key1",
				"aws_access_key": "key2",
			},
			expectedErr: utils.ErrAWSRegionNotProvided,
		},
		{
			name: "region is provided but no credentials",
			cfg: map[string]interface{}{
				utils.AwsRegionKey: "us-east-1",
			},
			// we don't expect an error since these credentials can be provided as env variables or instance roles
			expectedErr: nil,
		},
	}

	for _, tc := range testCases {
		_, err := New(tc.cfg)
		require.Equal(t, tc.expectedErr, err, tc.name)
	}
}
