package aws_secrets_manager

import (
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
	}

	for _, tc := range testCases {
		_, err := New(tc.cfg)
		if tc.expectedErr != nil {
			if tc.exactMatch {
				require.Equal(t, tc.expectedErr, err, tc.name)
			} else {
				require.True(t, strings.Contains(err.Error(), tc.expectedErr.Error()), "unexpected error")
			}
		} else {
			require.NoError(t, err, "unexpected error")
		}

	}
}
