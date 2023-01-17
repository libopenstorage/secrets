package aws_kms

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
			expectedErr: utils.ErrCMKNotProvided,
		},
		{
			name:        "cmk key is not provided",
			cfg:         map[string]interface{}{},
			expectedErr: utils.ErrCMKNotProvided,
		},
		{
			name: "region is not provided",
			cfg: map[string]interface{}{
				AwsCMKey: "key1",
			},
			expectedErr: utils.ErrAWSRegionNotProvided,
		},
	}

	for _, tc := range testCases {
		_, err := New(tc.cfg)
		require.Equal(t, tc.expectedErr, err, tc.name)
	}
}
