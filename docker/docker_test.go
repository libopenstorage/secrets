package docker

import (
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
			name: "config is not provided",
		},
		{
			name: "empty config",
			cfg:  map[string]interface{}{},
		},
	}

	for _, tc := range testCases {
		s, err := New(tc.cfg)
		require.Equal(t, tc.expectedErr, err, tc.name)
		require.NotNil(t, s, tc.name)
	}
}
