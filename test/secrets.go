package test

import (
	"testing"
)

type SecretTest interface {
	TestPutSecret(t *testing.T) error
	TestGetSecret(t *testing.T) error
}

func Run(st SecretTest, t *testing.T) {
	st.TestPutSecret(t)
	st.TestGetSecret(t)
}
