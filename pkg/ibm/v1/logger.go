package ibm

import (
	"fmt"
)

// BasicLogger ...
type BasicLogger struct{}

// Info ...
func (l *BasicLogger) Info(args ...interface{}) {
	for _, arg := range args {
		fmt.Println(arg)
	}
}
