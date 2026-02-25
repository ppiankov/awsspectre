package logging

import "testing"

func TestInit_NoError(t *testing.T) {
	// Init should not panic for either verbose mode
	Init(false)
	Init(true)
}
