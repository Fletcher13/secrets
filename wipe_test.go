package secrets

import (
	"os"
	"testing"
)

func TestWipe(t *testing.T) {
	data := []byte("sensitive_data")
	original := make([]byte, len(data))
	copy(original, data)

	Wipe(data)

	// After wiping, the data should be different (either zeros or random)
	if string(data) == string(original) {
		t.Error("Data should be wiped and different from original")
	}
}
