package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWipe(t *testing.T) {
	data := []byte("sensitive_data")
	original := make([]byte, len(data))
	copy(original, data)

	Wipe(data)

	// After wiping, the data should be different (either zeros or random)
	assert.NotEqual(t, original, data, "Data should be wiped and different from original")
}
