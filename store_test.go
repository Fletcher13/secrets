package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewStore(t *testing.T) {
	// Test with invalid key length
	_, err := NewStore("test_dir", []byte("short"))
	assert.Error(t, err, "Expected error for short key")

	// Test with valid key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	store, err := NewStore("test_dir", key)
	assert.NoError(t, err)
	defer testCleanup(t, store)
	assert.NotNil(t, store)
}
