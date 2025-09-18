package secrets

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewStore(t *testing.T) {
	// Test with empty password
	_, err := NewStore("test_dir", []byte(""))
	assert.Error(t, err, "Expected error for empty password")

	// Create new store
	store, err := NewStore("test_dir", []byte("prim_password"))
	assert.NoError(t, err)
	defer func() {
		err = os.RemoveAll("test_dir")
		assert.NoError(t, err)
	}()
	err = store.Close()
	assert.NoError(t, err)

	// Open existing store.
	store, err = NewStore("test_dir", []byte("prim_password"))
	assert.NoError(t, err)
	err = store.Close()
	assert.NoError(t, err)

	// Try to open existing store with wrong password
	store, err = NewStore("test_dir", []byte("bad_password"))
	assert.Error(t, err)
}
