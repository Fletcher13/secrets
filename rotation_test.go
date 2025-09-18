package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyRotation(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	store, err := NewStore("test_rotation", key)
	assert.NoError(t, err)
	defer testCleanup(t, store)

	// Save some data
	testData := []byte("test_rotation_data")
	path := "test/secret"
	err = store.Save(path, testData)
	assert.NoError(t, err)

	// Get initial key index
	info, err := store.GetStoreInfo()
	assert.NoError(t, err)
	initialKeyIndex := info.CurrentKeyIndex

	// Rotate keys
	err = store.Rotate()
	assert.NoError(t, err)

	// Verify data is still accessible
	loadedData, err := store.Load(path)
	assert.NoError(t, err)
	assert.Equal(t, testData, loadedData)

	// Verify key index changed
	info, err = store.GetStoreInfo()
	assert.NoError(t, err)
	assert.NotEqual(t, initialKeyIndex, info.CurrentKeyIndex, "Key index should have changed after rotation")
}
