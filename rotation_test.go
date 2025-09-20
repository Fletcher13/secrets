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

	//TODO: Get file's key index.

	// Rotate keys
	err = store.Rotate()
	assert.NoError(t, err)

	// TODO: Verify key index changed

	// Verify data is still accessible
	loadedData, err := store.Load(path)
	assert.NoError(t, err)
	assert.Equal(t, testData, loadedData)
}

func TestList(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	store, err := NewStore("test_list", key)
	assert.NoError(t, err)
	defer testCleanup(t, store)

	// Save multiple secrets
	secrets := map[string][]byte{
		"secret1":         []byte("data1"),
		"secret2":         []byte("data2"),
		"path/to/secret3": []byte("data3"),
	}

	for path, data := range secrets {
		err = store.Save(path, data)
		assert.NoError(t, err, "Failed to save %s", path)
	}

	// List secrets
	list, err := store.listDataFiles()
	assert.NoError(t, err)
	assert.Len(t, list, len(secrets))

	// Check that all expected secrets are in the list
	for path := range secrets {
		assert.Contains(t, list, path, "Secret %s not found in list", path)
	}
}
