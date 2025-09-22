package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStore_SaveLoadDelete(t *testing.T) {
	assert := assert.New(t)

	// Setup: Create a new store
	dir := filepath.Join(testStoreDir, "data_test_store")
	defer os.RemoveAll(dir) //nolint: errcheck

	store, err := NewStore(dir, testPassword)
	assert.NoError(err)
	assert.NotNil(store)
	defer store.Close()

	// Test case 1: Save and Load a secret successfully
	t.Run("Save and Load successful", func(t *testing.T) {
		secretPath := "my/test/secret"
		sensitiveData := []byte("this is a super secret message")

		err = store.Save(secretPath, sensitiveData)
		assert.NoError(err)

		loadedData, err := store.Load(secretPath)
		assert.NoError(err)
		assert.Equal(sensitiveData, loadedData)
	})

	// Test case 2: Overwrite an existing secret
	t.Run("Overwrite existing secret", func(t *testing.T) {
		secretPath := "my/test/secret_overwrite"
		oldData := []byte("old data")
		newData := []byte("new data")

		err = store.Save(secretPath, oldData)
		assert.NoError(err)

		err = store.Save(secretPath, newData)
		assert.NoError(err)

		loadedData, err := store.Load(secretPath)
		assert.NoError(err)
		assert.Equal(newData, loadedData)
	})

	// Test case 3: Load a non-existent secret
	t.Run("Load non-existent secret", func(t *testing.T) {
		secretPath := "non/existent/secret"
		loadedData, err := store.Load(secretPath)
		assert.Error(err)
		assert.Nil(loadedData)
		assert.Contains(err.Error(), "secret not found")
	})

	// Test case 4: Delete an existing secret
	t.Run("Delete existing secret", func(t *testing.T) {
		secretPath := "my/secret/to/delete"
		sensitiveData := []byte("data to be deleted")

		err = store.Save(secretPath, sensitiveData)
		assert.NoError(err)

		err = store.Delete(secretPath)
		assert.NoError(err)

		// Verify it's deleted
		_, err = store.Load(secretPath)
		assert.Error(err)
		assert.Contains(err.Error(), "secret not found")
	})

	// Test case 5: Delete a non-existent secret
	t.Run("Delete non-existent secret", func(t *testing.T) {
		secretPath := "non/existent/secret_to_delete"
		err = store.Delete(secretPath)
		assert.Error(err)
		assert.Contains(err.Error(), "no such file or directory")
	})

	// Test case 6: Path outside store hierarchy (Save)
	t.Run("Save path outside hierarchy", func(t *testing.T) {
		secretPath := "../outside/secret"
		sensitiveData := []byte("data")
		err = store.Save(secretPath, sensitiveData)
		assert.Error(err)
		assert.Contains(err.Error(), "path outside store hierarchy")
	})

	// Test case 7: Path outside store hierarchy (Load)
	t.Run("Load path outside hierarchy", func(t *testing.T) {
		secretPath := "../outside/secret"
		_, err := store.Load(secretPath)
		assert.Error(err)
		assert.Contains(err.Error(), "path outside store hierarchy")
	})

	// Test case 8: Path outside store hierarchy (Delete)
	t.Run("Delete path outside hierarchy", func(t *testing.T) {
		secretPath := "../outside/secret"
		err = store.Delete(secretPath)
		assert.Error(err)
		assert.Contains(err.Error(), "path outside store hierarchy")
	})

	// Test case 9: Save and load empty data
	t.Run("Save and load empty data", func(t *testing.T) {
		secretPath := "empty/data"
		sensitiveData := []byte("")

		err = store.Save(secretPath, sensitiveData)
		assert.NoError(err)

		loadedData, err := store.Load(secretPath)
		assert.NoError(err)
		assert.Equal(sensitiveData, loadedData)
	})

	// Test case 10: Check getKeyIndex
	t.Run("Get key index", func(t *testing.T) {
		secretPath := "key/index/test"
		sensitiveData := []byte("data for key index")
		err = store.Save(secretPath, sensitiveData)
		assert.NoError(err)

		fullPath := filepath.Join(store.dir, secretPath)
		keyIndex, err := store.getKeyIndex(fullPath)
		assert.NoError(err)
		assert.Equal(store.currentKeyIndex, keyIndex)
	})
}

func TestDeriveKeyFromPassword(t *testing.T) {
	assert := assert.New(t)

	salt := []byte("a_random_salt_for_key_derivation_32bytes")
	shortSalt := []byte("short_salt")

	// Test case 1: Successful key derivation with valid salt
	t.Run("Successful key derivation", func(t *testing.T) {
		key, err := deriveKeyFromPassword(testPassword, salt)
		assert.NoError(err)
		assert.NotNil(key)
		assert.Len(key, Argon2KeyLen)

		// Ensure deterministic output for same input
		key2, err := deriveKeyFromPassword(testPassword, salt)
		assert.NoError(err)
		assert.Equal(key, key2)
	})

	// Test case 2: Short salt (should return error)
	t.Run("Short salt", func(t *testing.T) {
		key, err := deriveKeyFromPassword(testPassword, shortSalt)
		assert.Error(err)
		assert.Nil(key)
		assert.Contains(err.Error(), "salt must be at least 32 bytes")
	})

	// Test case 3: Empty password (Argon2id handles this, but we should ensure no crash)
	t.Run("Empty password", func(t *testing.T) {
		emptyPassword := []byte("")
		key, err := deriveKeyFromPassword(emptyPassword, salt)
		assert.NoError(err)
		assert.NotNil(key)
		assert.Len(key, Argon2KeyLen)
	})

	// Test case 4: Nil password
	t.Run("Nil password", func(t *testing.T) {
		key, err := deriveKeyFromPassword(nil, salt)
		assert.NoError(err)
		assert.NotNil(key)
		assert.Len(key, Argon2KeyLen)
	})
}

func TestGenerateSalt(t *testing.T) {
	assert := assert.New(t)

	// Test case 1: Successful salt generation
	t.Run("Successful salt generation", func(t *testing.T) {
		salt1, err := generateSalt()
		assert.NoError(err)
		assert.NotNil(salt1)
		assert.Len(salt1, 32)

		// Ensure salts are random (highly unlikely to be equal)
		salt2, err := generateSalt()
		assert.NoError(err)
		assert.NotNil(salt2)
		assert.Len(salt2, 32)
		assert.NotEqual(salt1, salt2)
	})
}
