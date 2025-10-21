package darkstore

import (
	"fmt"
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

	store, err := newTestStore(dir)
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
		assert.NoError(err)
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

func BenchmarkEncrypt(b *testing.B) {
	store := &Store{
		currentKeyIndex: 0,
	}
	store.currentKey = []byte("a_32_character_byte_splice_key12")

	data := []byte("secret data")
	b.ResetTimer()
	for b.Loop() {
		_, err := store.encryptData(data)
		if err != nil {
			fmt.Printf("failed to encrypt: %v\n", err)
			return
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	store := &Store{
		currentKeyIndex: 0,
	}
	store.currentKey = []byte("a_32_character_byte_splice_key12")

	data := []byte("secret data")
	enc, err := store.encryptData(data)
	if err != nil {
		fmt.Printf("failed to encrypt: %v\n", err)
		return
	}

	b.ResetTimer()
	for b.Loop() {
		newData, err := store.decryptData(enc)
		if err != nil || string(newData) != string(data) {
			fmt.Printf("failed to decrypt: %v\n", err)
			return
		}
	}
}

func BenchmarkSaveCached(b *testing.B) {
	// Setup: Create a new store
	dir := filepath.Join(testStoreDir, "data_bench")
	_ = os.RemoveAll(dir)
	defer os.RemoveAll(dir) //nolint: errcheck

	store, err := newTestStore(dir)
	if err != nil {
		fmt.Printf("Failed to open store %s: %v\n", dir, err)
		return
	}
	defer store.Close()

	path := "cached_file"
	secret := []byte("secret")

	// Save it once to cache the disk block
	err = store.Save(path, secret)
	if err != nil {
		fmt.Printf("Failed to save secret %s: %v", path, err)
		return
	}

	b.ResetTimer()
	for b.Loop() {
		err := store.Save(path, secret)
		if err != nil {
			fmt.Printf("Failed to save secret %s: %v", path, err)
			return
		}
	}
}

func BenchmarkSave(b *testing.B) {
	// Setup: Create a new store
	dir := filepath.Join(testStoreDir, "data_bench")
	_ = os.RemoveAll(dir)
	// Do not delete this at the end of the test so BenchmarkLoad can
	// use the saved secrets from this benchmark.

	store, err := newTestStore(dir)
	if err != nil {
		fmt.Printf("Failed to open store %s: %v\n", dir, err)
		return
	}
	defer store.Close()

	i := 0

	b.ResetTimer()
	for b.Loop() {
		i++
		path := fmt.Sprintf("file%d", i)
		secret := []byte(fmt.Sprintf("secret%d", i))
		err := store.Save(path, secret)
		if err != nil {
			fmt.Printf("Failed to save secret %s: %v", path, err)
			return
		}
	}
}

func BenchmarkLoad(b *testing.B) {
	// Setup: Create a new store
	dir := filepath.Join(testStoreDir, "data_bench")
	defer os.RemoveAll(dir) //nolint: errcheck

	store, err := newTestStore(dir)
	if err != nil {
		fmt.Printf("Failed to open store %s: %v\n", dir, err)
		return
	}
	defer store.Close()

	i := 0
	loops := 0
	b.ResetTimer()
	for b.Loop() {
		i++
		path := fmt.Sprintf("file%d", i)
		expectedSecret := []byte(fmt.Sprintf("secret%d", i))
		secret, err := store.Load(path)
		if err != nil {
			i = 0 // Reached end of data saved by Save benchmark.
			loops++
		} else {
			if string(secret) != string(expectedSecret) {
				fmt.Printf("Failed to correctly load secret %s\n", path)
				return
			}
		}
	}
	fmt.Println("Load loops:", loops)
}
