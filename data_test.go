package secrets

import (
	"crypto/rand"
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

func TestDeriveKeyFromPassword(t *testing.T) {
	assert := assert.New(t)

	salt := []byte("16_byte_salt_foo")
	shortSalt := []byte("short_salt")

	// Test case 1: Successful key derivation with valid salt
	t.Run("Successful key derivation", func(t *testing.T) {
		key, err := deriveKeyFromPassword(testPassword, salt)
		assert.NoError(err)
		assert.NotNil(key)
		assert.Len(key, int(argon2KeyLen))

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
		assert.Contains(err.Error(), "salt must be at least 16 bytes")
	})

	// Test case 3: Empty password (Argon2id handles this, but we should ensure no crash)
	t.Run("Empty password", func(t *testing.T) {
		emptyPassword := []byte("")
		key, err := deriveKeyFromPassword(emptyPassword, salt)
		assert.NoError(err)
		assert.NotNil(key)
		assert.Len(key, int(argon2KeyLen))
	})

	// Test case 4: Nil password
	t.Run("Nil password", func(t *testing.T) {
		key, err := deriveKeyFromPassword(nil, salt)
		assert.NoError(err)
		assert.NotNil(key)
		assert.Len(key, int(argon2KeyLen))
	})
}

func TestGenerateSalt(t *testing.T) {
	assert := assert.New(t)

	// Test case 1: Successful salt generation
	t.Run("Successful salt generation", func(t *testing.T) {
		salt1, err := generateSalt()
		assert.NoError(err)
		assert.NotNil(salt1)
		assert.Len(salt1, 16)

		// Ensure salts are random (highly unlikely to be equal)
		salt2, err := generateSalt()
		assert.NoError(err)
		assert.NotNil(salt2)
		assert.Len(salt2, 16)
		assert.NotEqual(salt1, salt2)
	})
}

func TestNewStoreOne(t *testing.T) {
	assert := assert.New(t)
	// Setup: Create a new store
	dir := filepath.Join(testStoreDir, "data_one")
	_ = os.RemoveAll(dir)
	//defer os.RemoveAll(dir) //nolint: errcheck

	store, err := NewStore(dir, testPassword)
	assert.NoError(err)
	assert.NotNil(store)
	defer store.Close()

	i := 0
	path := fmt.Sprintf("file%d", i)
	secret := []byte(fmt.Sprintf("secret%d", i))
	assert.NoError(store.Save(path, secret))

	store2, err := NewStore(dir, testPassword)
	assert.NoError(err)
	assert.NotNil(store2)
	defer store2.Close()

	loadedSecret, err := store2.Load(path)
	assert.NoError(err)
	assert.Equal(string(secret), string(loadedSecret))

}

func TestOpenStoreTwo(t *testing.T) {
	assert := assert.New(t)
	// Setup: Open an existing store
	dir := filepath.Join(testStoreDir, "data_one")
	//defer os.RemoveAll(dir) //nolint: errcheck

	store, err := NewStore(dir, testPassword)
	assert.NoError(err)
	defer store.Close()

	i := 0
	path := fmt.Sprintf("file%d", i)
	expSecret := []byte(fmt.Sprintf("secret%d", i))
	secret, err := store.Load(path)
	assert.NoError(err)
	assert.Equal(string(secret), string(expSecret))
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

func BenchmarkSave(b *testing.B) {
	// Setup: Create a new store
	dir := filepath.Join(testStoreDir, "data_bench")
	_ = os.RemoveAll(dir)
	//defer os.RemoveAll(dir) //nolint: errcheck

	store, err := NewStore(dir, testPassword)
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

	store, err := NewStore(dir, testPassword)
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

func BenchmarkArgon2id(b *testing.B) {
	salt := make([]byte, 16)
	password := make([]byte, 16)

	b.ResetTimer() // Do not time the initial derivation
	for b.Loop() {
		_, _ = rand.Read(salt)
		_, _ = rand.Read(password)
		_, _ = deriveKeyFromPassword(testPassword, salt)
	}
}

/*
func BenchmarkArgon2id2Gig(b *testing.B) {
	salt := make([]byte, 16)
	password := make([]byte, 16)
	argon2Time = 1
	argon2Memory = 2 * 1024 * 1024

	b.ResetTimer()	// Do not time the initial derivation
	for b.Loop() {
		_, _ = rand.Read(salt)
		_, _ = rand.Read(password)
		_, _ = deriveKeyFromPassword(testPassword, salt)
	}
}
*/
