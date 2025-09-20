package secrets

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSaveAndLoad(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	store, err := NewStore("test_save_load", key)
	assert.NoError(t, err)
	defer testCleanup(t, store)

	// Test saving and loading data
	testData := []byte("test_secret_data")
	path := "test/secret"

	err = store.Save(path, testData)
	assert.NoError(t, err)

	loadedData, err := store.Load(path)
	assert.NoError(t, err)
	assert.Equal(t, testData, loadedData)
}

func TestDelete(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	store, err := NewStore("test_delete", key)
	assert.NoError(t, err)
	defer testCleanup(t, store)

	// Save a secret
	path := "test/secret"
	data := []byte("test_data")
	err = store.Save(path, data)
	assert.NoError(t, err)

	// Verify it exists
	loadedData, err := store.Load(path)
	assert.NoError(t, err)
	assert.Equal(t, data, loadedData)

	// Delete the secret
	err = store.Delete(path)
	assert.NoError(t, err)

	// Verify it's gone
	_, err = store.Load(path)
	assert.Error(t, err, "Expected error when loading deleted secret")
}

func TestDeriveKeyFromPassword(t *testing.T) {
	password := []byte("test_password")
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}

	key, err := deriveKeyFromPassword(password, salt)
	assert.NoError(t, err)
	assert.Len(t, key, 32)

	// Same password and salt should produce same key
	key2, err := deriveKeyFromPassword(password, salt)
	assert.NoError(t, err)
	assert.Equal(t, key, key2)
}

func TestGenerateSalt(t *testing.T) {
	salt, err := generateSalt()
	assert.NoError(t, err)
	assert.Len(t, salt, 32)

	// Generate another salt and ensure they're different
	salt2, err := generateSalt()
	assert.NoError(t, err)
	assert.Len(t, salt2, 32)
	assert.NotEqual(t, salt, salt2)
}

// Benchmark tests for deriveKeyFromPassword
func BenchmarkDeriveKeyFromPassword(b *testing.B) {
	// Generate a random password and salt for testing
	password := make([]byte, 32)
	salt := make([]byte, 32)

	_, err := rand.Read(password)
	assert.NoError(b, err)

	_, err = rand.Read(salt)
	assert.NoError(b, err)

	b.ResetTimer() // Don't include setup time in benchmark

	for i := 0; i < b.N; i++ {
		_, err := deriveKeyFromPassword(password, salt)
		assert.NoError(b, err)
	}
}

// Benchmark with different password lengths
func BenchmarkDeriveKeyFromPassword_ShortPassword(b *testing.B) {
	password := []byte("short")
	salt := make([]byte, 32)
	_, _ = rand.Read(salt)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := deriveKeyFromPassword(password, salt)
		assert.NoError(b, err)
	}
}

func BenchmarkDeriveKeyFromPassword_LongPassword(b *testing.B) {
	password := make([]byte, 1024) // 1KB password
	salt := make([]byte, 32)
	_, _ = rand.Read(password)
	_, _ = rand.Read(salt)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := deriveKeyFromPassword(password, salt)
		assert.NoError(b, err)
	}
}

// Benchmark with different salt sizes
func BenchmarkDeriveKeyFromPassword_MinimumSalt(b *testing.B) {
	password := []byte("test_password")
	salt := make([]byte, 16) // Minimum required salt size
	_, _ = rand.Read(salt)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := deriveKeyFromPassword(password, salt)
		assert.NoError(b, err)
	}
}

func BenchmarkDeriveKeyFromPassword_LargeSalt(b *testing.B) {
	password := []byte("test_password")
	salt := make([]byte, 64) // Larger salt
	_, _ = rand.Read(salt)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := deriveKeyFromPassword(password, salt)
		assert.NoError(b, err)
	}
}
