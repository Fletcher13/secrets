package darkstore

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStore_Rotate(t *testing.T) {
	assert := assert.New(t)

	// Setup: Create a new store
	dir := filepath.Join(testStoreDir, "rotate_test_store")
	defer os.RemoveAll(dir) //nolint: errcheck
	store, err := NewStore(dir, testPassword)
	assert.NoError(err)
	assert.NotNil(store)
	defer store.Close()

	// Save some data to be re-encrypted
	secretPath1 := "my/secret/data1"
	data1 := []byte("sensitive info 1")
	assert.NoError(store.Save(secretPath1, data1))

	secretPath2 := "another/secret/data2"
	data2 := []byte("sensitive info 2")
	assert.NoError(store.Save(secretPath2, data2))

	initialKeyIndex := store.currentKeyIndex

	// Test case 1: Successful key rotation
	t.Run("Successful rotation", func(t *testing.T) {
		err = store.Rotate()
		assert.NoError(err)
		// New key index should be incremented
		assert.Equal(initialKeyIndex+1, store.currentKeyIndex)

		// Allow time for goroutine (updateFiles) to complete
		time.Sleep(20 * time.Millisecond)

		// Verify all files are re-encrypted with the new key
		loadedData1, err := store.Load(secretPath1)
		assert.NoError(err)
		assert.Equal(data1, loadedData1)

		loadedData2, err := store.Load(secretPath2)
		assert.NoError(err)
		assert.Equal(data2, loadedData2)

		// Verify old key file is deleted
		oldKeyFilePath := filepath.Join(store.keyDir, fmt.Sprintf("key%d", initialKeyIndex))
		_, err = os.Stat(oldKeyFilePath)
		assert.True(os.IsNotExist(err), "Old key file should be deleted")

		// Verify new key file exists
		newKeyFilePath := filepath.Join(store.keyDir, fmt.Sprintf("key%d", store.currentKeyIndex))
		_, err = os.Stat(newKeyFilePath)
		assert.NoError(err, "New key file should exist")
	})

	// Test case 2: Max key index rollover (simulate by setting currentKeyIndex to 255)
	t.Run("Key index rollover", func(t *testing.T) {
		store.currentKey, err = store.newKey(255)
		assert.NoError(err)
		store.currentKeyIndex = 255       // Set to max
		err = store.saveCurrentKeyIndex() // Save to disk
		assert.NoError(err)

		// Save some data to be re-encrypted (after setting currentKeyIndex)
		secretPath3 := "rollover/secret"
		data3 := []byte("rollover data")
		assert.NoError(store.Save(secretPath3, data3))

		data4, err := store.Load(secretPath3)
		assert.NoError(err)
		assert.Equal(data4, data3)

		err = store.Rotate()
		assert.NoError(err)

		// New key index should roll over to 0
		assert.Equal(uint8(0), store.currentKeyIndex)

		// Allow time for goroutine (updateFiles) to complete
		time.Sleep(20 * time.Millisecond)

		// Verify data is still loadable
		loadedData3, err := store.Load(secretPath3)
		assert.NoError(err)
		assert.Equal(data3, loadedData3)
	})
}

func TestStore_listDataFiles(t *testing.T) {
	assert := assert.New(t)

	// Setup: Create a new store and populate with various files and directories
	dir := filepath.Join(testStoreDir, "list_data_files_test")
	absDir, _ := filepath.Abs(dir)
	defer os.RemoveAll(dir) //nolint: errcheck

	store, err := newTestStore(dir)
	assert.NoError(err)
	assert.NotNil(store)
	defer store.Close()

	// Create some dummy data files
	assert.NoError(store.Save("file1.txt", []byte("data1")))
	assert.NoError(store.Save("subdir/file2.txt", []byte("data2")))
	assert.NoError(store.Save("dir2/nested/file3.txt", []byte("data3")))

	// Create a non-secret file outside the store's data structure (should not be listed by listDataFiles)
	outsideFilePath := filepath.Join(dir, "../outsider.txt")
	assert.NoError(os.WriteFile(outsideFilePath, []byte("outsider data"), 0600))
	defer os.Remove(outsideFilePath) //nolint: errcheck

	// Test case 1: List files in a populated store
	t.Run("List files in populated store", func(t *testing.T) {
		files, err := store.listDataFiles()
		assert.NoError(err)
		assert.Len(files, 3) // Should only include the 3 data files

		expectedFiles := []string{
			filepath.Join(absDir, "file1.txt"),
			filepath.Join(absDir, "subdir", "file2.txt"),
			filepath.Join(absDir, "dir2", "nested", "file3.txt"),
		}
		// Sort to ensure consistent order for comparison
		sort.Strings(files)
		sort.Strings(expectedFiles)
		assert.Equal(expectedFiles, files)
	})

	// Test case 2: List files in an empty store (after deleting all data files)
	t.Run("List files in empty store", func(t *testing.T) {
		// Delete all previously created data files
		assert.NoError(store.Delete("file1.txt"))
		assert.NoError(store.Delete("subdir/file2.txt"))
		assert.NoError(store.Delete("dir2/nested/file3.txt"))

		files, err := store.listDataFiles()
		assert.NoError(err)
		assert.Len(files, 0)
	})
}

func TestStore_reencryptFile(t *testing.T) {
	assert := assert.New(t)

	// Setup: Create a new store
	dir := filepath.Join(testStoreDir, "reencrypt_file_test")
	defer os.RemoveAll(dir) //nolint: errcheck

	store, err := NewStore(dir, testPassword)
	assert.NoError(err)
	assert.NotNil(store)
	defer store.Close()
	assert.NoError(os.MkdirAll(store.tempDir, store.dirPerm))

	// Save an initial secret
	secretPath := "my/reencrypt/secret"
	fullPath := filepath.Join(dir, secretPath)
	originalData := []byte("data to be re-encrypted")
	assert.NoError(store.Save(secretPath, originalData))

	// Manually rotate the key to create an "old" key scenario
	// Generate new key
	newKey, err := store.newKey(1)
	assert.NoError(err)

	// Set current key
	store.currentKey = newKey
	store.currentKeyIndex = 1
	err = store.saveCurrentKeyIndex()
	assert.NoError(err)

	// Test case 1: Re-encrypt a file with an old key
	t.Run("Re-encrypt file with old key", func(t *testing.T) {
		// Before re-encryption, the file should still be encrypted with the old key
		origKeyIndex, err := store.getKeyIndex(fullPath)
		assert.NoError(err)
		assert.NotEqual(store.currentKeyIndex, origKeyIndex)
		store.reencryptFile(fullPath)

		// After re-encryption, the file should be encrypted with the current key
		newKeyIndex, err := store.getKeyIndex(fullPath)
		assert.NoError(err)
		assert.Equal(store.currentKeyIndex, newKeyIndex)

		loadedData, err := store.Load(secretPath)
		assert.NoError(err)
		assert.Equal(originalData, loadedData)
	})

	// Test case 2: Re-encrypt a file that is already using the current key
	t.Run("File already current key", func(t *testing.T) {
		// This file should already be using the current key from the previous test.
		initialModTime, err := os.Stat(fullPath)
		assert.NoError(err)

		store.reencryptFile(fullPath)

		// The file should not have been modified
		finalModTime, err := os.Stat(fullPath)
		assert.NoError(err)
		assert.Equal(initialModTime.ModTime(), finalModTime.ModTime())
	})

	// Test case 3: Handle corrupted file (unreadable)
	t.Run("Corrupted file (unreadable)", func(t *testing.T) {
		corruptedPath := filepath.Join(dir, "corrupted.bin")
		// Create a file but remove read permissions to simulate unreadable
		assert.NoError(os.WriteFile(corruptedPath, []byte("corrupt data"), 0000))
		defer os.Chmod(corruptedPath, 0600) //nolint: errcheck // Restore permissions for cleanup

		// Re-encryption should not panic and ideally log an error (not directly testable here)
		assert.NotPanics(func() { store.reencryptFile(corruptedPath) })

		// File should still exist as reencryptFile only returns. No delete yet.
		_, err := os.Stat(corruptedPath)
		assert.NoError(err)
	})

	// Test case 4: Handle decryption failure (invalid encrypted data format)
	t.Run("Decryption failure", func(t *testing.T) {
		invalidDataPath := filepath.Join(dir, "invalid_encrypted.bin")
		assert.NoError(os.WriteFile(invalidDataPath, []byte{0x01, 0x02, 0x03}, 0600)) // Invalid encrypted data

		assert.NotPanics(func() { store.reencryptFile(invalidDataPath) })

		// File should still exist as reencryptFile only returns.
		_, err := os.Stat(invalidDataPath)
		assert.NoError(err)
	})
}
