package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStore_readFile(t *testing.T) {
	assert := assert.New(t)

	// Setup: Create a temporary directory and a dummy store object
	dir := filepath.Join("test_stores", "io_test_read")
	defer os.RemoveAll(dir)

	store := &Store{dir: dir}
	store.filePerm = 0600 // Default file permissions for tests

	// Test case 1: Reading an existing file successfully
	t.Run("Read existing file", func(t *testing.T) {
		filePath := filepath.Join(dir, "testfile.txt")
		expectedData := []byte("hello world")
		_ = os.WriteFile(filePath, expectedData, 0600)

		data, err := store.readFile(filePath)
		assert.NoError(err)
		assert.Equal(expectedData, data)
	})

	// Test case 2: Attempting to read a non-existent file
	t.Run("Read non-existent file", func(t *testing.T) {
		filePath := filepath.Join(dir, "nonexistent.txt")
		data, err := store.readFile(filePath)
		assert.Error(err)
		assert.Nil(data)
		assert.True(os.IsNotExist(err))
		assert.Contains(err.Error(), "failed to read file")
	})

	// Test case 3: Attempting to read a file without appropriate permissions
	t.Run("Read file without permissions", func(t *testing.T) {
		if os.Geteuid() == 0 { // Skip if running as root
			t.Skip("Skipping permission test when running as root")
		}
		filePath := filepath.Join(dir, "no_perm_read.txt")
		_ = os.WriteFile(filePath, []byte("secret"), 0000) // No read permissions

		data, err := store.readFile(filePath)
		assert.Error(err)
		assert.Nil(data)
		assert.Contains(err.Error(), "permission denied")
	})
}

func TestStore_writeFile(t *testing.T) {
	assert := assert.New(t)

	// Setup: Create a temporary directory and a dummy store object
	dir := filepath.Join("test_stores", "io_test_write")
	defer os.RemoveAll(dir)

	store := &Store{dir: dir}
	store.filePerm = 0600 // Default file permissions for tests

	// Test case 1: Writing to a new file successfully
	t.Run("Write to new file", func(t *testing.T) {
		filePath := filepath.Join(dir, "newfile.txt")
		dataToWrite := []byte("new content")
		err := store.writeFile(filePath, dataToWrite)
		assert.NoError(err)

		readData, err := os.ReadFile(filePath)
		assert.NoError(err)
		assert.Equal(dataToWrite, readData)
	})

	// Test case 2: Overwriting an existing file successfully
	t.Run("Overwrite existing file", func(t *testing.T) {
		filePath := filepath.Join(dir, "existingfile.txt")
		_ = os.WriteFile(filePath, []byte("old content"), 0600)
		dataToWrite := []byte("overwritten content")

		err := store.writeFile(filePath, dataToWrite)
		assert.NoError(err)

		readData, err := os.ReadFile(filePath)
		assert.NoError(err)
		assert.Equal(dataToWrite, readData)
	})

	// Test case 3: Attempting to write to a file in a non-existent directory
	t.Run("Write to non-existent directory", func(t *testing.T) {
		filePath := filepath.Join(dir, "nonexistentdir", "file.txt")
		dataToWrite := []byte("content")

		err := store.writeFile(filePath, dataToWrite)
		assert.Error(err)
		assert.Contains(err.Error(), "no such file or directory")
	})

	// Test case 4: Attempting to write to a file without appropriate permissions (directory)
	t.Run("Write to directory without permissions", func(t *testing.T) {
		if os.Geteuid() == 0 { // Skip if running as root
			t.Skip("Skipping permission test when running as root")
		}
		noPermDir := filepath.Join(dir, "nopermdir")
		_ = os.Mkdir(noPermDir, 0000)   // No write permissions on directory
		defer os.Chmod(noPermDir, 0700) // Clean up permissions for defer os.RemoveAll

		filePath := filepath.Join(noPermDir, "file.txt")
		dataToWrite := []byte("content")

		err := store.writeFile(filePath, dataToWrite)
		assert.Error(err)
		assert.Contains(err.Error(), "permission denied")
	})

	// Test case 5: Attempting to write to a file without appropriate permissions (file)
	t.Run("Write to file without permissions", func(t *testing.T) {
		if os.Geteuid() == 0 { // Skip if running as root
			t.Skip("Skipping permission test when running as root")
		}
		filePath := filepath.Join(dir, "no_perm_file.txt")
		_ = os.WriteFile(filePath, []byte("original"), 0400) // No write permissions on file
		dataToWrite := []byte("new content")

		err := store.writeFile(filePath, dataToWrite)
		assert.Error(err)
		assert.Contains(err.Error(), "permission denied")
	})
}
