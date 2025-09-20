package secrets

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewStore(t *testing.T) {
	assert := assert.New(t)

	// Test case 1: Create a new store in an empty directory
	t.Run("New store in empty directory", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "new_store_test")
		assert.NoError(err)
		defer os.RemoveAll(dir)

		password := []byte("a-very-secret-password-that-is-long-enough")
		store, err := NewStore(dir, password)
		assert.NoError(err)
		assert.NotNil(store)
		assert.NotNil(store.currentKey, "currentKey should not be nil")

		store.Close()
	})

	// Test case 2: Open an existing valid store
	t.Run("Open existing store", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "existing_store_test")
		assert.NoError(err)
		defer os.RemoveAll(dir)

		password := []byte("a-very-secret-password-that-is-long-enough")
		// Create an initial store
		store, err := NewStore(dir, password)
		assert.NoError(err)
		assert.NotNil(store)
		store.Close()

		// Open the existing store
		store, err = NewStore(dir, password)
		assert.NoError(err)
		assert.NotNil(store)
		assert.Equal(uint8(0), store.currentKeyIndex, "currentKeyIndex should be 0 after opening an existing store")
		store.Close()
	})

	// Test case 3: Empty password
	t.Run("Empty password", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "empty_password_test")
		assert.NoError(err)
		defer os.RemoveAll(dir)

		password := []byte("")
		store, err := NewStore(dir, password)
		assert.Error(err)
		assert.Nil(store)
		assert.Contains(err.Error(), "password must not be empty")
	})

	// Test case 4: Directory exists but is a file
	t.Run("Directory is a file", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "file_instead_of_dir_test")
		assert.NoError(err)
		defer os.RemoveAll(dir)

		filePath := filepath.Join(dir, "testfile.txt")
		err = ioutil.WriteFile(filePath, []byte("hello"), 0600)
		assert.NoError(err)

		password := []byte("a-very-secret-password-that-is-long-enough")
		store, err := NewStore(filePath, password)
		assert.Error(err)
		assert.Nil(store)
		assert.Contains(err.Error(), "is not a directory")
	})

	// Test case 5: Non-empty directory that is not a store
	t.Run("Non-empty non-store directory", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "non_empty_non_store_test")
		assert.NoError(err)
		defer os.RemoveAll(dir)

		err = ioutil.WriteFile(filepath.Join(dir, "random.txt"), []byte("data"), 0600)
		assert.NoError(err)

		password := []byte("a-very-secret-password-that-is-long-enough")
		store, err := NewStore(dir, password)
		assert.Error(err)
		assert.Nil(store)
		assert.Contains(err.Error(), "is not empty")
	})
}

func TestStore_Close(t *testing.T) {
	assert := assert.New(t)

	// Create a new store
	dir, err := ioutil.TempDir("", "close_test")
	assert.NoError(err)
	defer os.RemoveAll(dir)

	password := []byte("a-very-secret-password-that-is-long-enough")
	store, err := NewStore(dir, password)
	assert.NoError(err)
	assert.NotNil(store)

	// Save some data to ensure primaryKey and currentKey are populated
	store.primaryKey = []byte("some-primary-key-data-1234567890123")
	store.currentKey = []byte("some-current-key-data-1234567890123")

	store.Close()

	// Verify keys are wiped (all zeros)
	for _, b := range store.primaryKey {
		assert.Equal(byte(0), b, "primaryKey should be zeroed")
	}
	for _, b := range store.currentKey {
		assert.Equal(byte(0), b, "currentKey should be zeroed")
	}

	// Verify store fields are cleared
	assert.Equal("", store.dir)
	assert.Equal("", store.keyDir)
	assert.Equal("", store.saltFile)
	assert.Equal("", store.curKeyIdxFile)
}

func TestStore_checkNewStore(t *testing.T) {
	assert := assert.New(t)

	// Helper function to create a new store for testing
	createTestStore := func(dir string, password []byte) (*Store, error) {
		store := &Store{
			dir:           dir,
			keyDir:        filepath.Join(dir, KeyDir),
			saltFile:      filepath.Join(dir, KeyDir, PrimSaltFile),
			curKeyIdxFile: filepath.Join(dir, KeyDir, CurKeyIdxFile),
			primaryKey:    make([]byte, 32),
		}
		store.dirPerm = 0700
		store.filePerm = 0600

		if err := os.MkdirAll(store.keyDir, store.dirPerm); err != nil {
			return nil, err
		}

		if err := store.createPrimaryKey(password); err != nil {
			return nil, err
		}
		_, err := store.newKey(0)
		if err != nil {
			return nil, err
		}
		store.currentKeyIndex = 0
		if err := store.saveCurrentKeyIndex(); err != nil {
			return nil, err
		}
		return store, nil
	}

	// Test case 1: Empty directory (should be a new store)
	t.Run("Empty directory", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "check_new_store_empty")
		assert.NoError(err)
		defer os.RemoveAll(dir)

		store := &Store{dir: dir}
		isNew, err := store.checkNewStore()
		assert.NoError(err)
		assert.True(isNew)
	})

	// Test case 2: Existing valid store
	t.Run("Existing valid store", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "check_new_store_existing")
		assert.NoError(err)
		defer os.RemoveAll(dir)

		password := []byte("some-password")
		_, err = createTestStore(dir, password)
		assert.NoError(err)

		store := &Store{
			dir:           dir,
			keyDir:        filepath.Join(dir, KeyDir),
			saltFile:      filepath.Join(dir, KeyDir, PrimSaltFile),
			curKeyIdxFile: filepath.Join(dir, KeyDir, CurKeyIdxFile),
		}
		isNew, err := store.checkNewStore()
		assert.NoError(err)
		assert.False(isNew)
	})

	// Test case 3: Directory exists but is a file
	t.Run("Directory is a file", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "check_new_store_file")
		assert.NoError(err)
		defer os.RemoveAll(dir)

		filePath := filepath.Join(dir, "testfile.txt")
		err = ioutil.WriteFile(filePath, []byte("hello"), 0600)
		assert.NoError(err)

		store := &Store{dir: filePath}
		isNew, err := store.checkNewStore()
		assert.Error(err)
		assert.False(isNew)
		assert.Contains(err.Error(), "is not a directory")
	})

	// Test case 4: Non-empty directory but not a store
	t.Run("Non-empty non-store directory", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "check_new_store_non_empty")
		assert.NoError(err)
		defer os.RemoveAll(dir)

		err = ioutil.WriteFile(filepath.Join(dir, "random.txt"), []byte("data"), 0600)
		assert.NoError(err)

		store := &Store{
			dir:    dir,
			keyDir: filepath.Join(dir, KeyDir),
		}
		isNew, err := store.checkNewStore()
		assert.Error(err)
		assert.True(isNew) // Should be considered new, but fail due to non-empty dir
		assert.Contains(err.Error(), "is not empty")
	})

	// Test case 5: Invalid keys directory (file instead of dir)
	t.Run("Keys directory is a file", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "check_new_store_keys_file")
		assert.NoError(err)
		defer os.RemoveAll(dir)

		keysDirPath := filepath.Join(dir, KeyDir)
		err = ioutil.WriteFile(keysDirPath, []byte("invalid"), 0600)
		assert.NoError(err)

		store := &Store{
			dir:    dir,
			keyDir: keysDirPath,
		}
		isNew, err := store.checkNewStore()
		assert.Error(err)
		assert.False(isNew)
		assert.Contains(err.Error(), "is not a directory")
	})

	// Test case 6: Missing salt file in an existing store
	t.Run("Missing salt file", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "check_new_store_missing_salt")
		assert.NoError(err)
		defer os.RemoveAll(dir)

		password := []byte("some-password")
		store, err := createTestStore(dir, password)
		assert.NoError(err)
		store.Close()

		// Remove the salt file
		err = os.Remove(filepath.Join(dir, KeyDir, PrimSaltFile))
		assert.NoError(err)

		// Re-initialize store object for checkNewStore
		store = &Store{
			dir:           dir,
			keyDir:        filepath.Join(dir, KeyDir),
			saltFile:      filepath.Join(dir, KeyDir, PrimSaltFile),
			curKeyIdxFile: filepath.Join(dir, KeyDir, CurKeyIdxFile),
		}
		isNew, err := store.checkNewStore()
		assert.Error(err)
		assert.False(isNew)
		assert.Contains(err.Error(), "no salt file")
	})

	// Test case 7: Invalid current key index file
	t.Run("Invalid current key index file", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "check_new_store_invalid_idx")
		assert.NoError(err)
		defer os.RemoveAll(dir)

		password := []byte("some-password")
		store, err := createTestStore(dir, password)
		assert.NoError(err)
		store.Close()

		// Corrupt the current key index file
		err = ioutil.WriteFile(filepath.Join(dir, KeyDir, CurKeyIdxFile), []byte("invalid"), 0600)
		assert.NoError(err)

		// Re-initialize store object for checkNewStore
		store = &Store{
			dir:           dir,
			keyDir:        filepath.Join(dir, KeyDir),
			saltFile:      filepath.Join(dir, KeyDir, PrimSaltFile),
			curKeyIdxFile: filepath.Join(dir, KeyDir, CurKeyIdxFile),
		}
		isNew, err := store.checkNewStore()
		assert.Error(err)
		assert.False(isNew)
		assert.Contains(err.Error(), "no key index")
	})

	// Test case 8: Missing current key file
	t.Run("Missing current key file", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "check_new_store_missing_key")
		assert.NoError(err)
		defer os.RemoveAll(dir)

		password := []byte("some-password")
		store, err := createTestStore(dir, password)
		assert.NoError(err)
		store.Close()

		// Remove the current key file (key0)
		err = os.Remove(filepath.Join(dir, KeyDir, "key0"))
		assert.NoError(err)

		// Re-initialize store object for checkNewStore
		store = &Store{
			dir:           dir,
			keyDir:        filepath.Join(dir, KeyDir),
			saltFile:      filepath.Join(dir, KeyDir, PrimSaltFile),
			curKeyIdxFile: filepath.Join(dir, KeyDir, CurKeyIdxFile),
		}
		isNew, err := store.checkNewStore()
		assert.Error(err)
		assert.False(isNew)
		assert.Contains(err.Error(), "no key file")
	})
}

func TestStore_checkForOldKeys(t *testing.T) {
	assert := assert.New(t)

	// Helper to create a store with multiple key files (simulating a crash during rotation)
	createCorruptedStore := func(dir string, password []byte) (*Store, error) {
		store, err := NewStore(dir, password)
		if err != nil {
			return nil, err
		}

		// Create an old key file (key1) in addition to key0
		_, err = store.newKey(1) // This will create key1 and save it.
		if err != nil {
			return nil, err
		}
		store.Close()
		return store, nil
	}

	// Test case 1: No old keys (should do nothing)
	t.Run("No old keys", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "check_old_keys_no_old")
		assert.NoError(err)
		defer os.RemoveAll(dir)

		password := []byte("some-password")
		store, err := NewStore(dir, password)
		assert.NoError(err)
		assert.NotNil(store)

		err = store.checkForOldKeys()
		assert.NoError(err)
		store.Close()
	})

	// Test case 2: Multiple key files (should trigger recovery)
	t.Run("Multiple key files", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "check_old_keys_multiple")
		assert.NoError(err)
		defer os.RemoveAll(dir)

		password := []byte("some-password")
		corruptedStore, err := createCorruptedStore(dir, password)
		assert.NoError(err)
		assert.NotNil(corruptedStore)

		// Open the store again, which will call checkForOldKeys
		store, err := NewStore(dir, password)
		assert.NoError(err)
		assert.NotNil(store)
		// The recovery process runs in a goroutine, so we can't directly assert its immediate effect.
		// We can, however, check that checkForOldKeys itself returned no error.
		store.Close()
	})
}
