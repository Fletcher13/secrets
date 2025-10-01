package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Helper function to create a new store for testing
func newTestStore(dir string) (*Store, error) {
	store := &Store{
		dir:           dir,
		keyDir:        filepath.Join(dir, keyDirName),
		saltFile:      filepath.Join(dir, keyDirName, primarySaltFile),
		curKeyIdxFile: filepath.Join(dir, keyDirName, curKeyIdxFile),
		primaryKey:    make([]byte, 32),
	}
	store.dirPerm = 0700
	store.filePerm = 0600

	if err := os.MkdirAll(store.keyDir, store.dirPerm); err != nil {
		return nil, err
	}

	salt := make([]byte, saltLength)
	if err := store.writeFile(store.saltFile, salt); err != nil {
		return nil, err
	}
	store.primaryKey = make([]byte, 32)

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

func TestNewStore(t *testing.T) {
	assert := assert.New(t)

	// Test case 1: Create a new store in an empty directory
	t.Run("New store in empty directory", func(t *testing.T) {
		dir := filepath.Join(testStoreDir, "new_store_test")
		defer os.RemoveAll(dir) //nolint: errcheck

		store, err := NewStore(dir, testPassword)
		assert.NoError(err)
		assert.NotNil(store)
		assert.NotNil(store.currentKey, "currentKey should not be nil")

		store.Close()
	})

	// Test case 2: Open an existing valid store
	t.Run("Open existing store", func(t *testing.T) {
		dir := filepath.Join(testStoreDir, "existing_store_test")
		defer os.RemoveAll(dir) //nolint: errcheck

		// Create an initial store
		store, err := NewStore(dir, testPassword)
		assert.NoError(err)
		assert.NotNil(store)
		store.Close()

		// Open the existing store
		store, err = NewStore(dir, testPassword)
		assert.NoError(err)
		assert.NotNil(store)
		assert.Equal(uint8(0), store.currentKeyIndex, "currentKeyIndex should be 0 after opening an existing store")
		store.Close()
	})

	// Test case 3: Empty password
	t.Run("Empty password", func(t *testing.T) {
		dir := filepath.Join(testStoreDir, "empty_password_test")
		defer os.RemoveAll(dir) //nolint: errcheck

		password := []byte("")
		store, err := NewStore(dir, password)
		assert.Error(err)
		assert.Nil(store)
		assert.Contains(err.Error(), "password must not be empty")
	})

	// Test case 4: Directory exists but is a file
	t.Run("Directory is a file", func(t *testing.T) {
		dir := filepath.Join(testStoreDir, "file_instead_of_dir_test")
		assert.NoError(os.MkdirAll(dir, 0700))
		defer os.RemoveAll(dir) //nolint: errcheck

		filePath := filepath.Join(dir, "testfile.txt")
		err := os.WriteFile(filePath, []byte("hello"), 0600)
		assert.NoError(err)

		store, err := NewStore(filePath, testPassword)
		assert.Error(err)
		assert.Nil(store)
		//TODO:		assert.Contains(err.Error(), "is not a directory")
	})

	// Test case 5: Non-empty directory that is not a store
	t.Run("Non-empty non-store directory", func(t *testing.T) {
		dir := filepath.Join(testStoreDir, "non_empty_non_store_test")
		assert.NoError(os.MkdirAll(dir, 0700))
		defer os.RemoveAll(dir) //nolint: errcheck

		err := os.WriteFile(filepath.Join(dir, "random.txt"), []byte("data"), 0600)
		assert.NoError(err)

		store, err := NewStore(dir, testPassword)
		assert.Error(err)
		assert.Nil(store)
		//TODO: assert.Contains(err.Error(), "is not empty")
	})
}

func TestStore_Close(t *testing.T) {
	assert := assert.New(t)

	// Create a new store
	dir := filepath.Join(testStoreDir, "close_test")
	defer os.RemoveAll(dir) //nolint: errcheck

	store, err := NewStore(dir, testPassword)
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

func TestStore_Passwd(t *testing.T) {
	assert := assert.New(t)

	dir := filepath.Join(testStoreDir, "passwd")
	defer os.RemoveAll(dir) //nolint: errcheck

	store, err := NewStore(dir, testPassword)
	assert.NoError(err)
	newPwDirPath := filepath.Join(dir, newPwDirName)

	// Test case 1: Successful passwd
	t.Run("Passwd Success", func(t *testing.T) {
		err := store.Passwd([]byte("new_password"))
		assert.NoError(err)
		assert.False(checkDirExists(newPwDirPath))
	})

	// Test case 2: Empty new password
	t.Run("Passwd Empty Password", func(t *testing.T) {
		err := store.Passwd([]byte(""))
		assert.Error(err)
		assert.False(checkDirExists(newPwDirPath))
	})

	// Test case 3: Store locked
	t.Run("Passwd locked", func(t *testing.T) {
		lk, err := store.lock(store.lockFile)
		assert.NoError(err)
		defer lk.unlock()
		err = store.Passwd(testPassword)
		assert.Error(err)
		assert.Contains(err.Error(), "is being modified")
		assert.False(checkDirExists(newPwDirPath))
	})

	// Test case 4: Successful passwd
	t.Run("Passwd Success", func(t *testing.T) {
		err := store.Passwd([]byte("new_password"))
		assert.NoError(err)
		assert.False(checkDirExists(newPwDirPath))
	})
}

func checkDirExists(dir string) bool {
	st, err := os.Stat(dir)
	if err == nil && st.IsDir() {
		return true
	}
	return false
}

func TestStore_checkNewStore(t *testing.T) {
	assert := assert.New(t)

	// Test case 1: Empty directory (should be a new store)
	t.Run("Empty directory", func(t *testing.T) {
		dir := filepath.Join(testStoreDir, "check_new_store_empty")
		defer os.RemoveAll(dir) //nolint: errcheck

		store := &Store{dir: dir}
		isNew, err := store.checkNewStore()
		assert.NoError(err)
		assert.True(isNew)
	})

	// Test case 2: Existing valid store
	t.Run("Existing valid store", func(t *testing.T) {
		dir := filepath.Join(testStoreDir, "check_new_store_existing")
		defer os.RemoveAll(dir) //nolint: errcheck

		_, err := newTestStore(dir)
		assert.NoError(err)

		store := &Store{
			dir:           dir,
			keyDir:        filepath.Join(dir, keyDirName),
			saltFile:      filepath.Join(dir, keyDirName, primarySaltFile),
			curKeyIdxFile: filepath.Join(dir, keyDirName, curKeyIdxFile),
		}
		isNew, err := store.checkNewStore()
		assert.NoError(err)
		assert.False(isNew)
	})

	// Test case 3: Directory exists but is a file
	t.Run("Directory is a file", func(t *testing.T) {
		dir := filepath.Join(testStoreDir, "check_new_store_file")
		assert.NoError(os.MkdirAll(dir, 0700))
		defer os.RemoveAll(dir) //nolint: errcheck

		filePath := filepath.Join(dir, "testfile.txt")
		err := os.WriteFile(filePath, []byte("hello"), 0600)
		assert.NoError(err)

		store := &Store{dir: filePath}
		_, err = store.checkNewStore()
		assert.Error(err)
		//TODO: assert.Contains(err.Error(), "is not a directory")
	})

	// Test case 4: Non-empty directory but not a store
	t.Run("Non-empty non-store directory", func(t *testing.T) {
		dir := filepath.Join(testStoreDir, "check_new_store_non_empty")
		assert.NoError(os.MkdirAll(dir, 0700))
		defer os.RemoveAll(dir) //nolint: errcheck

		err := os.WriteFile(filepath.Join(dir, "random.txt"), []byte("data"), 0600)
		assert.NoError(err)

		store := &Store{
			dir:    dir,
			keyDir: filepath.Join(dir, keyDirName),
		}
		_, err = store.checkNewStore()
		assert.Error(err)
	})

	// Test case 5: Invalid keys directory (file instead of dir)
	t.Run("Keys directory is a file", func(t *testing.T) {
		dir := filepath.Join(testStoreDir, "check_new_store_keys_file")
		assert.NoError(os.MkdirAll(dir, 0700))
		defer os.RemoveAll(dir) //nolint: errcheck

		keysDirPath := filepath.Join(dir, keyDirName)
		err := os.WriteFile(keysDirPath, []byte("invalid"), 0600)
		assert.NoError(err)

		store := &Store{
			dir:    dir,
			keyDir: keysDirPath,
		}
		isNew, err := store.checkNewStore()
		assert.Error(err)
		assert.False(isNew)
		//TODO: assert.Contains(err.Error(), "is not a directory")
	})

	// Test case 6: Missing salt file in an existing store
	t.Run("Missing salt file", func(t *testing.T) {
		dir := filepath.Join(testStoreDir, "check_new_store_missing_salt")
		defer os.RemoveAll(dir) //nolint: errcheck

		store, err := newTestStore(dir)
		assert.NoError(err)
		store.Close()

		// Remove the salt file
		err = os.Remove(filepath.Join(dir, keyDirName, primarySaltFile))
		assert.NoError(err)

		// Re-initialize store object for checkNewStore
		store = &Store{
			dir:           dir,
			keyDir:        filepath.Join(dir, keyDirName),
			saltFile:      filepath.Join(dir, keyDirName, primarySaltFile),
			curKeyIdxFile: filepath.Join(dir, keyDirName, curKeyIdxFile),
		}
		isNew, err := store.checkNewStore()
		assert.Error(err)
		assert.False(isNew)
		//TODO: assert.Contains(err.Error(), "no salt file")
	})

	// Test case 7: Invalid current key index file
	t.Run("Invalid current key index file", func(t *testing.T) {
		dir := filepath.Join(testStoreDir, "check_new_store_invalid_idx")
		defer os.RemoveAll(dir) //nolint: errcheck

		store, err := newTestStore(dir)
		assert.NoError(err)
		store.Close()

		// Corrupt the current key index file
		err = os.WriteFile(filepath.Join(dir, keyDirName, curKeyIdxFile), []byte("invalid"), 0600)
		assert.NoError(err)

		// Re-initialize store object for checkNewStore
		store = &Store{
			dir:           dir,
			keyDir:        filepath.Join(dir, keyDirName),
			saltFile:      filepath.Join(dir, keyDirName, primarySaltFile),
			curKeyIdxFile: filepath.Join(dir, keyDirName, curKeyIdxFile),
		}
		isNew, err := store.checkNewStore()
		assert.Error(err)
		assert.False(isNew)
		//TODO: assert.Contains(err.Error(), "no key index")
	})

	// Test case 8: Missing current key file
	t.Run("Missing current key file", func(t *testing.T) {
		dir := filepath.Join(testStoreDir, "check_new_store_missing_key")
		defer os.RemoveAll(dir) //nolint: errcheck

		store, err := newTestStore(dir)
		assert.NoError(err)
		store.Close()

		// Remove the current key file (key0)
		err = os.Remove(filepath.Join(dir, keyDirName, "key0"))
		assert.NoError(err)

		// Re-initialize store object for checkNewStore
		store = &Store{
			dir:           dir,
			keyDir:        filepath.Join(dir, keyDirName),
			saltFile:      filepath.Join(dir, keyDirName, primarySaltFile),
			curKeyIdxFile: filepath.Join(dir, keyDirName, curKeyIdxFile),
		}
		isNew, err := store.checkNewStore()
		assert.Error(err)
		assert.False(isNew)
		//TODO: assert.Contains(err.Error(), "no key file")
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
		dir := filepath.Join(testStoreDir, "check_old_keys_no_old")
		defer os.RemoveAll(dir) //nolint: errcheck

		store, err := NewStore(dir, testPassword)
		assert.NoError(err)
		assert.NotNil(store)

		err = store.checkForOldKeys()
		assert.NoError(err)
		store.Close()
	})

	// Test case 2: Multiple key files (should trigger recovery)
	t.Run("Multiple key files", func(t *testing.T) {
		dir := filepath.Join(testStoreDir, "check_old_keys_multiple")
		defer os.RemoveAll(dir) //nolint: errcheck

		corruptedStore, err := createCorruptedStore(dir, testPassword)
		assert.NoError(err)
		assert.NotNil(corruptedStore)

		// Open the store again, which will call checkForOldKeys
		store, err := NewStore(dir, testPassword)
		assert.NoError(err)
		assert.NotNil(store)
		// The recovery process runs in a goroutine, so we can't directly assert its immediate effect.
		// We can, however, check that checkForOldKeys itself returned no error.
		store.Close()
	})
}
