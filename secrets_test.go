package secrets

import (
	"os"
	"path/filepath"
)

const (
	testStoreDir = "test_stores"
)

var (
	testPassword = []byte("a-very-secret-password-that-is-long-enough")
)

// Helper function to create a new store for testing
func newTestStore(dir string) (*Store, error) {
	fullPath, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	store := &Store{
		dir:           fullPath,
		keyDir:        filepath.Join(fullPath, keyDirName),
		saltFile:      filepath.Join(fullPath, keyDirName, primarySaltFile),
		curKeyIdxFile: filepath.Join(fullPath, keyDirName, curKeyIdxFile),
		lockFile:      filepath.Join(fullPath, keyDirName, lockFileName),
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
	_, err = store.newKey(0)
	if err != nil {
		return nil, err
	}
	store.currentKey = make([]byte, 32)
	store.currentKeyIndex = 0
	if err := store.saveCurrentKeyIndex(); err != nil {
		return nil, err
	}
	return store, nil
}
