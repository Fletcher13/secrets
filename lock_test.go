package darkstore

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStore_lock(t *testing.T) {
	assert := assert.New(t)

	// Setup: Create a temporary directory and a dummy store object
	dir := filepath.Join(testStoreDir, "lock_test")
	defer os.RemoveAll(dir) //nolint: errcheck

	store := &Store{
		dir:      dir,
		dirPerm:  0700,
		filePerm: 0600,
	}

	// Test case 1: Acquire exclusive lock on a new file
	t.Run("Lock new file exclusive", func(t *testing.T) {
		filePath := filepath.Join(dir, "new_lock_file.lock")
		lk, err := store.lock(filePath)
		assert.NoError(err)
		assert.NotNil(lk)
		assert.NotNil(lk.f)
		defer lk.unlock()

		// Verify file exists
		_, err = os.Stat(filePath)
		assert.NoError(err)
	})

	// Test case 2: Acquire exclusive lock on an existing file
	t.Run("Lock existing file exclusive", func(t *testing.T) {
		filePath := filepath.Join(dir, "existing_lock_file.lock")
		assert.NoError(os.WriteFile(filePath, []byte("dummy"), 0600))

		lk, err := store.lock(filePath)
		assert.NoError(err)
		assert.NotNil(lk)
		defer lk.unlock()
	})

	// Test case 3: Attempt to acquire exclusive lock when already held (should block)
	t.Run("Lock blocking exclusive", func(t *testing.T) {
		filePath := filepath.Join(dir, "blocking_lock.lock")

		lk1, err := store.lock(filePath)
		assert.NoError(err)
		assert.NotNil(lk1)
		defer lk1.unlock()

		// Try to acquire a second lock in a goroutine, it should block
		done := make(chan bool)
		go func() {
			lk2, err := store.lock(filePath)
			assert.NoError(err)
			assert.NotNil(lk2)
			defer lk2.unlock()
			done <- true
		}()

		select {
		case <-done:
			assert.Fail("Second lock acquired without blocking")
		case <-time.After(100 * time.Millisecond):
			// Expected: lock acquisition should block
		}
		lk1.unlock() // Release the first lock
		select {
		case <-done:
			// Expected: second lock should now be acquired
		case <-time.After(500 * time.Millisecond):
			assert.Fail("Second lock did not acquire after first was released")
		}
	})

	// Test case 4: Acquire exclusive lock on a directory
	t.Run("Lock directory exclusive", func(t *testing.T) {
		lockDir := filepath.Join(dir, "lock_this_dir")
		assert.NoError(os.Mkdir(lockDir, 0700))
		defer os.RemoveAll(lockDir) //nolint: errcheck

		lk, err := store.lock(lockDir)
		assert.Error(err)
		assert.Nil(lk)
		assert.Contains(err.Error(), "is a directory")
	})

	// Test case 5: Error creating parent directory
	t.Run("Error creating parent directory", func(t *testing.T) {
		// Create a file where a directory should be
		badDir := filepath.Join(dir, "badparent")
		assert.NoError(os.WriteFile(badDir, []byte("file"), 0600))

		filePath := filepath.Join(badDir, "lock.lock")
		lk, err := store.lock(filePath)
		assert.Error(err)
		assert.Nil(lk)
		assert.Contains(err.Error(), "not a directory")
	})
}

func TestStore_rLock(t *testing.T) {
	assert := assert.New(t)

	// Setup: Create a temporary directory and a dummy store object
	dir := filepath.Join(testStoreDir, "rLock_test")
	assert.NoError(os.MkdirAll(dir, 0700))
	defer os.RemoveAll(dir) //nolint: errcheck

	store := &Store{
		dir:      dir,
		dirPerm:  0700,
		filePerm: 0600,
	}

	// Create a file to be locked
	filePath := filepath.Join(dir, "shared_lock_file.lock")
	assert.NoError(os.WriteFile(filePath, []byte("dummy"), 0600))

	// Test case 1: Acquire a shared lock successfully
	t.Run("Acquire shared lock", func(t *testing.T) {
		lk, err := store.rLock(filePath)
		assert.NoError(err)
		assert.NotNil(lk)
		defer lk.unlock()
	})

	// Test case 2: Acquire multiple shared locks simultaneously
	t.Run("Acquire multiple shared locks", func(t *testing.T) {
		lk1, err := store.rLock(filePath)
		assert.NoError(err)
		assert.NotNil(lk1)
		defer lk1.unlock()

		lk2, err := store.rLock(filePath)
		assert.NoError(err)
		assert.NotNil(lk2)
		defer lk2.unlock()

		// Both locks should be held without blocking
	})

	// Test case 3: Attempt to acquire shared lock when an exclusive lock is held (should block)
	t.Run("RLock blocking exclusive", func(t *testing.T) {
		blockingFilePath := filepath.Join(dir, "exclusive_blocking.lock")
		assert.NoError(os.WriteFile(blockingFilePath, []byte("dummy"), 0600))

		lkExclusive, err := store.lock(blockingFilePath) // Acquire exclusive lock
		assert.NoError(err)
		assert.NotNil(lkExclusive)
		defer lkExclusive.unlock()

		done := make(chan bool)
		go func() {
			lkShared, err := store.rLock(blockingFilePath)
			assert.NoError(err)
			assert.NotNil(lkShared)
			defer lkShared.unlock()
			done <- true
		}()

		select {
		case <-done:
			assert.Fail("Shared lock acquired without blocking on exclusive lock")
		case <-time.After(100 * time.Millisecond):
			// Expected: shared lock acquisition should block
		}
		lkExclusive.unlock() // Release exclusive lock
		select {
		case <-done:
			// Expected: shared lock should now be acquired
		case <-time.After(500 * time.Millisecond):
			assert.Fail("Shared lock did not acquire after exclusive was released")
		}
	})

	// Test case 4: Attempt to acquire shared lock on a non-existent file
	t.Run("RLock non-existent file", func(t *testing.T) {
		nonExistentPath := filepath.Join(dir, "nonexistent.lock")
		lk, err := store.rLock(nonExistentPath)
		assert.Error(err)
		assert.Nil(lk)
		assert.True(os.IsNotExist(err))
		assert.Contains(err.Error(), "no such file or directory")
	})
}

func TestFileLock_unlock(t *testing.T) {
	assert := assert.New(t)

	// Setup: Create a temporary directory and a dummy store object
	dir := filepath.Join(testStoreDir, "unlock_test")
	defer os.RemoveAll(dir) //nolint: errcheck

	store := &Store{
		dir:      dir,
		dirPerm:  0700,
		filePerm: 0600,
	}

	// Test case 1: Unlock an exclusive lock
	t.Run("Unlock exclusive lock", func(t *testing.T) {
		filePath := filepath.Join(dir, "exclusive.lock")
		lk, err := store.lock(filePath)
		assert.NoError(err)
		assert.NotNil(lk)

		lk.unlock()

		// After unlocking, another exclusive lock should be acquirable
		lk2, err := store.lock(filePath)
		assert.NoError(err)
		assert.NotNil(lk2)
		defer lk2.unlock()
	})

	// Test case 2: Unlock a shared lock
	t.Run("Unlock shared lock", func(t *testing.T) {
		filePath := filepath.Join(dir, "shared.lock")
		assert.NoError(os.WriteFile(filePath, []byte("dummy"), 0600))

		lk, err := store.rLock(filePath)
		assert.NoError(err)
		assert.NotNil(lk)

		lk.unlock()

		// After unlocking, another shared lock should be acquirable
		lk2, err := store.rLock(filePath)
		assert.NoError(err)
		assert.NotNil(lk2)
		defer lk2.unlock()
	})

	// Test case 3: Unlock a nil fileLock
	t.Run("Unlock nil fileLock", func(t *testing.T) {
		var lk *fileLock
		// Should not panic or cause an error
		assert.NotPanics(func() { lk.unlock() })
	})

	// Test case 4: Unlock a fileLock with nil file descriptor
	t.Run("Unlock fileLock with nil file descriptor", func(t *testing.T) {
		lk := &fileLock{f: nil}
		// Should not panic or cause an error
		assert.NotPanics(func() { lk.unlock() })
	})
}

func BenchmarkLockExisting(b *testing.B) {
	// Setup: Create a new store
	dir := filepath.Join(testStoreDir, "lock_bench")
	_ = os.RemoveAll(dir)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		fmt.Printf("Failed to create test directory %s: %v", dir, err)
		return
	}
	defer os.RemoveAll(dir) //nolint: errcheck

	s := &Store{
		dir:      dir,
		dirPerm:  0700,
		filePerm: 0600,
	}

	path := filepath.Join(dir, "testfile")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, s.filePerm)
	if err != nil {
		return
	}
	_ = f.Close()

	b.ResetTimer()
	for b.Loop() {
		lk, err := s.lock(path)
		if err != nil {
			fmt.Printf("Failed to lock %s: %v", path, err)
			return
		}
		lk.unlock()
	}
}

func BenchmarkLockNBExisting(b *testing.B) {
	// Setup: Create a new store
	dir := filepath.Join(testStoreDir, "lock_bench")
	_ = os.RemoveAll(dir)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		fmt.Printf("Failed to create test directory %s: %v", dir, err)
		return
	}
	defer os.RemoveAll(dir) //nolint: errcheck

	s := &Store{
		dir:      dir,
		dirPerm:  0700,
		filePerm: 0600,
	}

	path := filepath.Join(dir, "testfile")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, s.filePerm)
	if err != nil {
		return
	}
	_ = f.Close()

	b.ResetTimer()
	for b.Loop() {
		lk, err := s.lockNB(path)
		if err != nil {
			fmt.Printf("Failed to lock %s: %v", path, err)
			return
		}
		lk.unlock()
	}
}

func BenchmarkLockNew(b *testing.B) {
	dir := filepath.Join(testStoreDir, "lock_bench")
	_ = os.RemoveAll(dir)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		fmt.Printf("Failed to create test directory %s: %v", dir, err)
		return
	}
	defer os.RemoveAll(dir) //nolint: errcheck

	s := &Store{
		dir:      dir,
		dirPerm:  0700,
		filePerm: 0600,
	}

	i := 0

	b.ResetTimer()
	for b.Loop() {
		i++
		path := filepath.Join(dir, fmt.Sprintf("file%d", i))
		lk, err := s.lock(path)
		if err != nil {
			fmt.Printf("Failed to lock %s: %v", path, err)
			return
		}
		lk.unlock()
	}
}

func BenchmarkLockNBNew(b *testing.B) {
	dir := filepath.Join(testStoreDir, "lock_bench")
	_ = os.RemoveAll(dir)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		fmt.Printf("Failed to create test directory %s: %v", dir, err)
		return
	}
	defer os.RemoveAll(dir) //nolint: errcheck

	s := &Store{
		dir:      dir,
		dirPerm:  0700,
		filePerm: 0600,
	}

	i := 0

	b.ResetTimer()
	for b.Loop() {
		i++
		path := filepath.Join(dir, fmt.Sprintf("file%d", i))
		lk, err := s.lockNB(path)
		if err != nil {
			fmt.Printf("Failed to lock %s: %v", path, err)
			return
		}
		lk.unlock()
	}
}
