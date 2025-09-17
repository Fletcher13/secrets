package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// fileLock wraps an os.File used for advisory flock-based locking.
type fileLock struct {
	f *os.File
}

// lockExclusive acquires an exclusive lock on the given file path.
// This call is blocking, so if the lock is held, the function will wait
// until it has been released.  The containing directory is created if
// needed. The returned lock must be released by calling unlock().
func lockExclusive(path string) (*fileLock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("failed to create lock directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to acquire exclusive lock: %w", err)
	}
	return &fileLock{f: f}, nil
}

// lockShared acquires a shared lock on the given file path. The file
// must exist.  This call is blocking, so if the lock is held, the
// function will wait until it has been released.  The returned lock
// must be released by calling unlock().
func lockShared(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open file for shared lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to acquire shared lock: %w", err)
	}
	return &fileLock{f: f}, nil
}

// LockExclusiveNB acquires an exclusive lock on the given file path.
// This call is non-blocking, so if the lock is held, an error will be
// returned.  The containing directory is created if needed. The
// returned lock must be released by calling unlock().
func LockExclusiveNB(path string) (*fileLock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("failed to create lock directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to acquire exclusive lock: %w", err)
	}
	return &fileLock{f: f}, nil
}

// LockShared acquires a shared lock on the given file path. The file
// must exist.  This call is non-blocking, so if the lock is held, an
// error will be returned.  The returned lock must be released by
// calling unlock().
func LockSharedNB(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open file for shared lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to acquire shared lock: %w", err)
	}
	return &fileLock{f: f}, nil
}

// unlock releases the lock and closes the file descriptor.
func (l *fileLock) unlock() {
	if l == nil || l.f == nil {
		return
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
}
