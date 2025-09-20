package secrets

import (
	//	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// fileLock wraps an os.File used for advisory flock-based locking.
type fileLock struct {
	f *os.File
}

// lock acquires an exclusive lock on the given file path.  This call is
// blocking, so if the lock is already held, the function will wait
// until it has been released.  The containing directory is created if
// needed. The returned lock must be released by calling unlock().
func (s *Store) lock(path string) (*fileLock, error) {
	var f *os.File
	stat, err := os.Stat(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(path), s.dirPerm); err != nil {
			return nil, err //fmt.Errorf("failed to create lock directory: %w", err)
		}
		f, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR, s.filePerm)
		if err != nil {
			return nil, err //fmt.Errorf("failed to open lock file: %w", err)
		}
	} else if err != nil {
		return nil, err //fmt.Errorf("failed to access lock file: %w", err)
	} else if stat.IsDir() {
		f, err = os.OpenFile(path, os.O_RDWR, s.dirPerm)
		if err != nil {
			return nil, err //fmt.Errorf("failed to open lock file: %w", err)
		}
	} else {
		f, err = os.OpenFile(path, os.O_RDWR, s.filePerm)
		if err != nil {
			return nil, err //fmt.Errorf("failed to open lock file: %w", err)
		}
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err //fmt.Errorf("failed to acquire exclusive lock: %w", err)
	}
	return &fileLock{f: f}, nil
}

// rLock acquires a shared lock on the given file path. The file must
// exist.  This call is blocking, so if the lock is already held, the
// function will wait until it has been released.  The returned lock
// must be released by calling unlock().
func (s *Store) rLock(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, s.filePerm)
	if err != nil {
		return nil, err //fmt.Errorf("failed to open file for shared lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		_ = f.Close()
		return nil, err //fmt.Errorf("failed to acquire shared lock: %w", err)
	}
	return &fileLock{f: f}, nil
}

/*
// lockNB acquires an exclusive lock on the given file path.  This call
// is non-blocking, so if the lock is already held, an error will be
// returned.  The containing directory is created if needed. The
// returned lock must be released by calling unlock().
func (s *Store) lockNB(path string) (*fileLock, error) {
	if err := os.MkdirAll(filepath.Dir(path), s.dirPerm); err != nil {
		return nil, err//fmt.Errorf("failed to create lock directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, s.filePerm)
	if err != nil {
		return nil, err//fmt.Errorf("failed to open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err//fmt.Errorf("failed to acquire exclusive lock: %w", err)
	}
	return &fileLock{f: f}, nil
}

// rLockNB acquires a shared lock on the given file path. The file
// must exist.  This call is non-blocking, so if the lock is already
// held, an error will be returned.  The returned lock must be released
// by calling unlock().
func (s *Store) rLockNB(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, s.filePerm)
	if err != nil {
		return nil, err//fmt.Errorf("failed to open file for shared lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err//fmt.Errorf("failed to acquire shared lock: %w", err)
	}
	return &fileLock{f: f}, nil
}
*/

// unlock releases the lock and closes the file descriptor.
func (l *fileLock) unlock() {
	if l == nil || l.f == nil {
		return
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
}
