package secrets

import (
	"os"
)

// readFile acquires a shared lock on the file to be read, reads the file,
// releases the lock, then returns the data in the file as a byte slice.
// This minimizes the amount of time spent with the lock held.
func (s *Store) readFile(path string) ([]byte, error) {
	lk, err := s.rLock(path)
	if err != nil {
		return nil, err
	}
	defer lk.unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// writeFile creates a file if it does not exist, acquires an exclusive
// lock on the file to be written, writes the data to the file, then
// releases the lock.  This minimizes the amount of time spent with the
// lock held.
func (s *Store) writeFile(path string, data []byte) error {
	lk, err := s.lock(path)
	if err != nil {
		return err
	}
	defer lk.unlock()

	return os.WriteFile(path, data, s.filePerm)
}
