package secrets

import (
	"fmt"
	"os"
)

// readFile acquires a shared lock on the file to be read, reads the file,
// releases the lock, then returns the data in the file as a byte slice.
// This minimizes the amount of time spent with the lock held.
func readFile(path string) ([]byte, error) {
	lk, err := lockShared(path)
	if err != nil {
		return nil, err
	}
	defer lk.unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", err)
	}

	return data, nil
}

// writeFile creates a file if it does not exist, acquires an exclusive
// lock on the file to be written, writes the data to the file, then
// releases the lock.  This minimizes the amount of time spent with the
// lock held.
func writeFile(path string, data []byte, perm os.FileMode) (error) {
	lk, err := lockExclusive(path)
	if err != nil {
		return err
	}
	defer lk.unlock()

	return os.WriteFile(path, data, perm)
}
