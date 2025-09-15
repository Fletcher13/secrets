package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Rotate generates a new encryption key and re-encrypts all data
func (s *Store) Rotate() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Stop any ongoing recovery processes
	select {
	case s.stopRecovery <- struct{}{}:
	default:
	}

	// Calculate new key index (roll over to 0 if at 255)
	newKeyIndex := s.currentKeyIndex + 1
	if newKeyIndex == 0 { // Overflow case
		newKeyIndex = 1 // Skip 0 to avoid confusion
	}

	// Generate new key
	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		return fmt.Errorf("failed to generate new key: %w", err)
	}

	// Save the new key
	if err := s.saveKey(newKeyIndex, newKey); err != nil {
		return fmt.Errorf("failed to save new key: %w", err)
	}

	// Get list of all files to re-encrypt
	files, err := s.listDataFiles()
	if err != nil {
		// Clean up the new key if we can't proceed
		s.deleteKey(newKeyIndex)
		return fmt.Errorf("failed to list data files: %w", err)
	}

	// Re-encrypt all data files with the new key
	oldKey := s.currentKey
	s.currentKey = newKey
	s.currentKeyIndex = newKeyIndex

	var reencryptErrors []error
	var wg sync.WaitGroup
	errorCh := make(chan error, len(files))

	// Process files concurrently but with limited concurrency
	semaphore := make(chan struct{}, 10) // Limit to 10 concurrent operations

	for _, file := range files {
		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			if err := s.reencryptFile(filePath, oldKey, newKey); err != nil {
				errorCh <- fmt.Errorf("failed to re-encrypt %s: %w", filePath, err)
			}
		}(file)
	}

	wg.Wait()
	close(errorCh)

	// Collect any errors
	for err := range errorCh {
		reencryptErrors = append(reencryptErrors, err)
	}

	// Update current key index
	if err := s.saveCurrentKeyIndex(); err != nil {
		return fmt.Errorf("failed to save current key index: %w", err)
	}

	// If there were errors during re-encryption, we still have the new key
	// but some files might not be encrypted with it
	if len(reencryptErrors) > 0 {
		// Log errors but don't fail the rotation
		// The new key is in place and new data will use it
		return fmt.Errorf("rotation completed with errors: %v", reencryptErrors)
	}

	// Delete old keys (keep the current one and any that might still be in use)
	s.cleanupOldKeys()

	// Clear the old key from memory
	Wipe(oldKey)

	return nil
}

// listDataFiles returns all data files (excluding key files)
func (s *Store) listDataFiles() ([]string, error) {
	var files []string

	err := filepath.Walk(s.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and the keys directory
		if info.IsDir() {
			if path == s.dir || strings.HasPrefix(path, filepath.Join(s.dir, KeysDir)) {
				return nil
			}
			return filepath.SkipDir
		}

		// Get relative path
		relPath, err := filepath.Rel(s.dir, path)
		if err != nil {
			return err
		}

		files = append(files, relPath)
		return nil
	})

	return files, err
}

// reencryptFile re-encrypts a single file with the new key
func (s *Store) reencryptFile(relPath string, oldKey, newKey []byte) error {
	fullPath := filepath.Join(s.dir, relPath)

	// Read and decrypt with old key
	encryptedData, err := os.ReadFile(fullPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if len(encryptedData) < 1 {
		return fmt.Errorf("invalid file format")
	}

	oldKeyIndex := encryptedData[0]

	// Decrypt with appropriate key
	var keyToUse []byte
	if oldKeyIndex == s.currentKeyIndex {
		keyToUse = newKey // This shouldn't happen during rotation
	} else {
		keyToUse, err = s.loadKey(oldKeyIndex)
		if err != nil {
			return fmt.Errorf("failed to load key %d: %w", oldKeyIndex, err)
		}
	}

	data, err := s.decryptDataWithKey(encryptedData, keyToUse)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	// Encrypt with new key
	newEncryptedData, err := s.encryptDataWithKey(data, newKey, s.currentKeyIndex)
	if err != nil {
		return fmt.Errorf("failed to encrypt with new key: %w", err)
	}

	// Write back to file
	return os.WriteFile(fullPath, newEncryptedData, 0600)
}

// decryptDataWithKey decrypts data using a specific key
func (s *Store) decryptDataWithKey(encryptedData []byte, key []byte) ([]byte, error) {
	if len(encryptedData) < 1 {
		return nil, fmt.Errorf("invalid encrypted data format")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < 1+nonceSize {
		return nil, fmt.Errorf("invalid encrypted data format")
	}

	nonce := encryptedData[1 : 1+nonceSize]
	ciphertext := encryptedData[1+nonceSize:]

	data, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return data, nil
}

// encryptDataWithKey encrypts data using a specific key and key index
func (s *Store) encryptDataWithKey(data []byte, key []byte, keyIndex uint8) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	encryptedData := gcm.Seal(nil, nonce, data, nil)

	// Create data file structure
	result := make([]byte, 1+len(nonce)+len(encryptedData))
	result[0] = keyIndex
	copy(result[1:], nonce)
	copy(result[1+len(nonce):], encryptedData)

	return result, nil
}

// deleteKey removes a key file
func (s *Store) deleteKey(index uint8) {
	keyPath := filepath.Join(s.dir, KeysDir, fmt.Sprintf("key%d", index))
	_ = os.Remove(keyPath)
}

// cleanupOldKeys removes old key files that are no longer needed
func (s *Store) cleanupOldKeys() {
	keysDir := filepath.Join(s.dir, KeysDir)

	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return // Silently fail
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "key") {
			continue
		}

		// Extract key index from filename
		var keyIndex uint8
		if _, err = fmt.Sscanf(entry.Name(), "key%d", &keyIndex); err != nil {
			continue
		}

		// Keep current key and key 0 (for compatibility)
		if keyIndex == s.currentKeyIndex || keyIndex == 0 {
			continue
		}

		// Check if any files still use this key
		if !s.keyInUse(keyIndex) {
			s.deleteKey(keyIndex)
		}
	}
}

// keyInUse checks if any data files are still using the specified key
func (s *Store) keyInUse(keyIndex uint8) bool {
	files, err := s.listDataFiles()
	if err != nil {
		return true // Assume it's in use if we can't check
	}

	for _, file := range files {
		fullPath := filepath.Join(s.dir, file)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}

		if len(data) > 0 && data[0] == keyIndex {
			return true
		}
	}

	return false
}
