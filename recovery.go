package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// recoveryProcess handles crash recovery by re-encrypting data with the current key
func (s *Store) recoveryProcess() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopRecovery:
			return
		case <-ticker.C:
			if err := s.checkAndRecover(); err != nil {
				// Log error but continue running
				continue
			}
		}
	}
}

// checkAndRecover checks for inconsistent key usage and recovers if needed
func (s *Store) checkAndRecover() error {
	// Check if current key file exists and is valid
	currentKeyPath := filepath.Join(s.dir, CurrentKeyFile)
	if _, err := os.Stat(currentKeyPath); os.IsNotExist(err) {
		return fmt.Errorf("current key file missing")
	}

	// Get list of key files
	keysDir := filepath.Join(s.dir, KeysDir)
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return fmt.Errorf("failed to read keys directory: %w", err)
	}

	var keyIndices []uint8
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "key") {
			continue
		}

		var keyIndex uint8
		if _, err := fmt.Sscanf(entry.Name(), "key%d", &keyIndex); err != nil {
			continue
		}
		keyIndices = append(keyIndices, keyIndex)
	}

	s.mutex.RLock()
	currentKeyIndex := s.currentKeyIndex
	currentKey := s.currentKey
	s.mutex.RUnlock()

	// Check if we have multiple keys (indicating potential incomplete rotation)
	if len(keyIndices) > 1 {
		return s.recoverFromIncompleteRotation(currentKeyIndex, currentKey)
	}

	return nil
}

// recoverFromIncompleteRotation re-encrypts data that doesn't use the current key
func (s *Store) recoverFromIncompleteRotation(currentKeyIndex uint8, currentKey []byte) error {
	// Get list of all data files
	files, err := s.listDataFiles()
	if err != nil {
		return fmt.Errorf("failed to list data files: %w", err)
	}

	var needsRecovery []string

	// Check which files need recovery
	for _, file := range files {
		fullPath := filepath.Join(s.dir, file)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}

		if len(data) > 0 && data[0] != currentKeyIndex {
			needsRecovery = append(needsRecovery, file)
		}
	}

	if len(needsRecovery) == 0 {
		return nil // Nothing to recover
	}

	// Re-encrypt files that need recovery
	for _, file := range needsRecovery {
		if err := s.recoverFile(file, currentKeyIndex, currentKey); err != nil {
			// Log error but continue with other files
			continue
		}
	}

	return nil
}

// recoverFile re-encrypts a single file with the current key
func (s *Store) recoverFile(relPath string, currentKeyIndex uint8, currentKey []byte) error {
	fullPath := filepath.Join(s.dir, relPath)

	// Read encrypted data
	encryptedData, err := os.ReadFile(fullPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if len(encryptedData) < 1 {
		return fmt.Errorf("invalid file format")
	}

	oldKeyIndex := encryptedData[0]
	if oldKeyIndex == currentKeyIndex {
		return nil // Already using current key
	}

	// Load the old key
	oldKey, err := s.loadKey(oldKeyIndex)
	if err != nil {
		return fmt.Errorf("failed to load old key %d: %w", oldKeyIndex, err)
	}

	// Decrypt with old key
	data, err := s.decryptDataWithKey(encryptedData, oldKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt with old key: %w", err)
	}

	// Encrypt with current key
	newEncryptedData, err := s.encryptDataWithKey(data, currentKey, currentKeyIndex)
	if err != nil {
		return fmt.Errorf("failed to encrypt with current key: %w", err)
	}

	// Write back to file
	return os.WriteFile(fullPath, newEncryptedData, 0600)
}

// ValidateStore checks the integrity of the store
func (s *Store) ValidateStore() error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Check current key file
	currentKeyPath := filepath.Join(s.dir, CurrentKeyFile)
	data, err := os.ReadFile(currentKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read current key file: %w", err)
	}

	if len(data) != 1 {
		return fmt.Errorf("invalid current key file format")
	}

	currentKeyIndex := data[0]

	// Verify current key exists
	keyPath := filepath.Join(s.dir, KeysDir, fmt.Sprintf("key%d", currentKeyIndex))
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return fmt.Errorf("current key file key%d not found", currentKeyIndex)
	}

	// Try to load the current key
	_, err = s.loadKey(currentKeyIndex)
	if err != nil {
		return fmt.Errorf("failed to load current key: %w", err)
	}

	return nil
}

// GetStoreInfo returns information about the store
func (s *Store) GetStoreInfo() (*StoreInfo, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	info := &StoreInfo{
		Directory:       s.dir,
		CurrentKeyIndex: s.currentKeyIndex,
	}

	// Count total secrets
	secrets, err := s.list()
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}
	info.SecretCount = len(secrets)

	// Count key files
	keysDir := filepath.Join(s.dir, KeysDir)
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read keys directory: %w", err)
	}

	var keyIndices []uint8
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "key") {
			continue
		}

		var keyIndex uint8
		if _, err := fmt.Sscanf(entry.Name(), "key%d", &keyIndex); err != nil {
			continue
		}
		keyIndices = append(keyIndices, keyIndex)
	}

	info.KeyCount = len(keyIndices)
	info.KeyIndices = keyIndices

	return info, nil
}

// StoreInfo contains information about a store
type StoreInfo struct {
	Directory       string
	CurrentKeyIndex uint8
	SecretCount     int
	KeyCount        int
	KeyIndices      []uint8
}
