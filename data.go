package darkstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Save stores sensitive data at the given path
func (s *Store) Save(path string, data []byte) error {
	if s == nil {
		return fmt.Errorf("no store")
	}
	// Validate path
	if path == "" {
		return fmt.Errorf("path must not be empty")
	}
	fullPath := filepath.Join(s.dir, path)
	if !strings.HasPrefix(fullPath, s.dir+"/") {
		return fmt.Errorf("path outside store hierarchy: %s", path)
	}

	// Create directory structure if needed
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, s.dirPerm); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	stat, err := os.Stat(fullPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error checking %s: %w", path, err)
	} else if err == nil && stat.IsDir() {
		return fmt.Errorf("secret %s is a directory", path)
	}

	// Encrypt data
	encryptedData, err := s.encryptData(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	return s.writeFile(fullPath, encryptedData)
}

// Load retrieves sensitive data from the given path
func (s *Store) Load(path string) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("no store")
	}
	// Validate path
	if path == "" {
		return nil, fmt.Errorf("path must not be empty")
	}
	fullPath := filepath.Join(s.dir, path)
	if !strings.HasPrefix(fullPath, s.dir+"/") {
		return nil, fmt.Errorf("path outside store hierarchy: %s", path)
	}

	// Read encrypted data
	encryptedData, err := s.readFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("secret not found: %s", path)
		}
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Decrypt data
	data, err := s.decryptData(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return data, nil
}

// Delete removes sensitive data from the given path
func (s *Store) Delete(path string) error {
	if s == nil {
		return fmt.Errorf("no store")
	}
	// Clean and validate path
	fullPath := filepath.Clean(filepath.Join(s.dir, path))
	if !strings.HasPrefix(fullPath, s.dir) {
		return fmt.Errorf("path outside store hierarchy: %s", path)
	}

	if _, err := os.Stat(fullPath); err != nil {
		if os.IsNotExist(err) {
			return nil // The file wasn't there to begin with.
		}
		return err
	}

	// Exclusive lock before delete
	lk, err := s.lock(fullPath)
	if err != nil {
		return err
	}
	defer lk.unlock()

	return os.Remove(fullPath)
}

// encryptData encrypts data using the current key
func (s *Store) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.currentKey)
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
	result[0] = s.currentKeyIndex
	copy(result[1:], nonce)
	copy(result[1+len(nonce):], encryptedData)

	return result, nil
}

// decryptData decrypts data using the appropriate key
func (s *Store) decryptData(encryptedData []byte) ([]byte, error) {
	if len(encryptedData) < 1 {
		return nil, fmt.Errorf("invalid encrypted data format")
	}

	keyIndex := encryptedData[0]

	// Get the key for this data
	var key []byte
	if keyIndex == s.currentKeyIndex {
		key = s.currentKey
	} else {
		// Load the specific key
		var err error
		key, err = s.loadKey(keyIndex)
		if err != nil {
			return nil, fmt.Errorf("failed to load key %d: %w", keyIndex, err)
		}
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
	if data == nil { // Return an empty byte slice instead of nil.
		data = make([]byte, 0)
	}

	return data, nil
}

// getKeyIndex returns the key index used to encrypt a file.
func (s *Store) getKeyIndex(file string) (uint8, error) {
	// Read encrypted data
	encryptedData, err := s.readFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, fmt.Errorf("secret not found: %s", file)
		}
		return 0, fmt.Errorf("failed to read file %s: %w", file, err)
	}
	if len(encryptedData) < 1 {
		return 0, fmt.Errorf("corrupt file %s: %w", file, err)
	}
	return encryptedData[0], nil
}
