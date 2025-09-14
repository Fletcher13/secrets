package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// Save stores sensitive data at the given path
func (s *Store) Save(path string, data []byte) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Clean and validate path
	cleanPath := filepath.Clean(path)
	if strings.HasPrefix(cleanPath, "..") || strings.Contains(cleanPath, "/..") {
		return fmt.Errorf("path outside store hierarchy: %s", path)
	}

	// Ensure path is relative
	if filepath.IsAbs(cleanPath) {
		return fmt.Errorf("absolute paths not allowed: %s", path)
	}

	// Create directory structure if needed
	fullPath := filepath.Join(s.dir, cleanPath)
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Encrypt data
	encryptedData, err := s.encryptData(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Save to file
	return os.WriteFile(fullPath, encryptedData, 0600)
}

// Load retrieves sensitive data from the given path
func (s *Store) Load(path string) ([]byte, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Clean and validate path
	cleanPath := filepath.Clean(path)
	if strings.HasPrefix(cleanPath, "..") || strings.Contains(cleanPath, "/..") {
		return nil, fmt.Errorf("path outside store hierarchy: %s", path)
	}

	// Ensure path is relative
	if filepath.IsAbs(cleanPath) {
		return nil, fmt.Errorf("absolute paths not allowed: %s", path)
	}

	// Read encrypted data
	fullPath := filepath.Join(s.dir, cleanPath)
	encryptedData, err := os.ReadFile(fullPath)
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
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Clean and validate path
	cleanPath := filepath.Clean(path)
	if strings.HasPrefix(cleanPath, "..") || strings.Contains(cleanPath, "/..") {
		return fmt.Errorf("path outside store hierarchy: %s", path)
	}

	// Ensure path is relative
	if filepath.IsAbs(cleanPath) {
		return fmt.Errorf("absolute paths not allowed: %s", path)
	}

	fullPath := filepath.Join(s.dir, cleanPath)
	return os.Remove(fullPath)
}

// List returns all secret paths in the store
func (s *Store) List() ([]string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var secrets []string
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

		secrets = append(secrets, relPath)
		return nil
	})

	return secrets, err
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

	return data, nil
}

// Close closes the store and cleans up resources
func (s *Store) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Signal recovery process to stop
	close(s.stopRecovery)

	// Clear sensitive data from memory
	Wipe(s.masterKey)
	Wipe(s.currentKey)

	return nil
}

// DeriveKeyFromPassword derives a key from a password using scrypt
func DeriveKeyFromPassword(password []byte, salt []byte) ([]byte, error) {
	if len(salt) < 16 {
		return nil, fmt.Errorf("salt must be at least 16 bytes")
	}

	key, err := scrypt.Key(password, salt, ScryptN, ScryptR, ScryptP, ScryptKeyLen)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return key, nil
}

// GenerateSalt generates a random salt for key derivation
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	return salt, err
}
