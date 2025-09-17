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

const (
	// Key derivation constants
	ScryptN      = 32768
	ScryptR      = 8
	ScryptP      = 1
	ScryptKeyLen = 32
)

// Save stores sensitive data at the given path
func (s *Store) Save(path string, data []byte) error {
	// Clean and validate path
	fullPath := filepath.Clean(filepath.Join(s.dir, path))
	if !strings.HasPrefix(fullPath, s.dir) {
		return fmt.Errorf("path outside store hierarchy: %s", path)
	}

	// Create directory structure if needed
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Encrypt data
	encryptedData, err := s.encryptData(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	return writeFile(fullPath, encryptedData, 0600)
}

// Load retrieves sensitive data from the given path
func (s *Store) Load(path string) ([]byte, error) {
	// Clean and validate path
	fullPath := filepath.Clean(filepath.Join(s.dir, path))
	if !strings.HasPrefix(fullPath, s.dir) {
		return nil, fmt.Errorf("path outside store hierarchy: %s", path)
	}

	// Read encrypted data
	encryptedData, err := readFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("secret not found: %s", path)
		}
		return nil, fmt.Errorf("failed to read file: %s", err.Error())
	}

	// Decrypt data
	data, err := s.decryptData(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %s", err.Error())
	}

	return data, nil
}

// Delete removes sensitive data from the given path
func (s *Store) Delete(path string) error {
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

	// Require that the file exists; do not create it when locking
	if _, err := os.Stat(fullPath); err != nil {
		return err
	}

	// Exclusive lock before delete
	lk, err := lockExclusive(fullPath)
	if err != nil {
		return err
	}
	defer lk.unlock()

	return os.Remove(fullPath)
}

// list returns all secret paths in the store
func (s *Store) list() ([]string, error) {
	var alldata []string
	err := filepath.Walk(s.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip the keys directory but recurse into other directories
		if info.IsDir() {
			if strings.HasPrefix(path, filepath.Join(s.dir, KeysDir)) {
				return filepath.SkipDir
			}
			return nil
		}

		// Get relative path
		relPath, err := filepath.Rel(s.dir, path)
		if err != nil {
			return err
		}

		alldata = append(alldata, relPath)
		return nil
	})

	return alldata, err
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
