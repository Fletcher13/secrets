package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const (
	// Algorithm constants
	AlgorithmAES256GCM = 0

	// Key derivation constants
	ScryptN      = 32768
	ScryptR      = 8
	ScryptP      = 1
	ScryptKeyLen = 32

	// File names
	CurrentKeyFile = ".secretskeys/currentkey"
	KeysDir        = ".secretskeys"
)

// Store represents a secure storage for sensitive data
type Store struct {
	dir             string
	primaryKey      []byte
	currentKey      []byte
	currentKeyIndex uint8
	mutex           sync.RWMutex
	recoveryCh      chan struct{}
	stopRecovery    chan struct{}
}

// KeyData represents the structure of a key file
type KeyData struct {
	Algorithm    uint8
	EncryptedKey []byte
}

// DataFile represents the structure of a data file
type DataFile struct {
	KeyIndex      uint8
	EncryptedData []byte
	Nonce         []byte
}

// NewStore creates a new Store or opens an existing one
func NewStore(dirpath string, key []byte) (*Store, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("key must be at least 32 bytes long")
	}

	store := &Store{
		dir:          dirpath,
		primaryKey:   make([]byte, len(key)),
		recoveryCh:   make(chan struct{}, 1),
		stopRecovery: make(chan struct{}),
	}
	copy(store.primaryKey, key)

	// Ensure directory exists
	if err := os.MkdirAll(dirpath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	keysDir := filepath.Join(dirpath, KeysDir)
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %w", err)
	}

	// Check if this is an existing store or needs initialization
	currentKeyPath := filepath.Join(dirpath, CurrentKeyFile)
	if _, err := os.Stat(currentKeyPath); os.IsNotExist(err) {
		// Initialize new store
		if err := store.initializeStore(); err != nil {
			return nil, fmt.Errorf("failed to initialize store: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("failed to check current key file: %w", err)
	} else {
		// Open existing store
		if err := store.loadCurrentKey(); err != nil {
			return nil, fmt.Errorf("failed to load current key: %w", err)
		}
	}

	// Start recovery process if needed
	go store.recoveryProcess()

	return store, nil
}

// Close closes the store and cleans up resources
func (s *Store) Close() error {
	// Signal recovery process to stop (idempotent)
	defer func() { recover() }()
	close(s.stopRecovery)

	// Clear sensitive data from memory
	Wipe(s.primaryKey)
	Wipe(s.currentKey)

	return nil
}

// initializeStore sets up a new store with key0
func (s *Store) initializeStore() error {
	// Generate initial key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Encrypt and save key0
	if err := s.saveKey(0, key); err != nil {
		return fmt.Errorf("failed to save key0: %w", err)
	}

	// Set current key
	s.currentKey = key
	s.currentKeyIndex = 0

	// Save current key index
	return s.saveCurrentKeyIndex()
}

// loadCurrentKey loads the current encryption key
func (s *Store) loadCurrentKey() error {
	// Read current key index
	currentKeyPath := filepath.Join(s.dir, CurrentKeyFile)
	data, err := os.ReadFile(currentKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read current key file: %w", err)
	}

	if len(data) != 1 {
		return fmt.Errorf("invalid current key file format")
	}

	s.currentKeyIndex = data[0]

	// Load the key
	key, err := s.loadKey(s.currentKeyIndex)
	if err != nil {
		return fmt.Errorf("failed to load key %d: %w", s.currentKeyIndex, err)
	}

	s.currentKey = key
	return nil
}

// saveCurrentKeyIndex saves the current key index
func (s *Store) saveCurrentKeyIndex() error {
	currentKeyPath := filepath.Join(s.dir, CurrentKeyFile)
	// Exclusive lock during write of current key index
	lk, err := lockExclusive(currentKeyPath)
	if err != nil {
		return err
	}
	defer lk.unlock()

	return os.WriteFile(currentKeyPath, []byte{s.currentKeyIndex}, 0600)
}

// saveKey encrypts and saves a key
func (s *Store) saveKey(index uint8, key []byte) error {
	keyPath := filepath.Join(s.dir, KeysDir, fmt.Sprintf("key%d", index))

	// Encrypt the key with primary key using AES-GCM
	block, err := aes.NewCipher(s.primaryKey[:32])
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create key data structure
	keyData := &KeyData{
		Algorithm:    AlgorithmAES256GCM,
		EncryptedKey: gcm.Seal(nil, nonce, key, nil),
	}

	// Serialize key data
	data := make([]byte, 1+len(keyData.EncryptedKey)+len(nonce))
	data[0] = keyData.Algorithm
	copy(data[1:], nonce)
	copy(data[1+len(nonce):], keyData.EncryptedKey)

	// Exclusive lock while writing key file
	lk, err := lockExclusive(keyPath)
	if err != nil {
		return err
	}
	defer lk.unlock()

	return os.WriteFile(keyPath, data, 0600)
}

// loadKey loads and decrypts a key
func (s *Store) loadKey(index uint8) ([]byte, error) {
	keyPath := filepath.Join(s.dir, KeysDir, fmt.Sprintf("key%d", index))
	// Shared lock during read
	lk, err := lockShared(keyPath)
	if err != nil {
		return nil, err
	}
	defer lk.unlock()

	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	if len(data) < 1 {
		return nil, fmt.Errorf("invalid key file format")
	}

	algorithm := data[0]
	if algorithm != AlgorithmAES256GCM {
		return nil, fmt.Errorf("unsupported algorithm: %d", algorithm)
	}

	block, err := aes.NewCipher(s.primaryKey[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < 1+nonceSize {
		return nil, fmt.Errorf("invalid key file format")
	}

	nonce := data[1 : 1+nonceSize]
	encryptedKey := data[1+nonceSize:]

	key, err := gcm.Open(nil, nonce, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	return key, nil
}
