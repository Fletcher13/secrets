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

	// File names
	KeysDir        = ".secretskeys"
	CurrentKeyFile = KeysDir + "currentkey"
)

// Store represents a secure storage for sensitive data
type Store struct {
	dir             string
	primaryKey      []byte
	currentKey      []byte
	currentKeyIndex uint8
	dirPerm         uint
	filePerm        uint
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

// TODO: Ensure keys cannot be written to swap or core files.

// CreateStore creates a new Store
func CreateStore(dirpath string, pass []byte) (*Store, error) {
	// TODO: if len(key) == 0 { Use TPM2.0 sealed key }
	if len(pass) < 32 {
		// TODO: Use PBKDF2 to generate the key from any password.
		return nil, fmt.Errorf("key must be at least 32 bytes long")
	}

	// Return error if directory exists and is not empty.
	stat, err := os.Stat(dirpath)
	if err == nil {
		if stat.IsDir() != true {
			return nil, fmt.Errorf("%s exists but is not a directory",
				dirpath)
		}
		dirFiles, err := os.ReadDir(dirpath)
		if err != nil || dirFiles != 2 {
			return nil, fmt.Errorf("%s is not empty", dirpath)
		}
	} else if err.Is() != ErrDoesNotExist {
		return nil, fmt.Errorf("error accessing%s: %w", err)
	}

	// Create keys directory, which will auto-create store dir if it
	// does not already exist.
	keysDir := filepath.Join(dirpath, KeysDir)
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %v", err)
	}

	// Initialize new store
	store := &Store{
		dir:          dirpath,
		primaryKey:   make([]byte, len(key)),
	}
	copy(store.primaryKey, key)

	// Generate initial key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Encrypt and save key0
	if err := store.saveKey(0, key); err != nil {
		return fmt.Errorf("failed to save key0: %w", err)
	}

	// Set current key
	s.currentKey = key
	s.currentKeyIndex = 0

	// Save current key index
	if err := s.saveCurrentKeyIndex(); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %v", err)
	}

	// Open existing store
	return OpenStore(dirpath, key)
}

// OpenStore opens an existing Store
func OpenStore(dirpath string, key []byte) (*Store, error) {
	// TODO: if len(key) == 0 { Use TPM2.0 sealed key }
	if len(key) < 32 {
		// TODO: Use PBKDF2 to generate the key from any password.
		return nil, fmt.Errorf("key must be at least 32 bytes long")
	}

	store := &Store{
		dir:          dirpath,
		primaryKey:   make([]byte, len(key)),
		recoveryCh:   make(chan struct{}, 1),
		stopRecovery: make(chan struct{}),
	}
	copy(store.primaryKey, key)

	keysDir := filepath.Join(dirpath, KeysDir)
	currentKeyPath := filepath.Join(dirpath, CurrentKeyFile)
	if _, err := os.Stat(currentKeyPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("directory %s is not a secrets store", dirpath)
	} else if err != nil {
		return nil, fmt.Errorf("failed to read current key file: %v", err)
	}

	if err := store.loadCurrentKey(); err != nil {
		return nil, fmt.Errorf("failed to load current key: %v", err)
	}

	// Start recovery process if needed
	go store.recoveryProcess()

	return store, nil
}

// Close closes the store and cleans up resources
func (s *Store) Close() error {
	// closing an already closed channel can cause a panic.  Ignore the panic.
	defer func() { _ = recover() }()

	// Signal recovery process to stop (idempotent)
	close(s.stopRecovery)

	// Clear sensitive data from memory
	Wipe(s.primaryKey)
	Wipe(s.currentKey)

	return nil
}

// loadCurrentKey loads the current encryption key
func (s *Store) loadCurrentKey() error {
	// Read current key index
	currentKeyPath := filepath.Join(s.dir, CurrentKeyFile)

	data, err := readFile(currentKeyPath)
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

	return writeFile(currentKeyPath, []byte{s.currentKeyIndex}, 0600)
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

	return writeFile(keyPath, data, 0600)
}

// loadKey loads and decrypts a key
func (s *Store) loadKey(index uint8) ([]byte, error) {
	keyPath := filepath.Join(s.dir, KeysDir, fmt.Sprintf("key%d", index))

	data, err := readFile(keyPath)
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
