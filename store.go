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
	CurrentKeyFile = KeysDir + "/currentkey"
)

// Store represents a secure storage for sensitive data
type Store struct {
	dir             string
	primaryKey      []byte
	currentKey      []byte
	currentKeyIndex uint8
	dirPerm         os.FileMode
	filePerm        os.FileMode
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

// NewStore creates a new Store object, either opening an existing
// on-disk store at dirpath, or creating a new store at dirpath.
func NewStore(dirpath string, pass []byte) (*Store, error) {
	// TODO: if len(key) == 0 { Use TPM2.0 sealed key }
	if len(pass) != 32 {
		// TODO: Use PBKDF2 to generate the key from any password.
		return nil, fmt.Errorf("key must be exactly 32 bytes long")
	}

	storePath, err := filepath.Abs(dirpath)
	if err != nil {
		return nil, fmt.Errorf("error parsing directory %s: %w", dirpath, err)
	}

	isNewStore, err := checkNewStore(storePath)
	if err != nil {
		return nil, err
	}

	store := &Store{
		dir:          storePath,
		primaryKey:   make([]byte, 32),
		recoveryCh:   make(chan struct{}, 1),
		stopRecovery: make(chan struct{}),
	}
	// TODO: Use PBKDF2 instead of copy().
	copy(store.primaryKey, pass)

	if isNewStore {
		err = store.createNewStore()
	} else {
		err = store.loadCurrentKey()
	}
	if err != nil {
		return nil, err
	}

	stat, err := os.Stat(store.dir)
	if err != nil {
		// This should never fail.
		return nil, err
	}
	store.dirPerm = stat.Mode() & os.ModePerm
	store.filePerm = store.dirPerm & 0666 // Remove execute bit

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

// Check if this is an existing store or not.
func checkNewStore(storePath string) (bool, error) {
	keysPath := filepath.Join(storePath, KeysDir)

	stat, err := os.Stat(storePath)
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("error accessing %s: %w", storePath, err)
	}
	if os.IsNotExist(err) {
		return true, nil
	} else if !stat.IsDir() {
		return false, fmt.Errorf("%s is not a directory: %w", storePath, err)
	} else {
		// Directory exists, check if it's a valid store
		stat, err = os.Stat(keysPath)
		if os.IsNotExist(err) {
			// No keys directory, ensure dir is empty.
			dirFiles, err := os.ReadDir(storePath)
			if err != nil || len(dirFiles) != 0 {
				return false, fmt.Errorf("%s is not empty", storePath)
			}
			return true, nil
		} else if err != nil {
			return false, fmt.Errorf("error accessing %s: %w", keysPath, err)
		} else if !stat.IsDir() {
			return false, fmt.Errorf("%s is not a valid store", keysPath)
		}
		return false, nil
	}
}

func (s *Store) createNewStore() error {
	// Create keys directory, which will auto-create store dir if it
	// does not already exist.
	s.dirPerm = 0700
	s.filePerm = 0600

	keysPath := filepath.Join(s.dir, KeysDir)
	if err := os.MkdirAll(keysPath, s.dirPerm); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

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
	if err := s.saveCurrentKeyIndex(); err != nil {
		return fmt.Errorf("failed to initialize store: %w", err)
	}

	return nil
}

// loadCurrentKey loads the current encryption key
func (s *Store) loadCurrentKey() error {
	// Read current key index
	currentKeyPath := filepath.Join(s.dir, CurrentKeyFile)

	data, err := s.readFile(currentKeyPath)
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

	return s.writeFile(currentKeyPath, []byte{s.currentKeyIndex}, s.filePerm)
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

	return s.writeFile(keyPath, data, s.filePerm)
}

// loadKey loads and decrypts a key
func (s *Store) loadKey(index uint8) ([]byte, error) {
	keyPath := filepath.Join(s.dir, KeysDir, fmt.Sprintf("key%d", index))

	data, err := s.readFile(keyPath)
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
