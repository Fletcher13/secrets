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
	KeysDir         = ".secretskeys"
	PrimarySaltFile = KeysDir + "/primarysalt"
	CurrentKeyFile  = KeysDir + "/currentkey"
)

// Store represents a secure storage for sensitive data
type Store struct {
	dir             string
	primaryKey      []byte
	currentKey      []byte
	currentKeyIndex uint8
	dirPerm         os.FileMode
	filePerm        os.FileMode
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
func NewStore(dirpath string, password []byte) (*Store, error) {
	// TODO: if len(password) == 0 { Use TPM2.0 sealed key }
	if len(password) == 0 {
		// TODO: Use PBKDF2 to generate the key from any password.
		return nil, fmt.Errorf("password must not be empty")
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

	if isNewStore {
		err = store.createNewStore(password) // password needed to set salt.
	} else {
		err = store.openExistingStore(password) // password needed for primary key.
	}
	if err != nil {
		return nil, err
	}

	// Start recovery process if needed
	if err = store.checkForOldKeys(); err != nil {
		return nil, err
	}

	// Start watcher for key rotation done by other processes
	go store.rotateWatch()

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
	} else if os.IsNotExist(err) {
		return true, nil
	} else if !stat.IsDir() {
		return false, fmt.Errorf("%s is not a directory: %w", storePath, err)
	}

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
		return false, fmt.Errorf("%s is not a directory", storePath)
	}

	// Check that primary key salt, currentkey, and keyN are all there.
	_, err = os.Stat(filepath.Join(storePath, PrimarySaltFile))
	if err != nil {
		return false, fmt.Errorf("%s is not a valid store, no salt file",
			storePath)
	}
	data, err := os.ReadFile(filepath.Join(storePath, CurrentKeyFile))
	if err != nil || len(data) != 1 {
		return false, fmt.Errorf("%s is not a valid store, no current key file",
			storePath)
	}
	keyPath := filepath.Join(storePath, KeysDir, fmt.Sprintf("key%d", data[0]))
	_, err = os.Stat(keyPath)
	if err != nil {
		return false, fmt.Errorf("%s is not a valid store, no key file",
			storePath)
	}

	return false, nil
}

func (s *Store) createNewStore(password []byte) error {
	// Create keys directory, which will auto-create store dir if it
	// does not already exist.
	s.dirPerm = 0700
	s.filePerm = 0600

	keysPath := filepath.Join(s.dir, KeysDir)
	if err := os.MkdirAll(keysPath, s.dirPerm); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	if err := s.createPrimaryKey(password); err != nil {
		return fmt.Errorf("failed to extract primary key from password")
	}

	// Generate initial key
	if key, err := s.newKey(0); err != nil {
		return fmt.Errorf("failed to create key0: %w", err)
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

func (s *Store) openExistingStore(password []byte) error {
	err = store.getPrimaryKey(password) // password needed to retrieve salt.
	if err != nil {
		return err
	}
	err = store.loadCurrentKey()
	if err != nil {
		return err
	}
	stat, err := os.Stat(store.dir)
	if err != nil {
		return err // This should never fail.
	}
	store.dirPerm = stat.Mode() & os.ModePerm
	store.filePerm = store.dirPerm & 0666 // Remove execute bit

	return nil
}

func (s *Store) createPrimaryKey(password []byte) error {
	// Generate salt, save it, and then get primaryKey with Argon2
	salt, err := GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate random salt: %w", err)
	}
	primarySaltFile := filepath.Join(s.dir, PrimarySaltFile)
	err = s.writeFile(primarySaltFile, salt)
	if err != nil {
		return fmt.Errorf("failed to write salt for key: %w", err)
	}
	s.primaryKey, err = DeriveKeyFromPassword(password, salt)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	return nil
}

func (s *Store) getPrimaryKey(password []byte) error {
	// Read salt, then get primaryKey with Argon2
	primarySaltFile := filepath.Join(s.dir, PrimarySaltFile)
	salt, err := s.readFile(primarySaltFile)
	if err != nil {
		return fmt.Errorf("failed to read primary key salt: %w", err)
	}
	s.primaryKey, err = DeriveKeyFromPassword(password, salt)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
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

	return s.writeFile(currentKeyPath, []byte{s.currentKeyIndex})
}

// saveKey encrypts and saves a key
func (s *Store) newKey(index uint8) ([]byte, error) {
	keyPath := filepath.Join(s.dir, KeysDir, fmt.Sprintf("key%d", index))

	// Generate the key.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Encrypt the key with primary key using AES-GCM
	block, err := aes.NewCipher(s.primaryKey[:32])
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

	err = s.writeFile(keyPath, data)
	if err != nil {
		return nil, err
	}
	return key, nil
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

// checkForOldKeys checks for inconsistent key usage and recovers if needed
func (s *Store) checkForOldKeys() error {
	// Get list of key files
	keysDir := filepath.Join(s.dir, KeysDir)
	keys, err := filepath.Glob(keysDir + filepath.Separator + "key*")
	if err != nil {
		return fmt.Errorf("failed to read keys directory: %w", err)
	}
	if len(keys) > 1 {
		go s.updateFiles()
	}
	return nil
}
