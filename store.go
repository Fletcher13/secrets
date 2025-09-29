package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// Algorithm constants
	AlgorithmAES256GCM = 0

	// File names
	KeyDir        = ".secretskeys"
	PrimSaltFile  = "primarysalt"
	CurKeyIdxFile = "currentkey"
	LockFile      = ".keylock"
)

// Store represents a secure storage for sensitive data
type Store struct {
	dir             string
	keyDir          string
	saltFile        string
	curKeyIdxFile   string
	lockFile        string
	primaryKey      []byte
	currentKey      []byte
	currentKeyIndex uint8
	dirPerm         os.FileMode
	filePerm        os.FileMode
	stopChan        chan struct{}
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
		return nil, fmt.Errorf("password must not be empty")
	}

	storePath, err := filepath.Abs(dirpath)
	if err != nil {
		return nil, fmt.Errorf("error parsing directory %s: %w", dirpath, err)
	}

	store := &Store{
		dir:           storePath,
		keyDir:        filepath.Join(storePath, KeyDir),
		saltFile:      filepath.Join(storePath, KeyDir, PrimSaltFile),
		curKeyIdxFile: filepath.Join(storePath, KeyDir, CurKeyIdxFile),
		lockFile:      filepath.Join(storePath, KeyDir, LockFile),
		stopChan:      make(chan struct{}),
	}

	isNewStore, err := store.checkNewStore()
	if err != nil {
		return nil, err
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
	err = store.startRotateWatch()
	if err != nil {
		return nil, err
	}

	return store, nil
}

// Close closes the store and cleans up resources
func (s *Store) Close() {
	// Send stop signal to rotateWatch goroutine
	if s.stopChan != nil {
		select {
		case <-s.stopChan:
			// Channel already closed, do nothing
		default:
			close(s.stopChan)
		}
	}

	// Clear sensitive data from memory
	Wipe(s.primaryKey)
	Wipe(s.currentKey)

	// Ensure future references fail:
	s.dir = ""
	s.keyDir = ""
	s.saltFile = ""
	s.curKeyIdxFile = ""
}

// Passwd re-encrypts the decryption key on-disk with a new password.
// It will write zeroes over the old on-disk key before writing the new
// key, just to ensure that the old password can no longer be used to
// decrypt the key to this store.
//
// WARNING:  If multiple processes are accessing the same Store, processes
// other than the one that called this function will lose access to the
// store until they re-open it with the new password.
func (s *Store) Passwd(newpassword []byte) (error) {
	// TODO: Write this function.
	// Grab the rotation lock to ensure nothing is reading or writing
	// the keys.  Defer the release of the lock.
	// For each key:
	//   Load the key with the old password.
	//   Write zeroes over the original file.
	//   Encrypt the key with the new password.
	//   Write the newly encrypted version over top of the original file.
	return nil
}

// Check if this is an existing store or not.
func (s *Store) checkNewStore() (bool, error) {
	stat, err := os.Stat(s.dir)
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("error accessing %s: %w", s.dir, err)
	} else if os.IsNotExist(err) {
		return true, nil
	} else if !stat.IsDir() {
		return false, fmt.Errorf("%s is not a directory: %w", s.dir, err)
	}

	// Directory exists, check if it's a valid store
	stat, err = os.Stat(s.keyDir)
	if os.IsNotExist(err) {
		// No keys directory, ensure dir is empty.
		dirFiles, err := os.ReadDir(s.dir)
		if err != nil || len(dirFiles) != 0 {
			return false, fmt.Errorf("%s is not empty", s.dir)
		}
		return true, nil
	} else if err != nil {
		return false, fmt.Errorf("error accessing %s: %w", s.keyDir, err)
	} else if !stat.IsDir() {
		return false, fmt.Errorf("%s is not a directory", s.dir)
	}

	// Check that primary key salt, currentkey, and keyN are all there.
	_, err = os.Stat(s.saltFile)
	if err != nil {
		return false, fmt.Errorf("%s is not a valid store, no salt file", s.dir)
	}
	data, err := os.ReadFile(s.curKeyIdxFile)
	if err != nil || len(data) != 1 {
		return false, fmt.Errorf("%s is not a valid store, no key index", s.dir)
	}
	curKeyIdxFile := filepath.Join(s.keyDir, fmt.Sprintf("key%d", data[0]))
	_, err = os.Stat(curKeyIdxFile)
	if err != nil {
		return false, fmt.Errorf("%s is not a valid store, no key file", s.dir)
	}

	return false, nil
}

func (s *Store) createNewStore(password []byte) error {
	// Create keys directory, which will auto-create store dir if it
	// does not already exist.
	s.dirPerm = 0700
	s.filePerm = 0600

	if err := os.MkdirAll(s.keyDir, s.dirPerm); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	// TODO: Double check that this works.  Evaluate race conditions carefully.
	lk, err := s.lockNB(s.lockFile)
	if err != nil {
		return fmt.Errorf("error locking %s: %w", s.lockFile, err)
	}
	defer lk.unlock()

	if err := s.createPrimaryKey(password); err != nil {
		return fmt.Errorf("failed to extract primary key from password")
	}

	// Generate initial key
	var key []byte
	if key, err = s.newKey(0); err != nil {
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
	lk, err := s.rLock(s.lockFile)
	if err != nil {
		return fmt.Errorf("error locking %s: %w", s.keyDir, err)
	}
	defer lk.unlock()

	err = s.getPrimaryKey(password) // password needed to retrieve salt.
	if err != nil {
		return err
	}
	err = s.loadCurrentKey()
	if err != nil {
		return err
	}
	stat, err := os.Stat(s.dir)
	if err != nil {
		return err // This should never fail.
	}
	s.dirPerm = stat.Mode() & os.ModePerm
	s.filePerm = s.dirPerm & 0666 // Remove execute bit

	return nil
}

func (s *Store) createPrimaryKey(password []byte) error {
	// Generate salt, save it, and then get primaryKey with Argon2
	salt, err := generateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate random salt: %w", err)
	}
	err = s.writeFile(s.saltFile, salt)
	if err != nil {
		return fmt.Errorf("failed to write salt for key: %w", err)
	}
	s.primaryKey, err = deriveKeyFromPassword(password, salt)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	return nil
}

func (s *Store) getPrimaryKey(password []byte) error {
	// Read salt, then get primaryKey with Argon2
	salt, err := s.readFile(s.saltFile)
	if err != nil {
		return fmt.Errorf("failed to read primary key salt: %w", err)
	}
	s.primaryKey, err = deriveKeyFromPassword(password, salt)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	return nil
}

// loadCurrentKey loads the current encryption key
func (s *Store) loadCurrentKey() error {
	// Read current key index
	data, err := s.readFile(s.curKeyIdxFile)
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
	return s.writeFile(s.curKeyIdxFile, []byte{s.currentKeyIndex})
}

// newKey generates, encrypts, and saves a key
func (s *Store) newKey(index uint8) ([]byte, error) {
	keyPath := filepath.Join(s.keyDir, fmt.Sprintf("key%d", index))

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

	// Save key.
	//	fmt.Printf("kdbg: Saving key %s\n", keyPath)
	err = s.writeFile(keyPath, data)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// loadKey loads and decrypts a key
func (s *Store) loadKey(index uint8) ([]byte, error) {
	keyPath := filepath.Join(s.keyDir, fmt.Sprintf("key%d", index))

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
	lk, err := s.rLock(s.lockFile)
	if err != nil {
		return fmt.Errorf("error locking %s: %w", s.keyDir, err)
	}
	keys, err := filepath.Glob(filepath.Join(s.keyDir, "key*"))
	lk.unlock()
	if err != nil {
		return fmt.Errorf("failed to read keys directory: %w", err)
	}
	if len(keys) > 1 {
		go s.updateFiles(0)
	}
	return nil
}
