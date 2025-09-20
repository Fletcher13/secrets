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
	lk, err := s.lock(s.keyDir)
	if err != nil {
		return fmt.Errorf("key rotation currently in process; cannot start a new one")
	}
	defer lk.unlock()

	// Calculate new key index (roll over to 0 if at 255)
	newKeyIndex := s.currentKeyIndex + 1

	newKeyFilePath := filepath.Join(s.keyDir, fmt.Sprintf("key%d", newKeyIndex))
	_, err = os.Stat(newKeyFilePath)
	if !os.IsNotExist(err) {
		return fmt.Errorf("too many existing keys")
	}

	// Generate new key
	newKey, err := s.newKey(newKeyIndex)
	if err != nil {
		return fmt.Errorf("failed to save new key: %w", err)
	}

	// Set current key
	s.currentKey = newKey
	s.currentKeyIndex = newKeyIndex
	err = s.saveCurrentKeyIndex()
	if err != nil {
		return fmt.Errorf("failed to initialize store: %w", err)
	}

	go s.updateFiles()
	return nil
}

func (s *Store) updateFiles() {
	// Get list of all files to re-encrypt
	files, err := s.listDataFiles()
	if err != nil {
		return
	}
	for _, file := range files {
		s.reencryptFile(file)
	}

	// Clean up old keys if this successfully updated all files.
	origKeyIndex := s.currentKeyIndex
	// Get list of all files again, just to make sure there weren't new ones.
	files, err = s.listDataFiles()
	if err != nil {
		return
	}
	for _, file := range files {
		if s.getKeyIndex(file) != origKeyIndex {
			updateFiles() // Didn't get them all, redo the update.
			return
		}
	}
	l := s.Lock(keyDir)
	defer l.Unlock()
	if s.currentKeyIndex != origKeyIndex {
		// A rotation happened while checking, can't delete old keys.  Redo.
		updateFiles()
		return
	}
	curKeyPath := fmt.Sprintf("key%d", origKeyIndex)
	allKeys = filepath.Glob(keyDir + "key*")
	for _, keyFile := range allKeys {
		if keyFile != curKeyPath {
			os.Delete(keyFile)
		}
	}
}

// listDataFiles returns all data files (excluding key files)
func (s *Store) listDataFiles() ([]string, error) {
	var files []string

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

		files = append(files, path)
		return nil
	})

	return files, err
}

// reencryptFile re-encrypts a single file with the new key
func (s *Store) reencryptFile(relPath string) {
	fullPath := filepath.Join(s.dir, relPath)

	lk, err := s.lock(fullPath)
	if err != nil {
		return
	}
	defer lk.unlock()

	// Read and decrypt with old key
	encryptedData, err := os.ReadFile(fullPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if len(encryptedData) < 1 {
		// Invalid file format, so no useful data.  Delete this file.
		//		_ = s.Delete(relPath)
		return
	}

	oldKeyIndex := encryptedData[0]

	if oldKeyIndex == s.currentKeyIndex {
		// Already updated, no need to re-encrypt.
		return
	}
	data, err := s.decryptData(encryptedData)
	if err != nil {
		// Failed to decrypt, so this data is useless.  Delete this file.
		//		_ = s.Delete(relPath)
		return
	}

	// Encrypt with new key
	newEncryptedData, err := s.encryptData(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt with new key: %w", err)
	}

	// Write back to file
	_ = os.WriteFile(fullPath, newEncryptedData, s.filePerm)
	return
}

// rotateWatch does an inotify watch on the currentKey file to see if
// some other process has done a key rotation.
func (s *Store) rotateWatch() {
	// TODO: Write this.
	//	set inotify on currentkey file
	for {
		select {
		//		watchtriggered:
		//			s.loadCurrentKey()
		}
	}
}
