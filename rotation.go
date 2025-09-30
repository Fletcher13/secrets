package secrets

import (
	"fmt"
	//"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
)

// Rotate generates a new encryption key and re-encrypts all data
func (s *Store) Rotate() error {
	lk, err := s.lock(s.lockFile)
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
		return fmt.Errorf("failed to save key index file: %w", err)
	}

	go s.updateFiles(0)
	return nil
}

func (s *Store) updateFiles(calls int) {
	// Make sure we don't loop forever.  This is called recursively,
	// so only go 10 levels deep.  If we haven't succeeded by then,
	// something is very wrong.
	if calls > 10 {
		// TODO: Write unit test for this case.
		return
	}
	// Get list of all files to re-encrypt
	files, err := s.listDataFiles()
	if err != nil {
		return
	}
	for _, file := range files {
		//log.Printf("kdbg: Re-encrypting %s\n", file)
		s.reencryptFile(file)
	}

	// Clean up old keys if this successfully updated all files.
	newKeyIndex := s.currentKeyIndex
	// Get list of all files again, just to make sure there weren't new ones.
	files, err = s.listDataFiles()
	if err != nil {
		//log.Printf("kdbg: ListDataFiles failed.\n")
		return
	}
	for _, file := range files {
		i, err := s.getKeyIndex(file)
		if err != nil || i != newKeyIndex {
			//log.Printf("kdbg: Re-updating because %s has wrong key index.\n", file)
			s.updateFiles(calls + 1) // Didn't get them all, redo the update.
			return
		}
	}
	lk, err := s.lock(s.lockFile)
	if err != nil {
		//log.Printf("kdbg: Failed to grab store lock file.\n")
		return
	}
	// Don't defer the unlock until after knowing if recursive call will be made
	if s.currentKeyIndex != newKeyIndex {
		// A rotation happened while checking, can't delete old keys.  Redo.
		//log.Printf("kdbg: Rotation happened, re-encrypting files\n")
		lk.unlock()
		s.updateFiles(calls + 1)
		return
	}
	defer lk.unlock()
	curKeyPath := filepath.Join(s.keyDir, fmt.Sprintf("key%d", newKeyIndex))
	allKeys, err := filepath.Glob(filepath.Join(s.keyDir, "key*"))
	if err != nil {
		//log.Printf("kdbg: Glob failed.\n")
		return
	}
	for _, keyFile := range allKeys {
		if keyFile != curKeyPath {
			//log.Printf("kdbg: Removing key %s\n", keyFile)
			_ = os.Remove(keyFile)
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
			if strings.HasPrefix(path, s.keyDir) {
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
func (s *Store) reencryptFile(path string) {
	lk, err := s.lock(path)
	if err != nil {
		//log.Printf("kdbg: Failed to lock %s\n", path)
		return
	}
	defer lk.unlock()

	// Read and decrypt with old key
	encryptedData, err := os.ReadFile(path)
	if err != nil {
		//log.Printf("kdbg: Failed to read %s\n", path)
		// Failed to read file.  Delete it.
		_ = os.Remove(path)
		return
	}

	if len(encryptedData) < 1 {
		//log.Printf("kdbg: %s is empty\n", path)
		// Invalid file format, so no useful data.  Delete this file.
		_ = os.Remove(path)
		return
	}

	oldKeyIndex := encryptedData[0]

	if oldKeyIndex == s.currentKeyIndex {
		//		log.Printf("kdbg: %s encrypted with current key %d\n", path, oldKeyIndex)
		// Already updated, no need to re-encrypt.
		return
	}
	//	log.Printf("kdbg: Re-encrypting %s from key %d to key %d\n", path,
	//		oldKeyIndex, s.currentKeyIndex)

	data, err := s.decryptData(encryptedData)
	if err != nil {
		//log.Printf("kdbg: Failed to decrypt %s\n", path)
		// Failed to decrypt, so this data is useless.  Delete this file.
		_ = os.Remove(path)
		return
	}

	// Encrypt with new key
	newEncryptedData, err := s.encryptData(data)
	if err != nil {
		//log.Printf("kdbg: Failed to encrypt %s\n", path)
		// failed to encrypt with new key, just return leaving file
		// encrypted by old key
		return
	}

	// Write back to file
	_ = os.WriteFile(path, newEncryptedData, s.filePerm)
	//	if err != nil {
	//		log.Printf("kdbg: Failed to write newly-encrypted %s\n", path)
	//	}
}

// startRotateWatch initializes an fsnotify watch on the keys directory
// to see if any other process has done a key rotation.
func (s *Store) startRotateWatch() error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	err = w.Add(s.keyDir)
	if err != nil {
		return err
	}
	go s.rotateWatch(w)
	return nil
}

// rotateWatch is the goroutine that handles fsnotify messages from the
// keys directory to see if any other process has done a key rotation.
func (s *Store) rotateWatch(watcher *fsnotify.Watcher) {
	defer watcher.Close() //nolint: errcheck
	keyIdxFile := filepath.Join(s.keyDir, CurKeyIdxFile)
	for {
		select {
		case <-s.stopChan:
			// Stop signal received, exit gracefully
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) && event.Name == keyIdxFile {
				//log.Println("kdbg: rotateWatch Updating current key.")
				lk, err := s.rLock(s.lockFile)
				if err != nil {
					//log.Printf("kdbg: rotateWatch error grabbing lock: %v", err)
					return
				}
				err = s.loadCurrentKey()
				lk.unlock()
				if err != nil {
					//log.Printf("kdbg: rotateWatch error loading new key: %v\n",
					//	err)
					return
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			if err != nil {
				//log.Println("kdbg: Watcher got error:", err)
				return
			}
		}
	}
}
