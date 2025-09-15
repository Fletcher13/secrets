package secrets

import (
	"os"
	"testing"
)

func TestNewStore(t *testing.T) {
	// Test with invalid key length
	_, err := NewStore("test_dir", []byte("short"))
	if err == nil {
		t.Error("Expected error for short key, got nil")
	}

	// Test with valid key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	store, err := NewStore("test_dir", key)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer testCleanup(t, store)

	if store == nil {
		t.Error("Store should not be nil")
	}
}

func TestSaveAndLoad(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	store, err := NewStore("test_save_load", key)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer testCleanup(t, store)

	// Test saving and loading data
	testData := []byte("test_secret_data")
	path := "test/secret"

	err = store.Save(path, testData)
	if err != nil {
		t.Fatalf("Failed to save data: %v", err)
	}

	loadedData, err := store.Load(path)
	if err != nil {
		t.Fatalf("Failed to load data: %v", err)
	}

	if string(loadedData) != string(testData) {
		t.Errorf("Expected %s, got %s", string(testData), string(loadedData))
	}
}

func TestList(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	store, err := NewStore("test_list", key)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer testCleanup(t, store)

	// Save multiple secrets
	secrets := map[string][]byte{
		"secret1":         []byte("data1"),
		"secret2":         []byte("data2"),
		"path/to/secret3": []byte("data3"),
	}

	for path, data := range secrets {
		err = store.Save(path, data)
		if err != nil {
			t.Fatalf("Failed to save %s: %v", path, err)
		}
	}

	// List secrets
	list, err := store.list()
	if err != nil {
		t.Fatalf("Failed to list secrets: %v", err)
	}

	if len(list) != len(secrets) {
		t.Errorf("Expected %d secrets, got %d", len(secrets), len(list))
	}

	// Check that all expected secrets are in the list
	for path := range secrets {
		found := false
		for _, listedPath := range list {
			if listedPath == path {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Secret %s not found in list", path)
		}
	}
}

func TestDelete(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	store, err := NewStore("test_delete", key)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer testCleanup(t, store)

	// Save a secret
	path := "test/secret"
	data := []byte("test_data")
	err = store.Save(path, data)
	if err != nil {
		t.Fatalf("Failed to save secret: %v", err)
	}

	// Verify it exists
	loadedData, err := store.Load(path)
	if err != nil {
		t.Fatalf("Failed to load secret: %v", err)
	}
	if string(loadedData) != string(data) {
		t.Error("Secret data mismatch")
	}

	// Delete the secret
	err = store.Delete(path)
	if err != nil {
		t.Fatalf("Failed to delete secret: %v", err)
	}

	// Verify it's gone
	_, err = store.Load(path)
	if err == nil {
		t.Error("Expected error when loading deleted secret")
	}
}

func TestKeyRotation(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	store, err := NewStore("test_rotation", key)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer testCleanup(t, store)

	// Save some data
	testData := []byte("test_rotation_data")
	path := "test/secret"
	err = store.Save(path, testData)
	if err != nil {
		t.Fatalf("Failed to save data: %v", err)
	}

	// Get initial key index
	info, err := store.GetStoreInfo()
	if err != nil {
		t.Fatalf("Failed to get store info: %v", err)
	}
	initialKeyIndex := info.CurrentKeyIndex

	// Rotate keys
	err = store.Rotate()
	if err != nil {
		t.Fatalf("Failed to rotate keys: %v", err)
	}

	// Verify data is still accessible
	loadedData, err := store.Load(path)
	if err != nil {
		t.Fatalf("Failed to load data after rotation: %v", err)
	}
	if string(loadedData) != string(testData) {
		t.Error("Data mismatch after rotation")
	}

	// Verify key index changed
	info, err = store.GetStoreInfo()
	if err != nil {
		t.Fatalf("Failed to get store info after rotation: %v", err)
	}
	if info.CurrentKeyIndex == initialKeyIndex {
		t.Error("Key index should have changed after rotation")
	}
}

func TestWipe(t *testing.T) {
	data := []byte("sensitive_data")
	original := make([]byte, len(data))
	copy(original, data)

	Wipe(data)

	// After wiping, the data should be different (either zeros or random)
	if string(data) == string(original) {
		t.Error("Data should be wiped and different from original")
	}
}

func TestDeriveKeyFromPassword(t *testing.T) {
	password := []byte("test_password")
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}

	key, err := DeriveKeyFromPassword(password, salt)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}

	// Same password and salt should produce same key
	key2, err := DeriveKeyFromPassword(password, salt)
	if err != nil {
		t.Fatalf("Failed to derive key again: %v", err)
	}

	if string(key) != string(key2) {
		t.Error("Same password and salt should produce same key")
	}
}

func TestGenerateSalt(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	if len(salt) != 32 {
		t.Errorf("Expected salt length 32, got %d", len(salt))
	}

	// Generate another salt and ensure they're different
	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate second salt: %v", err)
	}

	if string(salt) == string(salt2) {
		t.Error("Generated salts should be different")
	}
}

func TestPathValidation(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	store, err := NewStore("test_path_validation", key)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer testCleanup(t, store)

	// Test invalid paths
	invalidPaths := []string{
		"../outside",
		"/absolute/path",
		"path/../../outside",
		"path/..",
	}

	for _, invalidPath := range invalidPaths {
		err = store.Save(invalidPath, []byte("data"))
		if err == nil {
			t.Errorf("Expected error for invalid path %s", invalidPath)
		}
	}
}

func testCleanup(t *testing.T, store *Store) {
	err := store.Close()
	if err != nil {
		t.Fatalf("Failed to load data: %v", err)
	}
	err = os.RemoveAll("test_list")
	if err != nil {
		t.Fatalf("Failed to load data: %v", err)
	}
}
