package secrets

import (
	"testing"
)

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

