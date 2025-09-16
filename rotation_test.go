package secrets

import (
	"os"
	"testing"
)

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
