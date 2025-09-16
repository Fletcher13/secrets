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

