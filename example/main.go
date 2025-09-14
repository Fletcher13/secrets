package main

import (
	"fmt"
	"log"
	"os"

	"github.com/fletcher13/secrets"
)

func main() {
	// Example: Use a simple key for demonstration. In a real application,
	// derive this securely (e.g., from a password using PBKDF2).
	encryptionKey := []byte("a-very-secret-key-that-is-at-least-32-bytes-long")

	// Create a temporary directory for the secret store
	dir := "example_secret_store"

	// Clean up any existing directory
	os.RemoveAll(dir)

	store, err := secrets.NewStore(dir, encryptionKey)
	if err != nil {
		log.Fatalf("Error creating/opening store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			log.Printf("Error closing store: %v", err)
		}
		os.RemoveAll(dir) // Clean up the directory when done
	}()

	fmt.Println("=== Secrets Store Example ===")

	// Save sensitive data
	secretPath := "my/api/key"
	sensitiveData := []byte("my_super_secret_api_key_123")
	err = store.Save(secretPath, sensitiveData)
	if err != nil {
		log.Fatalf("Error saving secret: %v", err)
	}
	fmt.Printf("Secret saved to %s\n", secretPath)

	// Save another secret
	anotherSecret := "database/password"
	passwordData := []byte("secure_password_456")
	err = store.Save(anotherSecret, passwordData)
	if err != nil {
		log.Fatalf("Error saving secret: %v", err)
	}
	fmt.Printf("Secret saved to %s\n", anotherSecret)

	// Load sensitive data
	loadedData, err := store.Load(secretPath)
	if err != nil {
		log.Fatalf("Error loading secret: %v", err)
	}
	fmt.Printf("Loaded secret: %s\n", string(loadedData))

	// List all secrets
	alldata, err := store.List()
	if err != nil {
		log.Fatalf("Error listing secrets: %v", err)
	}
	fmt.Printf("All secrets: %v\n", alldata)

	// Get store information
	info, err := store.GetStoreInfo()
	if err != nil {
		log.Fatalf("Error getting store info: %v", err)
	}
	fmt.Printf("Store info: Directory=%s, CurrentKeyIndex=%d, SecretCount=%d, KeyCount=%d\n",
		info.Directory, info.CurrentKeyIndex, info.SecretCount, info.KeyCount)

	// Demonstrate key rotation
	fmt.Println("\n=== Key Rotation Example ===")
	err = store.Rotate()
	if err != nil {
		log.Fatalf("Error rotating keys: %v", err)
	}
	fmt.Println("Key rotation completed successfully")

	// Verify data is still accessible after rotation
	loadedData, err = store.Load(secretPath)
	if err != nil {
		log.Fatalf("Error loading secret after rotation: %v", err)
	}
	fmt.Printf("Secret still accessible after rotation: %s\n", string(loadedData))

	// Get updated store information
	info, err = store.GetStoreInfo()
	if err != nil {
		log.Fatalf("Error getting store info: %v", err)
	}
	fmt.Printf("Updated store info: CurrentKeyIndex=%d, KeyCount=%d\n",
		info.CurrentKeyIndex, info.KeyCount)

	// Demonstrate password-based key derivation
	fmt.Println("\n=== Password-based Key Derivation Example ===")
	password := []byte("my_secure_password")
	salt, err := secrets.GenerateSalt()
	if err != nil {
		log.Fatalf("Error generating salt: %v", err)
	}

	derivedKey, err := secrets.DeriveKeyFromPassword(password, salt)
	if err != nil {
		log.Fatalf("Error deriving key: %v", err)
	}
	fmt.Printf("Derived key from password (length: %d bytes)\n", len(derivedKey))

	// Demonstrate secure memory wiping
	fmt.Println("\n=== Secure Memory Wiping Example ===")
	sensitiveBytes := []byte("sensitive_data_to_wipe")
	fmt.Printf("Before wipe: %s\n", string(sensitiveBytes))
	secrets.Wipe(sensitiveBytes)
	fmt.Printf("After wipe: %s (should be empty or random)\n", string(sensitiveBytes))

	fmt.Println("\n=== Example completed successfully ===")
}
