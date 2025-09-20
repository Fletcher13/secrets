package main

import (
	"fmt"
	"log"
	"os"

	"github.com/fletcher13/secrets"
)

func main() {
	// Example: Use a simple password for demonstration. In a real
	// application, obtain the password from a secure source.
	password := []byte("secret-password")

	// Create a temporary directory for the secret store
	dir := "example_secret_store"

	// Clean up any existing directory
	err := os.RemoveAll(dir)
	if err != nil {
		log.Fatalf("Error ensuring store directory does not exist: %v", err)
	}

	store, err := secrets.NewStore(dir, password)
	secrets.Wipe(password)
	if err != nil {
		log.Fatalf("Error creating/opening store: %v", err)
	}
	defer func() {
		store.Close()
		err = os.RemoveAll(dir) // Clean up the directory when done
		if err != nil {
			log.Fatalf("Error ensuring store directory does not exist: %v", err)
		}
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

	// Demonstrate secure memory wiping
	fmt.Println("\n=== Secure Memory Wiping Example ===")
	sensitiveBytes := []byte("sensitive_data_to_wipe")
	fmt.Printf("Before wipe: %s\n", string(sensitiveBytes))
	secrets.Wipe(sensitiveBytes)
	fmt.Printf("After wipe: %s (should be empty or random)\n", string(sensitiveBytes))

	fmt.Println("\n=== Example completed successfully ===")
}
