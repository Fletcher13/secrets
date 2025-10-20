
# darkstore

Golang package to securely save passwords, keys, and other sensitive data.

This package provides a simple and secure way for developers to handle
sensitive information like passwords and API keys without needing deep
cryptographic expertise. It encrypts and stores data persistently,
ensuring availability across program restarts and protecting against
corruption from multiple process access.

## Features
- Secure encryption and decryption of sensitive data.
- Persistent storage of secrets on disk.
- Thread-safe and process-safe access to secrets.
- Support for key rotation to enhance security.
- Ability to create password-protected tarballs of secret stores for
  portability.

## Installation

To install the `darkstore` package, use `go get`:

```bash
go get github.com/kenm928/darkstore
```

This package requires Go 1.24 or later.

## Overview

A set of data protected by a single password is called a 'store'.  Each
darkstore store lives in its own directory.  The data is protected by a
symmetric encryption algorithm.  Currently only AES256GCM is supported,
but the library is designed to support any symmetric key algorithm in
the future.

A random key is generated that is used to encrypt the actual data, and
that key is stored with the data encrypted by a user-given password.

## Usage

### Creating or Opening a Secret Store

To create a new `darkstore.Store` or open an existing one, use
`darkstore.NewStore(dirpath string, password []byte)`.

- If `dirpath` is an empty directory or does not exist, a new store will
  be initialized there.
- If `dirpath` contains an existing store, the store will be opened for
  use.
- An error will be returned if `dirpath` is not empty and does not
  contain a darkstore store.

The `password` parameter is required for decrypting the store's internal
keys. This password should *not* be saved with the darkstore store, as
that would defeat the purpose of encrypting the data.  The password is
then hashed with Argon2id to generate the key used to encrypt/decrypt
the key(s) used to encrypt/decrypt the sensitive data.

### Key Rotation

The `store.Rotate()` method allows you to generate a new encryption key
for the store and re-encrypt all existing data with the new key. This is
a crucial security feature for regularly updating your encryption keys.

TODO: Figure out logging for a library.

### Updating Password

The `store.Passwd()` method allows the user to change the password for a
store.  This function is guaranteed to succeed or fail without leaving
the store in an unaccessible state, even if the program panics or system
halts in the middle of the `Passwd()` call.

### Zeroization

Never put sensitive data in a string, always use a byte slice.  Byte
slices can be zeroed when the data is no longer needed, but strings
cannot be zeroed in Go.

Use the `darkstore.Wipe()` function to zero out sensitive data when that
data is no longer needed.  This is required for FIPS-140 and Common
Criteria compliance.

### Example

```go
package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/kenm928/darkstore"
)

func main() {
	// Example: Use a simple password for demonstration. In a real
	// application, obtain the password from a secure source.
	password := []byte("secret-password")

	// Create a temporary directory for the secret store
	dir, err := ioutil.TempDir("", "secret_store")
	if err != nil {
		fmt.Printf("Error creating temp directory: %v\n", err)
		return
	}
	defer os.RemoveAll(dir) // Clean up the directory when done

	store, err := darkstore.NewStore(dir, password)
	if err != nil {
		fmt.Printf("Error creating/opening store: %v\n", err)
		return
	}
	darkstore.Wipe(password)

	// Save sensitive data
	secretPath := "my/api/key"
	sensitiveData := []byte("my_super_secret_api_key_123")
	err = store.Save(secretPath, sensitiveData)
	if err != nil {
		fmt.Printf("Error saving secret: %v\n", err)
		return
	}
	fmt.Printf("Secret saved to %s\n", secretPath)

	// Load sensitive data
	loadedData, err := store.Load(secretPath)
	if err != nil {
		fmt.Printf("Error loading secret: %v\n", err)
		return
	}
	fmt.Printf("Loaded secret: %s\n", string(loadedData))
}
```

## Implementation Details

Every `darkstore.Store` directory contains a `.darkstorekeys`
subdirectory. This directory manages the encryption keys for the store.

### Key Management

In the `.darkstorekeys` directory, you will find:
- `currentkey`: A single byte file indicating which key number (0-255)
  is currently used for newly encrypted data.
- `key<N>`: One or more binary files, where `<N>` is a number between 0
  and 255. Each `key<N>` file contains the encryption key for that
  index. The first byte of a `key<N>` file indicates the encryption
  algorithm used (currently, only algorithm 0, AES256GCM, is defined),
  followed by the key itself, encrypted with the key passed in to
  `darkstore.NewStore()`.
- `primarysalt`: A binary file containing the salt used for hashing the
  store's password with Argon2id.
- `.keylock`: An empty file used with flock(2) to prevent multiple
  threads or processes from accessing the keys directory simultaneously.

### Data Storage

All other files in the `darkstore.Store` directory are encrypted user
data. When `store.Save(path, data)` is called:
- The `path` is cleaned and validated to ensure it remains within the
  store's hierarchy.
- The `data` is encrypted.
- The first byte of the saved data file indicates the key number used
  for encryption, followed by the encrypted data.

### Store Initialization and Key Generation

When `darkstore.NewStore()` is called on an empty directory:
- It initializes `currentkey` to 0.
- Generates, encrypts, and saves `key0`.

### Key Rotation Process

The `store.Rotate()` function performs the following:
1. Generates a new key, incrementing the `currentkey` index (rolling
   over to 0 if `currentkey` is 255).
2. Saves the new key in a `key<N>` file.
3. Updates `currentkey` in the config file to point to the new key.
4. Re-encrypts all existing data in the store with the new key.
5. Deletes all old keys once all data is confirmed to be re-encrypted.

### Concurrency and Crash Recovery

The library aims to be thread-safe and process-safe using file
`rwlocks`. Considerations for NFS filesystems and multi-computer safety
require further research into mechanisms like `flock`.

When `NewStore()` is called:
- It verifies the existence of the `currentkey` file and associated key
  file.
- If multiple key files are present (indicating a potential incomplete
  rotation from a previous crash), a goroutine is launched to walk
  through the store hierarchy. This goroutine re-encrypts any data not
  using `currentkey` with the `currentkey`.
- To handle concurrent rotations or crashes during re-encryption,
  mechanisms are in place (e.g., monitoring the config file for changes
  via `inotify`) to stop ongoing re-encryption goroutines if a new
  rotation is initiated. This ensures data consistency and prevents
  corruption. The responsibility for updating secrets shifts to the
  latest rotation process.
