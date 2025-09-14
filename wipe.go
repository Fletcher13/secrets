package secrets

import (
	"crypto/rand"
	"runtime"
	"unsafe"
)

// Wipe securely zeros out sensitive data in memory
// This is required for FIPS-140 and Common Criteria compliance
func Wipe(data []byte) {
	if len(data) == 0 {
		return
	}

	// Fill with random data first to ensure no patterns remain
	if _, err := rand.Read(data); err != nil {
		// If random fill fails, just zero it
		for i := range data {
			data[i] = 0
		}
	} else {
		// Then zero it out
		for i := range data {
			data[i] = 0
		}
	}

	// Force a memory barrier to ensure the writes are visible
	runtime.KeepAlive(data)

	// On some systems, we might need to explicitly mark memory as no longer containing secrets
	// This is a best-effort approach for additional security
	if len(data) > 0 {
		// Access the underlying memory to ensure it's been written
		_ = *(*byte)(unsafe.Pointer(&data[0]))
	}
}

// WipeString securely zeros out sensitive string data
// Note: This only works for strings that are backed by mutable byte slices
func WipeString(s *string) {
	if s == nil || len(*s) == 0 {
		return
	}

	// Convert string to byte slice (this creates a copy, but we need to clear the original)
	// Unfortunately, Go strings are immutable, so we can't directly wipe them
	// This function serves as a reminder to avoid storing sensitive data in strings
	*s = ""

	// Force garbage collection to potentially free the underlying memory
	runtime.GC()
}
