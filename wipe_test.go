package darkstore

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWipe(t *testing.T) {
	assert := assert.New(t)

	// Test case 1: Wiping a non-empty byte slice
	t.Run("Wipe non-empty slice", func(t *testing.T) {
		data := []byte{1, 2, 3, 4, 5}
		Wipe(data)
		expected := []byte{0, 0, 0, 0, 0}
		assert.Equal(expected, data, "Data should be zeroed out")
	})

	// Test case 2: Wiping an empty byte slice
	t.Run("Wipe empty slice", func(t *testing.T) {
		data := []byte{}
		// Should not panic or cause an error
		assert.NotPanics(func() { Wipe(data) })
		assert.Empty(data, "Empty slice should remain empty")
	})

	// Test case 3: Wiping a nil byte slice
	t.Run("Wipe nil slice", func(t *testing.T) {
		var data []byte = nil
		// Should not panic or cause an error
		assert.NotPanics(func() { Wipe(data) })
		assert.Nil(data, "Nil slice should remain nil")
	})

	// Test case 4: Wiping a larger slice
	t.Run("Wipe larger slice", func(t *testing.T) {
		data := make([]byte, 100)
		for i := range data {
			data[i] = byte(i % 256) // Fill with some pattern
		}
		Wipe(data)
		expected := make([]byte, 100)
		assert.Equal(expected, data, "Larger slice should be zeroed out")
	})
}
