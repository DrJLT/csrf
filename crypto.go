package csrf

import (
	"crypto/rand"
	"io"
)

// Slices must be of the same length, or oneTimePad will panic
func oneTimePad(data, key []byte) {
	n := len(data)
	if n != len(key) {
		panic("Lengths of slices are not equal")
	}

	for i := 0; i < n; i++ {
		data[i] ^= key[i]
	}
}

func maskToken(data []byte) []byte {
	if len(data) != tokenLength {
		return nil
	}

	result := make([]byte, 2*tokenLength)
	key := result[:tokenLength]
	token := result[tokenLength:]
	copy(token, data)

	// generate the random token
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}

	oneTimePad(token, key)
	return result
}

func unmaskToken(data []byte) []byte {
	if len(data) != tokenLength*2 {
		return nil
	}

	token := data[tokenLength:]
	oneTimePad(token, data[:tokenLength])

	return token
}
