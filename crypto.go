package csrf

import (
	"crypto/rand"
	"io"
)

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

	io.ReadFull(rand.Reader, key)

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
