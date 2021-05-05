package csrf

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
)

const (
	tokenLength = 32
)

func generateToken() []byte {
	bytes := make([]byte, tokenLength)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		panic(err)
	}
	return bytes
}

func verifyToken(realToken, sentToken []byte) bool {
	realN := len(realToken)
	sentN := len(sentToken)
	unmasked := unmaskToken(sentToken)
	if realN == tokenLength && sentN == 2*tokenLength {
		return len(unmasked) == tokenLength && subtle.ConstantTimeCompare(realToken, unmasked) == 1
	}
	return false
}

func init() {
	buf := make([]byte, 1)
	_, err := io.ReadFull(rand.Reader, buf)

	if err != nil {
		panic(fmt.Sprintf("crypto/rand is unavailable: Read() failed with %#v", err))
	}
}
