package csrf

import (
	"crypto/rand"
	"crypto/subtle"
	"io"
)

func generateToken() []byte {
	bytes := make([]byte, tokenLength)
	io.ReadFull(rand.Reader, bytes)
	return bytes
}

func verifyToken(realToken, sentToken []byte) bool {
	realN := len(realToken)
	sentN := len(sentToken)
	unmasked := unmaskToken(sentToken)
	if realN == tokenLength && sentN == 2*tokenLength {
		return subtle.ConstantTimeCompare(realToken, unmasked) == 1
	}
	return false
}
