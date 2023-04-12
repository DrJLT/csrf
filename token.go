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

// package csrf

// import (
// 	"encoding/base64"
// 	"net/http"
// )

// type ctxKey int

// const (
// 	nosurfKey ctxKey = iota
// )

// // Token won't be available after CSRFHandler finishes
// func Token(req *http.Request) string {
// 	token, ok := req.Context().Value(nosurfKey).(*string)
// 	if !ok {
// 		return ""
// 	}
// 	return *token
// }

// func ctxSetToken(req *http.Request, token []byte) {
// 	ctx := req.Context().Value(nosurfKey).(*string)
// 	*ctx = base64.StdEncoding.EncodeToString(maskToken(token))
// }
