package nosurf

import (
	"encoding/base64"
	"net/http"
)

type ctxKey int

const (
	nosurfKey ctxKey = iota
)

// Token won't be available after CSRFHandler finishes
func Token(req *http.Request) string {
	token, ok := req.Context().Value(nosurfKey).(*string)
	if !ok {
		return ""
	}
	return *token
}

func ctxSetToken(req *http.Request, token []byte) {
	ctx := req.Context().Value(nosurfKey).(*string)
	*ctx = base64.StdEncoding.EncodeToString(maskToken(token))
}
