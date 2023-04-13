package csrf

import (
	"encoding/base64"
	"net/http"
)

const (
	cookieName  = "csrf"
	tokenLength = 32
)

func New(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" || r.Method == "HEAD" {
			h.ServeHTTP(w, r)
			return
		}

		sentToken, err := base64.StdEncoding.DecodeString(r.Header.Get(cookieName))
		if err != nil {
			errorhandler(w)
			return
		}

		var realToken []byte
		tokenCookie, err := r.Cookie(cookieName)
		if err == nil {
			realToken, err = base64.StdEncoding.DecodeString(tokenCookie.Value)
			if err != nil {
				errorhandler(w)
				return
			}
		}

		if len(realToken) != tokenLength || !verifyToken(realToken, sentToken) {
			errorhandler(w)
			return
		}

		h.ServeHTTP(w, r)
	})
}

func errorhandler(w http.ResponseWriter) {
	http.Error(w, http.StatusText(400), 400)
}

func Token(w http.ResponseWriter, r *http.Request) string {
	var token []byte
	tokenCookie, err := r.Cookie(cookieName)
	if err == nil {
		token, err = base64.StdEncoding.DecodeString(tokenCookie.Value)
		if err == nil {
			return base64.StdEncoding.EncodeToString(maskToken(token))
		}
	}
	token = generateToken()
	cookie := http.Cookie{
		MaxAge:   86400,
		Name:     cookieName,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Value:    base64.StdEncoding.EncodeToString(token),
	}
	http.SetCookie(w, &cookie)
	return base64.StdEncoding.EncodeToString(maskToken(token))
}
