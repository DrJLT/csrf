package csrf

import (
	"context"
	"encoding/base64"
	"net/http"
)

const (
	cookieName = "wwords"
)

// CSRFHandler is a struct
type CSRFHandler struct {
	successHandler http.Handler
	failureHandler http.Handler
	baseCookie     http.Cookie
}

func defaultFailureHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(400), 400)
}

// New CSRFHandler is generated
func New(handler http.Handler) *CSRFHandler {
	baseCookie := http.Cookie{
		MaxAge: 31536000,
		Secure: true,
	}
	csrf := &CSRFHandler{
		successHandler: handler,
		failureHandler: http.HandlerFunc(defaultFailureHandler),
		baseCookie:     baseCookie,
	}
	return csrf
}

func (h *CSRFHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var token string
	r = r.WithContext(context.WithValue(r.Context(), nosurfKey, &token))
	var realToken []byte
	tokenCookie, err := r.Cookie(cookieName)
	if err == nil {
		realToken, err = base64.StdEncoding.DecodeString(tokenCookie.Value)
		if err != nil {
			realToken = nil
		}
	}

	if len(realToken) != tokenLength {
		h.RegenerateToken(w, r)
	} else {
		ctxSetToken(r, realToken)
	}

	w.Header().Add("vary", "cookie")
	if r.Method == "GET" || r.Method == "HEAD" {
		h.successHandler.ServeHTTP(w, r)
		return
	}

	// For MITM attacks
	// if r.URL.Scheme == "https" {
	// 	referer, err := url.Parse(r.Header.Get("Referer"))
	// 	if err != nil || referer.String() == "" || referer.Scheme != r.URL.Scheme || referer.Host != r.URL.Host {
	// 		h.failureHandler.ServeHTTP(w, r)
	// 		return
	// 	}
	// }

	sentToken, err := base64.StdEncoding.DecodeString(r.Header.Get("wwords"))
	if err != nil {
		sentToken = nil
	}

	if !verifyToken(realToken, sentToken) {
		h.failureHandler.ServeHTTP(w, r)
		return
	}

	h.successHandler.ServeHTTP(w, r)
}

// RegenerateToken as the name suggests
func (h *CSRFHandler) RegenerateToken(w http.ResponseWriter, r *http.Request) string {
	token := generateToken()
	h.setTokenCookie(w, r, token)
	return Token(r)
}

func (h *CSRFHandler) setTokenCookie(w http.ResponseWriter, r *http.Request, token []byte) {
	ctxSetToken(r, token)

	cookie := h.baseCookie
	cookie.Name = cookieName
	cookie.Value = base64.StdEncoding.EncodeToString(token)

	http.SetCookie(w, &cookie)
}

// SetFailureHandler for custom 400.
// func (h *CSRFHandler) SetFailureHandler(handler http.Handler) {
// 	h.failureHandler = handler
// }

// SetBaseCookie to add to.
// func (h *CSRFHandler) SetBaseCookie(cookie http.Cookie) {
// 	h.baseCookie = cookie
// }

// func (h CSRFHandler) getcookieName() string {
// 	if h.baseCookie.Name != "" {
// 		return h.baseCookie.Name
// 	}

// 	return cookieName
// }
