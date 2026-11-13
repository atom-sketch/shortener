package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

const cookieName = "user_id"

var (
	ErrMalformedCookie  = errors.New("malformed user cookie")
	ErrInvalidSignature = errors.New("invalid user cookie signature")
)

type Cookies struct {
	key []byte
}

func NewCookies(key []byte) Cookies {
	return Cookies{key: append([]byte(nil), key...)}
}

func (c Cookies) UserID(r *http.Request) (string, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return "", err
	}
	id, signature, ok := strings.Cut(cookie.Value, ":")
	if !ok || strings.TrimSpace(id) == "" || signature == "" || strings.Contains(signature, ":") {
		return "", ErrMalformedCookie
	}
	actual, err := hex.DecodeString(signature)
	if err != nil || !hmac.Equal(c.sign(id), actual) {
		return "", ErrInvalidSignature
	}
	return id, nil
}

func (c Cookies) Issue(w http.ResponseWriter, r *http.Request) (string, error) {
	var randomID [16]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(randomID[:])
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    id + ":" + hex.EncodeToString(c.sign(id)),
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
	return id, nil
}

func (c Cookies) sign(id string) []byte {
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(id))
	return mac.Sum(nil)
}
