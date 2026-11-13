package app

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"shortener/internal/auth"
	"shortener/internal/storage"
)

const maxRequestBody = 1 << 20

type app struct {
	baseURL string
	cookies auth.Cookies
	links   *storage.Memory
}

func New(baseURL string, signingKey []byte) http.Handler {
	a := app{
		baseURL: strings.TrimRight(baseURL, "/"),
		cookies: auth.NewCookies(signingKey),
		links:   storage.NewMemory(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/shorten", a.shorten)
	mux.HandleFunc("GET /api/user/urls", a.userURLs)
	mux.HandleFunc("GET /{id}", a.redirect)
	return mux
}

func (a app) shorten(w http.ResponseWriter, r *http.Request) {
	var request struct {
		URL string `json:"url"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	err := decoder.Decode(&request)
	if err == nil {
		err = decoder.Decode(new(json.RawMessage))
		switch {
		case err == io.EOF:
			err = nil
		case err == nil:
			err = errors.New("expected one JSON object")
		}
	}
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid JSON request", http.StatusBadRequest)
		return
	}
	parsed, err := url.Parse(request.URL)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		http.Error(w, "url must be an absolute HTTP or HTTPS URL", http.StatusBadRequest)
		return
	}

	userID, err := a.cookies.UserID(r)
	if err != nil {
		userID, err = a.cookies.Issue(w, r)
		if err != nil {
			writeInternalError(w, err)
			return
		}
	}
	id := a.links.Add(userID, request.URL)
	writeJSON(w, http.StatusCreated, struct {
		Result string `json:"result"`
	}{Result: a.baseURL + "/" + id})
}

func (a app) redirect(w http.ResponseWriter, r *http.Request) {
	originalURL, ok := a.links.OriginalURL(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, originalURL, http.StatusTemporaryRedirect)
}

func (a app) userURLs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	userID, err := a.cookies.UserID(r)
	if errors.Is(err, auth.ErrMalformedCookie) {
		http.Error(w, "malformed user cookie", http.StatusUnauthorized)
		return
	}
	if err != nil {
		userID, err = a.cookies.Issue(w, r)
		if err != nil {
			writeInternalError(w, err)
			return
		}
	}

	links := a.links.UserLinks(userID)
	if len(links) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	type userURL struct {
		ShortURL    string `json:"short_url"`
		OriginalURL string `json:"original_url"`
	}
	result := make([]userURL, 0, len(links))
	for _, link := range links {
		result = append(result, userURL{
			ShortURL:    a.baseURL + "/" + link.ID,
			OriginalURL: link.OriginalURL,
		})
	}
	writeJSON(w, http.StatusOK, result)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write JSON response: %v", err)
	}
}

func writeInternalError(w http.ResponseWriter, err error) {
	log.Printf("issue user cookie: %v", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}
