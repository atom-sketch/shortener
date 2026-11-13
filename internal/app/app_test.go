package app_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"shortener/internal/app"
)

const (
	baseURL = "http://localhost:8080"
	testKey = "test-signing-key"
)

type linkResponse struct {
	ShortURL    string `json:"short_url"`
	OriginalURL string `json:"original_url"`
}

func TestShortenRedirectAndList(t *testing.T) {
	handler := app.New(baseURL, []byte(testKey))
	original := "https://example.com/some/long/path?q=go#http"
	shortURL, cookie := shorten(t, handler, original, nil)
	assertSignature(t, cookie)
	if !cookie.HttpOnly || cookie.Path != "/" {
		t.Fatalf("unexpected cookie attributes: %v", cookie)
	}
	if !strings.HasPrefix(shortURL, baseURL+"/") || shortURL == baseURL+"/" {
		t.Fatalf("unexpected short URL: %q", shortURL)
	}

	redirect := request(handler, http.MethodGet, shortURL, nil, nil)
	requireStatus(t, redirect, http.StatusTemporaryRedirect)
	if got := redirect.Header().Get("Location"); got != original {
		t.Fatalf("Location = %q, want %q", got, original)
	}
	requireStatus(t, request(handler, http.MethodGet, "/unknown", nil, nil), http.StatusNotFound)

	secondOriginal := "https://example.org/second"
	secondShortURL, replacement := shorten(t, handler, secondOriginal, cookie)
	if replacement != nil {
		t.Fatal("valid cookie was replaced")
	}
	if secondShortURL == shortURL {
		t.Fatal("two links share the same short URL")
	}
	otherOriginal := "https://example.net/other-user"
	otherShortURL, otherCookie := shorten(t, handler, otherOriginal, nil)
	if otherCookie == nil || otherCookie.Value == cookie.Value {
		t.Fatal("second user did not receive a distinct cookie")
	}

	assertLinks(t, handler, cookie, []linkResponse{
		{ShortURL: shortURL, OriginalURL: original},
		{ShortURL: secondShortURL, OriginalURL: secondOriginal},
	})
	assertLinks(t, handler, otherCookie, []linkResponse{
		{ShortURL: otherShortURL, OriginalURL: otherOriginal},
	})
}

func TestUserURLsWithMissingOrInvalidCookie(t *testing.T) {
	handler := app.New(baseURL, []byte(testKey))
	_, valid := shorten(t, handler, "https://example.com/private", nil)
	_, signature, _ := strings.Cut(valid.Value, ":")
	for _, tc := range []struct {
		name       string
		cookie     *http.Cookie
		wantStatus int
	}{
		{"missing", nil, http.StatusNoContent},
		{"tampered ID", userCookie(strings.Repeat("a", 32) + ":" + signature), http.StatusNoContent},
		{"empty", userCookie(""), http.StatusUnauthorized},
		{"missing ID", userCookie(":" + signature), http.StatusUnauthorized},
		{"malformed", userCookie("no-separator"), http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := request(handler, http.MethodGet, "/api/user/urls", nil, tc.cookie)
			requireStatus(t, response, tc.wantStatus)
			if tc.wantStatus == http.StatusNoContent {
				if response.Body.Len() != 0 {
					t.Fatal("204 response has a body")
				}
				cookie := responseCookie(t, response)
				assertSignature(t, cookie)
				empty := request(handler, http.MethodGet, "/api/user/urls", nil, cookie)
				requireStatus(t, empty, http.StatusNoContent)
				if len(empty.Result().Cookies()) != 0 {
					t.Fatal("valid cookie for a user with no links was replaced")
				}
			}
		})
	}
}

func TestShortenReplacesInvalidCookie(t *testing.T) {
	handler := app.New(baseURL, []byte(testKey))
	for _, value := range []string{"", "missing-signature", "forged-id:00"} {
		original := "https://example.com/new"
		shortURL, cookie := shorten(t, handler, original, userCookie(value))
		assertSignature(t, cookie)
		assertLinks(t, handler, cookie, []linkResponse{{ShortURL: shortURL, OriginalURL: original}})
	}
}

func TestShortenRejectsInvalidRequests(t *testing.T) {
	handler := app.New(baseURL, []byte(testKey))
	for _, body := range []string{
		`{"url":`, `{}`, `{"url":"/relative"}`, `{"url":"javascript:alert(1)"}`,
		`{"url":"https://example.org"} {}`, `{"url":"https://:443/path"}`,
	} {
		response := request(handler, http.MethodPost, "/api/shorten", strings.NewReader(body), nil)
		requireStatus(t, response, http.StatusBadRequest)
	}
	body := `{"url":"https://example.org"}` + strings.Repeat(" ", 1<<20)
	response := request(handler, http.MethodPost, "/api/shorten", strings.NewReader(body), nil)
	requireStatus(t, response, http.StatusRequestEntityTooLarge)
}

func shorten(t *testing.T, handler http.Handler, original string, cookie *http.Cookie) (string, *http.Cookie) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"url": original})
	if err != nil {
		t.Fatal(err)
	}
	response := request(handler, http.MethodPost, "/api/shorten", strings.NewReader(string(body)), cookie)
	requireStatus(t, response, http.StatusCreated)
	var result struct {
		Result string `json:"result"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) == 0 {
		return result.Result, nil
	}
	return result.Result, responseCookie(t, response)
}

func request(handler http.Handler, method, path string, body io.Reader, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func requireStatus(t *testing.T, response *httptest.ResponseRecorder, want int) {
	t.Helper()
	if response.Code != want {
		t.Fatalf("HTTP status = %d, want %d, body = %q", response.Code, want, response.Body.String())
	}
}

func responseCookie(t *testing.T, response *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "user_id" {
		t.Fatalf("expected one user_id cookie, got %v", cookies)
	}
	return cookies[0]
}

func userCookie(value string) *http.Cookie {
	return &http.Cookie{Name: "user_id", Value: value}
}

func assertSignature(t *testing.T, cookie *http.Cookie) {
	t.Helper()
	if cookie == nil {
		t.Fatal("missing user cookie")
	}
	id, signature, ok := strings.Cut(cookie.Value, ":")
	if !ok || id == "" {
		t.Fatalf("invalid cookie format: %q", cookie.Value)
	}
	mac := hmac.New(sha256.New, []byte(testKey))
	mac.Write([]byte(id))
	if want := hex.EncodeToString(mac.Sum(nil)); signature != want {
		t.Fatalf("cookie signature = %q, want %q", signature, want)
	}
}

func assertLinks(t *testing.T, handler http.Handler, cookie *http.Cookie, want []linkResponse) {
	t.Helper()
	response := request(handler, http.MethodGet, "/api/user/urls", nil, cookie)
	requireStatus(t, response, http.StatusOK)
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	var got []linkResponse
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("links = %+v, want %+v", got, want)
	}
	for i, link := range got {
		if link != want[i] {
			t.Fatalf("link %d = %+v, want %+v", i, link, want[i])
		}
	}
}
