package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

var dummyConfig = oauth2.Config{
	ClientID:     "our-id",
	ClientSecret: "some-secret",
	Endpoint: oauth2.Endpoint{
		AuthURL:  "http://oauth.example.com/auth",
		TokenURL: "http://oauth.example.com/token",
	},
	RedirectURL: "http://localhost/oauth2/callback",
	Scopes:      []string{},
}

var dummyCookie = &http.Cookie{
	Name:   "test-cookie",
	Value:  "dummy-token",
	MaxAge: 3600,
	Path:   "/",
}

func testAuthHandler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, true, "Nested handler called")
	})
}

func TestAuthHandlerRedirect(t *testing.T) {
	auth := &Authenticator{
		clientConfig: dummyConfig,
		cookieName:   "test-cookie",
		stateMap:     TTLMap{m: make(map[string]Value)},
	}

	assert := assert.New(t)
	r := httptest.NewRequest("GET", "http://localhost/some_endpoint", nil)
	w := httptest.NewRecorder()

	ah := auth.authHandler(testAuthHandler(t))
	ah.ServeHTTP(w, r)

	assert.Equal(http.StatusFound, w.Code, "authHandler should return 302 Found")

	loc := w.Header().Get("Location")
	assert.True(strings.HasPrefix(loc, dummyConfig.Endpoint.AuthURL+"?client_id="+dummyConfig.ClientID), "Redirect to correct URL")
}

func TestAuthHandlerCookie(t *testing.T) {
	auth := &Authenticator{
		clientConfig: dummyConfig,
		cookieName:   "test-cookie",
		stateMap:     TTLMap{m: make(map[string]Value)},
	}

	assert := assert.New(t)
	r := httptest.NewRequest("GET", "http://localhost/some_endpoint", nil)
	r.AddCookie(dummyCookie)
	w := httptest.NewRecorder()

	ah := auth.authHandler(testAuthHandler(t))
	ah.ServeHTTP(w, r)

	assert.Equal(http.StatusOK, w.Code, "authHandler should return 200 OK")
}
