package main

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

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
	Name:   "test-cookie0",
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
		cookieName: "test-cookie",
		signer:     NewSigner("test"),
	}

	oauthConfig = dummyConfig
	assert := assert.New(t)
	r := httptest.NewRequest("GET", "http://localhost/some_endpoint", nil)
	w := httptest.NewRecorder()

	ah := auth.authHandler(testAuthHandler(t))
	ah.ServeHTTP(w, r)

	assert.Equal(http.StatusForbidden, w.Code, "authHandler should return 403 Forbidden")

	locBytes, err := ioutil.ReadAll(w.Body)
	assert.Nil(err)
	loc := string(locBytes[:len(locBytes)])
	assert.True(strings.Contains(loc, dummyConfig.Endpoint.AuthURL+"?client_id="+dummyConfig.ClientID), "Redirect to correct URL")
}

func TestAuthHandlerUnsignedCookieRedirect(t *testing.T) {
	auth := &Authenticator{
		cookieName: "test-cookie",
		signer:     NewSigner("test"),
	}

	oauthConfig = dummyConfig
	assert := assert.New(t)
	r := httptest.NewRequest("GET", "http://localhost/some_endpoint", nil)
	dummyCookie.Value = "dummy-token" + SEP + strconv.FormatInt(time.Now().Unix()+3600, 10)
	r.AddCookie(dummyCookie)
	w := httptest.NewRecorder()

	ah := auth.authHandler(testAuthHandler(t))
	ah.ServeHTTP(w, r)

	assert.Equal(http.StatusForbidden, w.Code, "authHandler should return 403 Forbidden")
}

func TestAuthHandlerExpiredCookieRedirect(t *testing.T) {
	auth := &Authenticator{
		cookieName: "test-cookie",
		signer:     NewSigner("test"),
	}

	oauthConfig = dummyConfig
	assert := assert.New(t)
	r := httptest.NewRequest("GET", "http://localhost/some_endpoint", nil)
	dummyCookie.Value = auth.signer.getSignedData(
		"dummy-token" + SEP + strconv.FormatInt(time.Now().Unix()-3600, 10))
	r.AddCookie(dummyCookie)
	w := httptest.NewRecorder()

	ah := auth.authHandler(testAuthHandler(t))
	ah.ServeHTTP(w, r)

	assert.Equal(http.StatusForbidden, w.Code, "authHandler should return 403 Forbidden")
}

func TestAuthHandlerBadSignatureCookieRedirect(t *testing.T) {
	auth := &Authenticator{
		cookieName: "test-cookie",
		signer:     NewSigner("test"),
	}

	oauthConfig = dummyConfig
	assert := assert.New(t)
	r := httptest.NewRequest("GET", "http://localhost/some_endpoint", nil)
	dummyCookie.Value = auth.signer.getSignedData(
		"dummy-token" + SEP + strconv.FormatInt(time.Now().Unix()+3600, 10))
	dummyCookie.Value = dummyCookie.Value + "badsig"
	r.AddCookie(dummyCookie)
	w := httptest.NewRecorder()

	ah := auth.authHandler(testAuthHandler(t))
	ah.ServeHTTP(w, r)

	assert.Equal(http.StatusForbidden, w.Code, "authHandler should return 403 Forbidden")
}

func TestAuthHandlerCookie(t *testing.T) {
	auth := &Authenticator{
		cookieName: "test-cookie",
		signer:     NewSigner("test"),
	}

	oauthConfig = dummyConfig
	assert := assert.New(t)
	r := httptest.NewRequest("GET", "http://localhost/some_endpoint", nil)
	dummyCookie.Value = auth.signer.getSignedData(
		"dummy-token" + SEP + strconv.FormatInt(time.Now().Unix()+3600, 10))
	r.AddCookie(dummyCookie)
	w := httptest.NewRecorder()

	ah := auth.authHandler(testAuthHandler(t))
	ah.ServeHTTP(w, r)

	assert.Equal(http.StatusOK, w.Code, "authHandler should return 200 OK")
}
