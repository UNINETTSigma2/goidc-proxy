package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		cookieName: "test-cookie",
		signer:     NewSigner("test"),
	}

	oauthConfig = dummyConfig
	assert := assert.New(t)
	r := httptest.NewRequest("GET", "http://localhost/some_endpoint", nil)
	w := httptest.NewRecorder()

	ah := auth.authHandler(testAuthHandler(t))
	ah.ServeHTTP(w, r)

	assert.Equal(http.StatusOK, w.Code, "authHandler should return 200")

	locBytes, err := ioutil.ReadAll(w.Body)
	assert.Nil(err)
	loc := string(locBytes[:len(locBytes)])
	assert.True(strings.Contains(loc, dummyConfig.Endpoint.AuthURL+"?client_id="+dummyConfig.ClientID), "Redirect to correct URL")
}

func createMockGroupServer(rawURL string) (error, *httptest.Server) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return err, nil
	}
	groupsHost := parsedURL.Host

	groupJSON, err := json.Marshal([]Group{Group{"0000-" + rawURL}})
	if err != nil {
		return fmt.Errorf("Failed to marshal JSON, got error: ", err), nil
	}

	l, err := net.Listen("tcp", groupsHost)
	if err != nil {
		return fmt.Errorf("Failed to listen to: %s! Got error: %s", groupsHost, err), nil
	}

	groupsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(groupJSON)

	}))
	groupsServer.Listener = l

	return nil, groupsServer
}

func TestGroupsGetter(t *testing.T) {
	groupURLs := []string{"http://localhost:28765", "http://should-not-work.test"}
	err, mockGroupsServer := createMockGroupServer(groupURLs[0])
	if err != nil {
		t.Fatal(err)
	}

	mockGroupsServer.Start()
	defer mockGroupsServer.Close()
	mockToken := &oauth2.Token{AccessToken: "test-token"}

	groups := getUserGroups(mockToken, groupURLs)
	for _, g := range groups {
		assert.True(t, strings.HasPrefix(g, "0000-"), "groups returned incorrectly")
	}
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

	assert.Equal(http.StatusOK, w.Code, "authHandler should return 200")
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

	assert.Equal(http.StatusOK, w.Code, "authHandler should return 200")
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

	assert.Equal(http.StatusOK, w.Code, "authHandler should return 200")
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
