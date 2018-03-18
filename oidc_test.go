package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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

	oidc "github.com/coreos/go-oidc"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/UNINETT/goidc-proxy/conf"
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

var testStateID = "0000-1234-1337-9001"
var stateCookie = &http.Cookie{
	Name:   "state." + testStateID,
	Value:  "1234-1234-1234-1234",
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

type testVerifier struct {
	jwk jose.JSONWebKey
}

func (t *testVerifier) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
	}
	return jws.Verify(&t.jwk)
}

type signingKey struct {
	keyID string // optional
	priv  interface{}
	pub   interface{}
	alg   jose.SignatureAlgorithm
}

// sign creates a JWS using the private key from the provided payload.
func (s *signingKey) sign(t *testing.T, payload []byte) string {
	privKey := &jose.JSONWebKey{Key: s.priv, Algorithm: string(s.alg), KeyID: s.keyID}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: s.alg, Key: privKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	data, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// jwk returns the public part of the signing key.
func (s *signingKey) jwk() jose.JSONWebKey {
	return jose.JSONWebKey{Key: s.pub, Use: "sig", Algorithm: string(s.alg), KeyID: s.keyID}
}

func newRSAKey(t *testing.T) *signingKey {
	priv, err := rsa.GenerateKey(rand.Reader, 1028)
	if err != nil {
		t.Fatal(err)
	}
	return &signingKey{"", priv, priv.Public(), jose.RS256}
}

func createMockIssuer(t *testing.T, issuer string) (*signingKey, *oidc.IDTokenVerifier) {
	signKey := newRSAKey(t)
	ks := &testVerifier{signKey.jwk()}
	return signKey, oidc.NewVerifier(issuer, ks, &oidc.Config{
		SkipClientIDCheck: true,
		SkipExpiryCheck:   true,
	})
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

func TestCallbackHandler(t *testing.T) {
	err := conf.ReadConfig("goidc_test.json")
	if err != nil {
		t.Fatalf("Failed to read config file: %s", err)
	}

	// Create a issuer capable of signing our ID token.
	signKey, verifier := createMockIssuer(t, "https://foo")
	auth := &Authenticator{
		cookieName: "state",
		signer:     NewSigner("test"),
		ctx:        context.Background(),
		verifier:   verifier,
	}

	idToken := `{"iss":"https://foo"}`
	idTokenSigned := signKey.sign(t, []byte(idToken))
	mockTokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"access_token": "9000000000000000011111111111111111test", "scope": "user", "token_type": "bearer", "expires_in": 86400, "id_token": "%s" }`, idTokenSigned)))

	}))
	defer mockTokenServer.Close()
	oauthConfig.Endpoint.TokenURL = mockTokenServer.URL

	err, mockGroupsServer := createMockGroupServer(strings.Split(conf.GetStringValue("engine.groups_endpoint"), ",")[0])
	if err != nil {
		t.Fatal(err)
	}
	mockGroupsServer.Start()
	defer mockGroupsServer.Close()

	r := httptest.NewRequest("GET", "http://localhost/oauth2/callback?state="+testStateID+"", nil)
	r.AddCookie(stateCookie)
	w := httptest.NewRecorder()
	ah := auth.callbackHandler()
	ah.ServeHTTP(w, r)

	assert.Equal(t, http.StatusFound, w.Code, "authHandler should return 302 Found")
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
	assert.True(t, len(groups) == 1, "wrong number of groups returned")

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
