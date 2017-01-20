package main

import (
	"context"
	log "github.com/Sirupsen/logrus"
	oidc "github.com/coreos/go-oidc"
	//"github.com/davecgh/go-spew/spew"
	"github.com/m4rw3r/uuid"
	"github.com/uninett/goidc-proxy/conf"
	"golang.org/x/oauth2"
	"net/http"
	"strings"
)

type Authenticator struct {
	provider     *oidc.Provider
	clientConfig oauth2.Config
	ctx          context.Context
	audVerify    oidc.VerificationOption
	expVerify    oidc.VerificationOption
	cookieDur    int
	cookieName   string
	signer       *Signer
}

func newAuthenticator(
	clientID string,
	clientSecret string,
	redirectUrl string,
	issuerUrl string) (*Authenticator, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuerUrl)
	if err != nil {
		log.Error("failed to get provider: %v", err)
		return nil, err
	}

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectUrl,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	// Enforce aud and expiry check, as library is not doing it by default
	audVerify := oidc.VerifyAudience(clientID)
	expVerify := oidc.VerifyExpiry()

	return &Authenticator{
		provider:     provider,
		clientConfig: config,
		ctx:          ctx,
		audVerify:    audVerify,
		expVerify:    expVerify,
		cookieDur:    28800, // 60*60*8 (8 hours)
		cookieName:   "goidc",
		signer:       NewSigner(conf.GetStringValue("server.signkey")),
	}, nil
}

func (a *Authenticator) callbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fetch state from cookie & path from cookie value
		c, err := r.Cookie(r.URL.Query().Get("state"))
		if err != nil {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}
		if !a.signer.checkSig(c.Value) {
			http.Error(w, "Signature does not match", http.StatusBadRequest)
			return
		}

		token, err := a.clientConfig.Exchange(a.ctx, r.URL.Query().Get("code"))
		if err != nil {
			log.Warn("no token found: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}

		_, err = a.provider.Verifier(a.audVerify, a.expVerify).Verify(a.ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Setup the cookie which will be used by client to authn later
		http.SetCookie(w, &http.Cookie{
			Name:     a.cookieName,
			Value:    token.AccessToken,
			MaxAge:   a.cookieDur,
			Path:     "/",
			HttpOnly: true,
			Secure:   conf.GetBoolValue("server.securecookie"),
		})
		http.Redirect(w, r, strings.Split(c.Value, SEP)[0], http.StatusFound)
	})
}

func (a *Authenticator) authHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(a.cookieName)
		if err != nil {
			uid, err := uuid.V4()
			if err != nil {
				log.Warn("Failed in getting UUID", err)
			}
			// Setup the cookie which will be used to get the rediect path after authn
			http.SetCookie(w, &http.Cookie{
				Name:     uid.String(),
				Value:    a.signer.getSignedData(r.URL.String()),
				MaxAge:   300,
				Path:     "/",
				HttpOnly: true,
				Secure:   conf.GetBoolValue("server.securecookie"),
			})
			log.Debug("Path is: ", r.URL.String())
			http.Redirect(w, r, a.clientConfig.AuthCodeURL(uid.String()), http.StatusFound)
			return
		}
		r.Header.Add("Authorization", "Bearer "+c.Value)
		next.ServeHTTP(w, r)
	})
}
