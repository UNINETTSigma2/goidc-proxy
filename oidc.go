package main

import (
	"context"
	log "github.com/Sirupsen/logrus"
	oidc "github.com/coreos/go-oidc"
	//"github.com/davecgh/go-spew/spew"
	"github.com/m4rw3r/uuid"
	"golang.org/x/oauth2"
	"net/http"
)

var audVerify oidc.VerificationOption
var expVerify oidc.VerificationOption

const cookieDur = 28800 // 60*60*8 (8 hours)
const cookieName = "oidc-cookie"

type Authenticator struct {
	provider     *oidc.Provider
	clientConfig oauth2.Config
	ctx          context.Context
	stateMap     TTLMap
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
	audVerify = oidc.VerifyAudience(clientID)
	expVerify = oidc.VerifyExpiry()
	stateMap := TTLMap{m: make(map[string]Value)}
	// Expire enteries as they come in a seperate routines
	go expireEnteries(stateMap)

	return &Authenticator{
		provider:     provider,
		clientConfig: config,
		ctx:          ctx,
		stateMap:     stateMap,
	}, nil
}

func (a *Authenticator) callbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fetch state & path from our map
		path := getEntry(a.stateMap, r.URL.Query().Get("state"))
		if path == "" {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}
		// Delete the entry as we are done with this authn request
		delEntry(a.stateMap, r.URL.Query().Get("state"))

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

		_, err = a.provider.Verifier(audVerify, expVerify).Verify(a.ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Setup the cookie which will be used by client to authn later
		http.SetCookie(w, &http.Cookie{
			Name:   cookieName,
			Value:  token.AccessToken,
			MaxAge: cookieDur,
			Path:   "/",
		})
		http.Redirect(w, r, path, http.StatusFound)
	})
}

func (a *Authenticator) authHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := r.Cookie(cookieName)
		if err != nil {
			uid, err := uuid.V4()
			if err != nil {
				log.Warn("Failed in getting UUID", err)
			}
			addEntry(a.stateMap, uid.String(), r.URL.String())
			log.Debug(r.URL.String())
			http.Redirect(w, r, a.clientConfig.AuthCodeURL(uid.String()), http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}
