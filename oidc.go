package main

import (
	"context"

	log "github.com/Sirupsen/logrus"
	oidc "github.com/coreos/go-oidc"
	//"github.com/davecgh/go-spew/spew"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/SermoDigital/jose/jws"
	"github.com/m4rw3r/uuid"
	"github.com/uninett/goidc-proxy/conf"
	"golang.org/x/oauth2"
)

type UserIDSec struct {
	ID []string `json:"dataporten-userid_sec"`
}

var oauthConfig oauth2.Config

type Authenticator struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	clientConfig oauth2.Config
	ctx          context.Context
	cookieName   string
	signer       *Signer
	acr          oauth2.AuthCodeOption
	tfPrinipals  map[string]struct{}
	redirectMap  TTLMap
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

	scopes := strings.Split(conf.GetStringValue("engine.scopes"), ",")
	oauthConfig = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectUrl,
		Scopes:       append([]string{oidc.ScopeOpenID}, scopes...),
	}
	oidcConfig := &oidc.Config{
		ClientID:       clientID,
		SkipNonceCheck: true,
	}
	verifier := provider.Verifier(oidcConfig)

	var acrVal oauth2.AuthCodeOption
	if conf.GetStringValue("engine.twofactor.acr_values") != "" {
		acrVal = oauth2.SetAuthURLParam("acr_values",
			conf.GetStringValue("engine.twofactor.acr_values"))
	}

	var tfPMap map[string]struct{}
	if conf.GetStringValue("engine.twofactor.principals") != "" {
		tfSvals := strings.Split(conf.GetStringValue("engine.twofactor.principals"), ",")
		tfPMap = make(map[string]struct{})
		for i := range tfSvals {
			tfPMap[tfSvals[i]] = struct{}{}
		}
	}
	redirectMap := TTLMap{m: make(map[string]Value)}

	authneticator := &Authenticator{
		provider:    provider,
		verifier:    verifier,
		ctx:         ctx,
		cookieName:  "goidc",
		signer:      NewSigner(conf.GetStringValue("engine.signkey")),
		acr:         acrVal,
		tfPrinipals: tfPMap,
		redirectMap: redirectMap,
	}

	// Expire enteries in a seperate routines
	go expireEnteries(authneticator.redirectMap)

	return authneticator, nil
}

func (a *Authenticator) callbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fetch state from cookie & path from cookie value
		c, err := r.Cookie("state." + r.URL.Query().Get("state"))
		if err != nil {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}
		cData := strings.Split(c.Value, SEP)
		if len(cData) != 2 || !a.signer.checkSig(cData[0], cData[1]) {
			http.Error(w, "Path signature does not match", http.StatusBadRequest)
			return
		}

		token, err := oauthConfig.Exchange(a.ctx, r.URL.Query().Get("code"))
		if err != nil {
			log.Warn("No token found: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		oidcToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}

		_, err = a.verifier.Verify(a.ctx, oidcToken)
		if err != nil {
			log.Info("Failed to verify OpenID Token ", err.Error())
			http.Error(w, "Failed to verify OpenID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		var groups []string
		if conf.GetStringValue("engine.groups_endpoint") != "" {
			groups, _ = getGroups(token.AccessToken, conf.GetStringValue("engine.groups_endpoint"))
		}

		// Check if this given principals are allowed to access resource
		if conf.GetStringValue("engine.authorized_principals") != "" {
			authzPrinipals := strings.Split(conf.GetStringValue("engine.authorized_principals"), ",")
			authorized := false
			for _, grp := range groups {
				for _, p := range authzPrinipals {
					if p == grp {
						authorized = true
					}
				}
			}
			if !authorized {
				http.Error(w, "Not authorized to access resource", http.StatusForbidden)
				return
			}
		}

		// Get user info and see if user/affiliations are in the list of twofactor_principals
		if !conf.GetBoolValue("engine.twofactor.all") && a.acr != nil {
			userInfo, err := a.provider.UserInfo(a.ctx, oauthConfig.TokenSource(a.ctx, token))
			if err != nil {
				http.Error(w, "Failed to getting User Info: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// Check if we are have redirected already then create cookie directly
			if getEntry(a.redirectMap, userInfo.Subject) == 0 {
				rediect, err := a.checkTwoFactorAuth(token.AccessToken, userInfo, groups)
				if err != nil {
					http.Error(w, "Failed to check user affiliations: "+err.Error(), http.StatusInternalServerError)
					return
				}
				if rediect {
					log.Debug("Redirecting for Two factor auth with UserID ", userInfo.Subject)
					addEntry(a.redirectMap, userInfo.Subject, time.Now().Unix())
					http.Redirect(w, r, oauthConfig.AuthCodeURL(r.URL.Query().Get("state"), a.acr), http.StatusFound)
					return
				}
			}
		}

		// Check if downstream application wants JWT or OAuth2 token
		var cToken string
		var maxAge int
		if conf.GetStringValue("engine.token_type") == "jwt" {
			cToken, err = getJWTToken(token.AccessToken, conf.GetStringValue("engine.jwt_token_issuer"))
			if err != nil {
				http.Error(w, "Failed to get JWT token: "+err.Error(), http.StatusInternalServerError)
				return
			}
			parseJWT, err := jws.ParseJWT([]byte(cToken))
			if err != nil {
				http.Error(w, "Failed to parse JWT token: "+err.Error(), http.StatusInternalServerError)
				return
			}
			maxAge = int(parseJWT.Claims().Get("exp").(float64) - parseJWT.Claims().Get("iat").(float64))
		} else {
			cToken = token.AccessToken
			maxAge = int(token.Expiry.Unix() - time.Now().Unix())
		}

		// Setup the cookie which will be used by client to authn later
		cValue := cToken + SEP + strconv.FormatInt(token.Expiry.Unix(), 10)
		http.SetCookie(w, &http.Cookie{
			Name:     a.cookieName,
			Value:    a.signer.getSignedData(cValue),
			MaxAge:   maxAge,
			Path:     "/",
			HttpOnly: true,
			Secure:   conf.GetBoolValue("server.secure_cookie"),
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
				Name:     "state." + uid.String(),
				Value:    a.signer.getSignedData(r.URL.String()),
				MaxAge:   28800,
				Path:     "/",
				HttpOnly: true,
				Secure:   conf.GetBoolValue("server.secure_cookie"),
			})
			log.Debug("Path is: ", r.URL.String())
			// Check if we have two factor enable for all or selected principals, if for selected
			//  we will redirect for twofactor auth after getting user identity
			if a.acr != nil && conf.GetBoolValue("engine.twofactor.all") {
				http.Redirect(w, r, oauthConfig.AuthCodeURL(uid.String(), a.acr), http.StatusFound)
			} else {
				http.Redirect(w, r, oauthConfig.AuthCodeURL(uid.String()), http.StatusFound)
			}
			return
		}

		recToken, valid := a.checkTokenValidity(c.Value)
		if !valid {
			log.Info("Got invalid token, rediecting for authnetication")
			uid, err := uuid.V4()
			if err != nil {
				log.Warn("Failed in getting UUID", err)
			}
			// Token is not valid, so redirecting to authenticate again
			if a.acr != nil && conf.GetBoolValue("engine.twofactor.all") {
				http.Redirect(w, r, oauthConfig.AuthCodeURL(uid.String(), a.acr), http.StatusFound)
			} else {
				http.Redirect(w, r, oauthConfig.AuthCodeURL(uid.String()), http.StatusFound)
			}
			return
		}
		r.Header.Add("Authorization", "Bearer "+recToken)
		next.ServeHTTP(w, r)
	})
}

func (a *Authenticator) checkTokenValidity(data string) (string, bool) {
	cData := strings.Split(data, SEP)
	if len(cData) != 3 || !a.signer.checkSig(cData[0]+SEP+cData[1], cData[2]) {
		log.Warn("Token signature does not match")
		return "", false
	}
	expTime, err := strconv.ParseInt(cData[1], 10, 64)
	if err != nil {
		log.Debug("Failed to parse the expiry time")
		return "", false
	}
	if time.Now().Unix() > expTime {
		log.Debug("Token has expired, will rediect to authnetication again")
		return "", false
	}
	return cData[0], true
}

func (a *Authenticator) checkTwoFactorAuth(token string, userInfo *oidc.UserInfo, groups []string) (bool, error) {
	var userPrincipals []string
	var userIdSec UserIDSec

	userPrincipals = append(userPrincipals, userInfo.Subject)
	userPrincipals = append(userPrincipals, groups...)
	err := userInfo.Claims(&userIdSec)
	if err != nil {
		log.Warn("Failed in getting Feide ID", err)
		return false, err
	}
	if len(userIdSec.ID) > 0 {
		userPrincipals = append(userPrincipals, userIdSec.ID...)
	}

	for _, p := range userPrincipals {
		if _, ok := a.tfPrinipals[p]; ok {
			return true, nil
		}
	}

	return false, nil
}
