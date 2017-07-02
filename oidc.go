package main

import (
	"context"

	log "github.com/Sirupsen/logrus"
	oidc "github.com/coreos/go-oidc"
	//"github.com/davecgh/go-spew/spew"
	"net/http"
	"net/url"
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
			log.Warn("State cookie not found ", GetIPsFromRequest(r))
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		log.Debug("Got response back for state: "+c.Name+" from Source IPs ", GetIPsFromRequest(r))
		token, err := oauthConfig.Exchange(a.ctx, r.URL.Query().Get("code"))
		if err != nil {
			log.Warn("No token found: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		oidcToken, ok := token.Extra("id_token").(string)
		if !ok {
			log.Warn("Failed in getting id_token ", GetIPsFromRequest(r))
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}

		_, err = a.verifier.Verify(a.ctx, oidcToken)
		if err != nil {
			log.Info("Failed to verify OpenID Token "+err.Error()+" ", GetIPsFromRequest(r))
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
				log.Debug("User is not authorized to access ", GetIPsFromRequest(r))
				http.Error(w, "Not authorized to access resource", http.StatusForbidden)
				return
			}
		}

		// Get user info and see if user/affiliations are in the list of twofactor_principals
		if !conf.GetBoolValue("engine.twofactor.all") && a.acr != nil {
			userInfo, err := a.provider.UserInfo(a.ctx, oauthConfig.TokenSource(a.ctx, token))
			if err != nil {
				log.Warn("Failed in getting User Info: "+err.Error()+" ", GetIPsFromRequest(r))
				http.Error(w, "Failed in getting User Info: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// Check if we are have redirected already then create cookie directly
			if getEntry(a.redirectMap, userInfo.Subject) == 0 {
				rediect, err := a.checkTwoFactorAuth(token.AccessToken, userInfo, groups)
				if err != nil {
					log.Warn("Failed to check user affiliations: "+err.Error()+" ", GetIPsFromRequest(r))
					http.Error(w, "Failed to check user affiliations: "+err.Error(), http.StatusInternalServerError)
					return
				}
				if rediect {
					log.Debug("Redirecting for Two factor auth with UserID ", userInfo.Subject)
					addEntry(a.redirectMap, userInfo.Subject, time.Now().Unix())
					w.Write(getRedirectJS(c.Name, oauthConfig.AuthCodeURL(r.URL.Query().Get("state"), a.acr)))
					return
				}
			}
		}

		log.Debug("Principal is authorized to access the resource from Source IPs ", GetIPsFromRequest(r))

		// Check if downstream application wants JWT or OAuth2 token
		var cToken string
		var maxAge int
		var expiry int64
		if conf.GetStringValue("engine.token_type") == "jwt" {
			cToken, err = getJWTToken(token.AccessToken, conf.GetStringValue("engine.jwt_token_issuer"))
			if err != nil {
				log.Warn("Failed to get JWT token: "+err.Error()+" ", GetIPsFromRequest(r))
				http.Error(w, "Failed to get JWT token: "+err.Error(), http.StatusInternalServerError)
				return
			}
			parseJWT, err := jws.ParseJWT([]byte(cToken))
			if err != nil {
				log.Info("Failed to parse JWT token: "+err.Error()+" ", GetIPsFromRequest(r))
				http.Error(w, "Failed to parse JWT token: "+err.Error(), http.StatusInternalServerError)
				return
			}
			maxAge = int(parseJWT.Claims().Get("exp").(float64) - float64(time.Now().Unix()))
			expiry = int64(parseJWT.Claims().Get("exp").(float64))
		} else {
			cToken = token.AccessToken
			maxAge = int(token.Expiry.Unix() - time.Now().Unix())
			expiry = int64(token.Expiry.Unix())
		}

		// Setup the cookie which will be used by client to authn later
		cValue := a.signer.getSignedData(cToken + SEP + strconv.FormatInt(expiry, 10))
		cnt := 1
		log.Debug("Token Cookie size: ", len(cValue))
		var cValues []string
		if len(cValue) > 3500 {
			cnt, cValues = splitCookie(cValue, 3500)
		} else {
			cValues = append(cValues, cValue)
		}
		for i := 0; i < cnt; i++ {
			cookie := &http.Cookie{
				Name:     a.cookieName + strconv.Itoa(i),
				Value:    cValues[i],
				MaxAge:   maxAge,
				Path:     "/",
				HttpOnly: true,
				Secure:   conf.GetBoolValue("server.secure_cookie"),
			}
			http.SetCookie(w, cookie)
		}

		unescapedStateCookie, err := url.PathUnescape(c.Value)
		if err != nil {
			log.Warn("Failed unescaping state cookie, setting to / ", err)
			unescapedStateCookie = "/"
		}
		log.Debug("Redirecting to original path "+unescapedStateCookie+" after successful authnetication ", GetIPsFromRequest(r))

		http.Redirect(w, r, unescapedStateCookie, http.StatusFound)
	})
}

func (a *Authenticator) authHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cValue, err := readCookie(r, a.cookieName)
		if err != nil {
			// Check if it is a XHR request, then send 401. As browser will not handle
			// redirect in this. Application has to handle the error by itself
			if isXHR(r.URL.Path) {
				log.Debug("XHR request is unauthenticated, will send 401 not redirect "+r.URL.Path+" ", GetIPsFromRequest(r))
				http.Error(w, "Unauthenticate XHR request, will not redirect", http.StatusUnauthorized)
			}

			uid, err := uuid.V4()
			if err != nil {
				log.Warn("Failed in getting UUID", err)
				return
			}

			// Check if we have two factor enable for all or selected principals, if for selected
			//  we will redirect for twofactor auth after getting user identity
			if a.acr != nil && conf.GetBoolValue("engine.twofactor.all") {
				w.Write(getRedirectJS("state."+uid.String(), oauthConfig.AuthCodeURL(uid.String(), a.acr)))
			} else {
				w.Write(getRedirectJS("state."+uid.String(), oauthConfig.AuthCodeURL(uid.String())))
			}
			return
		}

		recToken, valid := a.checkTokenValidity(cValue)
		if !valid {
			log.Info("Got invalid token, rediecting for authnetication", GetIPsFromRequest(r))
			uid, err := uuid.V4()
			if err != nil {
				log.Warn("Failed in getting UUID", err)
				return
			}
			// Check if it is a XHR request, then send 401. As browser will not handle
			// redirect in this. Application has to handle the error by itself
			if isXHR(r.URL.Path) {
				log.Debug("XHR request is unauthenticated, will send 401 not redirect "+r.URL.Path+" ", GetIPsFromRequest(r))
				http.Error(w, "Unauthenticate XHR request, will not redirect", http.StatusUnauthorized)
			}
			// Token is not valid, so redirecting to authenticate again
			if a.acr != nil && conf.GetBoolValue("engine.twofactor.all") {
				w.Write(getRedirectJS("state."+uid.String(), oauthConfig.AuthCodeURL(uid.String(), a.acr)))
			} else {
				w.Write(getRedirectJS("state."+uid.String(), oauthConfig.AuthCodeURL(uid.String())))
			}
			return
		}
		r.Header.Add("Authorization", "Bearer "+recToken)
		next.ServeHTTP(w, r)
	})
}

func (a *Authenticator) checkTokenValidity(data string) (string, bool) {
	t1 := time.Now()
	defer func() {
		t2 := time.Now()
		log.WithFields(log.Fields{
			"took_ns": t2.Sub(t1),
		}).Debug("checkTokenValidity returned")
	}()

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
