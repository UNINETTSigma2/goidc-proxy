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

	"github.com/m4rw3r/uuid"
	"github.com/uninett/goidc-proxy/conf"
	"golang.org/x/oauth2"
)

type UserIDSec struct {
	ID []string `json:"dataporten-userid_sec"`
}

type Authenticator struct {
	provider          *oidc.Provider
	verifier          *oidc.IDTokenVerifier
	clientConfig      oauth2.Config
	ctx               context.Context
	cookieName        string
	signer            *Signer
	acr               oauth2.AuthCodeOption
	tfPrinipals       map[string]struct{}
	redirectMap       TTLMap
	logoutURL         string
	oidcGroupsClaim   string
	oidcUsernameClaim string
}

func newAuthenticator(
	clientID string,
	clientSecret string,
	redirectUrl string,
	issuerUrl string) (*Authenticator, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuerUrl)
	if err != nil {
		log.Errorf("failed to get provider: %v", err)
		return nil, err
	}

	scopes := strings.Split(conf.GetStringValue("engine.scopes"), ",")
	oauthConfig := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectUrl,
		Scopes:       append([]string{oidc.ScopeOpenID}, scopes...),
	}
	oidcConfig := &oidc.Config{
		ClientID: clientID,
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
	logoutURL := conf.GetStringValue("engine.logout_redirect_url")
	if logoutURL == "" {
		logoutURL = "/"
	}

	var groupsClaim string
	if conf.GetStringValue("engine.groups_claim") != "" {
		groupsClaim = conf.GetStringValue("engine.groups_claim")
	}

	var usernameClaim string
	if conf.GetStringValue("engine.username_claim") != "" {
		usernameClaim = conf.GetStringValue("engine.username_claim")
	}

	authneticator := &Authenticator{
		provider:          provider,
		verifier:          verifier,
		ctx:               ctx,
		cookieName:        "goidc",
		signer:            NewSigner(conf.GetStringValue("engine.signkey")),
		acr:               acrVal,
		tfPrinipals:       tfPMap,
		logoutURL:         logoutURL,
		redirectMap:       redirectMap,
		clientConfig:      oauthConfig,
		oidcGroupsClaim:   groupsClaim,
		oidcUsernameClaim: usernameClaim,
	}

	// Expire enteries in a seperate routines
	go expireEnteries(authneticator.redirectMap)

	return authneticator, nil
}

func getUserGroups(token *oauth2.Token, groupURLs []string) []string {
	var groups []string
	groupsOut := make(chan []string)
	for _, groupURL := range groupURLs {
		go func(currGroupURL string) {
			userGroups, err := getGroups(token.AccessToken, currGroupURL)

			if err != nil {
				log.Warnf("Unable to fetch groups from: %s, failed with: %s", currGroupURL, err)
			}

			groupsOut <- userGroups
		}(groupURL)
	}

	for _ = range groupURLs {
		select {
		case newGroups := <-groupsOut:
			groups = append(groups, newGroups...)
		}
	}

	return groups
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
		token, err := a.clientConfig.Exchange(a.ctx, r.URL.Query().Get("code"))
		if err != nil {
			log.Warnf("No token found: %v", err)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		oidcToken, ok := token.Extra("id_token").(string)
		if !ok {
			log.Warn("Failed in getting id_token ", GetIPsFromRequest(r))
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}

		idToken, err := a.verifier.Verify(a.ctx, oidcToken)
		if err != nil {
			log.Info("Failed to verify OpenID Token "+err.Error()+" ", GetIPsFromRequest(r))
			http.Error(w, "Failed to verify OpenID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		var principals []string
		// Extract groups from ID if oidc_groups_claim is specified
		if conf.GetStringValue("engine.groups_claim") != "" {
			var claims map[string]interface{}
			if err := idToken.Claims(&claims); err != nil {
				log.Info("Valied to extract group claim from OpenID token")
				http.Error(
					w,
					"Failed to extract claims from OpenID Token: "+err.Error(),
					http.StatusInternalServerError,
				)
				return
			}
			log.Infof("Found claims: %v", claims)
			if claimValues, found := claims[conf.GetStringValue("engine.groups_claim")]; found {
				log.Infof("Found claimValue: %s", claimValues)
				for _, claimValue := range claimValues.([]interface{}) {
					group := claimValue.(string)
					log.Infof("Found group: %s", group)
					principals = append(principals, group)
				}
			}
		}

		// Obtain groups from groups endpoint if configured
		if conf.GetStringValue("engine.groups_endpoint") != "" {
			groupURLs := strings.Split(conf.GetStringValue("engine.groups_endpoint"), ",")
			principals = append(principals, getUserGroups(token, groupURLs)...)
		}

		// Extract username from token if oidc_username_claim is specified
		if conf.GetStringValue("engine.username_claim") != "" {
			var claims map[string]interface{}
			if err := idToken.Claims(&claims); err != nil {
				log.Info("Failed to extract username claim from OpenID token")
				http.Error(
					w,
					"Failed to extract group claim from OpenID token: "+err.Error(),
					http.StatusInternalServerError,
				)
				return
			}
			if claimValue, found := claims[conf.GetStringValue("engine.username_claim")]; found {
				username := claimValue.(string)
				log.Infof("Found principal %s from username claim property", username)
				principals = append(principals, username)
			}
		}

		// Check if this given principals are allowed to access resource
		if conf.GetStringValue("engine.authorized_principals") != "" {
			authzPrinipals := strings.Split(conf.GetStringValue("engine.authorized_principals"), ",")
			authorized := false

			log.Debugf("Authorized principals: %v", authzPrinipals)

			userInfo, err := a.provider.UserInfo(a.ctx, a.clientConfig.TokenSource(a.ctx, token))
			if err != nil {
				log.Warn("Failed in getting User Info: "+err.Error()+" ", GetIPsFromRequest(r))
			} else {
				for _, p := range authzPrinipals {
					log.Debugf("Checking if %v equal %v", p, "fc:uid:"+userInfo.Subject)
					if p == "fc:uid:"+userInfo.Subject {
						authorized = true
						break
					}
				}
			}

			log.Debugf("Checking authorized groups")
			if !authorized {
				for _, principal := range principals {
					if authorized {
						break
					}
					log.Debugf("Checking if %v is authorized", principal)
					for _, validPrincipal := range authzPrinipals {
						if principal == validPrincipal {
							log.Debugf("%v is authorized", principal)
							authorized = true
							break
						}
					}
				}
				// for _, grp := range groups {
				// 	if authorized {
				// 		break
				// 	}

				// 	for _, p := range authzPrinipals {
				// 		if p == grp {
				// 			authorized = true
				// 			break
				// 		}
				// 	}
				// }
			}
			if !authorized {
				log.Debug("User is not authorized to access ", GetIPsFromRequest(r))
				http.Error(w, "Not authorized to access resource", http.StatusForbidden)
				return
			}
		}

		// Get user info and see if user/affiliations are in the list of twofactor_principals
		if !conf.GetBoolValue("engine.twofactor.all") && a.acr != nil {
			userInfo, err := a.provider.UserInfo(a.ctx, a.clientConfig.TokenSource(a.ctx, token))
			if err != nil {
				log.Warn("Failed in getting User Info: "+err.Error()+" ", GetIPsFromRequest(r))
				http.Error(w, "Failed in getting User Info: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// Check if we are have redirected already then create cookie directly
			if getEntry(a.redirectMap, userInfo.Subject) == 0 {
				rediect, err := a.checkTwoFactorAuth(token.AccessToken, userInfo, principals)
				if err != nil {
					log.Warn("Failed to check user affiliations: "+err.Error()+" ", GetIPsFromRequest(r))
					http.Error(w, "Failed to check user affiliations: "+err.Error(), http.StatusInternalServerError)
					return
				}
				if rediect {
					log.Debug("Redirecting for Two factor auth with UserID ", userInfo.Subject)
					addEntry(a.redirectMap, userInfo.Subject, time.Now().Unix())
					w.WriteHeader(http.StatusForbidden)
					w.Write(getRedirectJS(c.Name, a.clientConfig.AuthCodeURL(r.URL.Query().Get("state"), a.acr)))
					return
				}
			}
		}

		log.Debug("Principal is authorized to access the resource from Source IPs ", GetIPsFromRequest(r))

		// Check if downstream application wants JWT or OAuth2 token
		var cToken string
		var maxAge int
		var expiry int64
		// if conf.GetStringValue("engine.token_type") == "jwt" {
		// 	cToken, err = getJWTToken(token.AccessToken, conf.GetStringValue("engine.jwt_token_issuer"))
		// 	if err != nil {
		// 		log.Warn("Failed to get JWT token: "+err.Error()+" ", GetIPsFromRequest(r))
		// 		http.Error(w, "Failed to get JWT token: "+err.Error(), http.StatusInternalServerError)
		// 		return
		// 	}
		// 	parseJWT, err := jws.ParseJWT([]byte(cToken))
		// 	if err != nil {
		// 		log.Info("Failed to parse JWT token: "+err.Error()+" ", GetIPsFromRequest(r))
		// 		http.Error(w, "Failed to parse JWT token: "+err.Error(), http.StatusInternalServerError)
		// 		return
		// 	}
		// 	maxAge = int(parseJWT.Claims().Get("exp").(float64) - float64(time.Now().Unix()))
		// 	expiry = int64(parseJWT.Claims().Get("exp").(float64))
		// } else {
		// 	cToken = token.AccessToken
		// 	maxAge = int(token.Expiry.Unix() - time.Now().Unix())
		// 	expiry = int64(token.Expiry.Unix())
		// }
		cToken = token.AccessToken
		maxAge = int(token.Expiry.Unix() - time.Now().Unix())
		expiry = int64(token.Expiry.Unix())

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
		log.Debug(
			"Redirecting to original path "+unescapedStateCookie+" after successful authnetication ",
			GetIPsFromRequest(r),
		)

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
				log.Debug(
					"XHR request is unauthenticated, will send 401 not redirect "+r.URL.Path+" ",
					GetIPsFromRequest(r),
				)
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
				w.WriteHeader(http.StatusForbidden)
				w.Write(getRedirectJS("state."+uid.String(), a.clientConfig.AuthCodeURL(uid.String(), a.acr)))
			} else {
				w.WriteHeader(http.StatusForbidden)
				w.Write(getRedirectJS("state."+uid.String(), a.clientConfig.AuthCodeURL(uid.String())))
			}
			return
		}

		recToken, valid := a.checkTokenValidity(cValue)
		if !valid {
			log.Info("Got invalid token, redirecting for authentication", GetIPsFromRequest(r))
			uid, err := uuid.V4()
			if err != nil {
				log.Warn("Failed in getting UUID", err)
				return
			}
			// Check if it is a XHR request, then send 401. As browser will not handle
			// redirect in this. Application has to handle the error by itself
			if isXHR(r.URL.Path) {
				log.Debug(
					"XHR request is unauthenticated, will send 401 not redirect "+r.URL.Path+" ",
					GetIPsFromRequest(r),
				)
				http.Error(w, "Unauthenticate XHR request, will not redirect", http.StatusUnauthorized)
			}
			// Token is not valid, so redirecting to authenticate again
			if a.acr != nil && conf.GetBoolValue("engine.twofactor.all") {
				w.WriteHeader(http.StatusForbidden)
				w.Write(getRedirectJS("state."+uid.String(), a.clientConfig.AuthCodeURL(uid.String(), a.acr)))
			} else {
				w.WriteHeader(http.StatusForbidden)
				w.Write(getRedirectJS("state."+uid.String(), a.clientConfig.AuthCodeURL(uid.String())))
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

func (a *Authenticator) logoutHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := 0
		for {
			cookie, err := r.Cookie(a.cookieName + strconv.Itoa(i))
			if err == nil {
				cookie.Expires = time.Now().AddDate(-10, 0, 0)
				cookie.Value = "42"
				cookie.Path = "/"
				cookie.HttpOnly = true
				http.SetCookie(w, cookie)
			} else {
				break
			}
			i += 1
		}
		log.Debug("logging out user")
		http.Redirect(w, r, a.logoutURL, http.StatusFound)
	})
}
