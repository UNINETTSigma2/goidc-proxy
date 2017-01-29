package main

import (
	"context"
	log "github.com/Sirupsen/logrus"
	"github.com/parnurzeal/gorequest"
	"github.com/uninett/goidc-proxy/conf"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type TFPrincipals struct {
	Principals []string `json:"principals"`
}

func newTokenSource(clientID string, clientSecret string, tokenURL string) oauth2.TokenSource {
	conf := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
	}

	ctx := context.Background()

	return conf.TokenSource(ctx)
}

func getTFPrincipals(tokenSource oauth2.TokenSource) map[string]struct{} {
	var tfPrinipals TFPrincipals
	tfMap := make(map[string]struct{})
	token, err := tokenSource.Token()
	if err != nil {
		log.Warn("Failed in getting client token", err)
		return nil
	}
	resp, _, errs := gorequest.New().Get(conf.GetStringValue("engine.twofactor.backend")).
		Set("Authorization", "Bearer "+token.AccessToken).
		EndStruct(&tfPrinipals)

	if errs != nil || resp.StatusCode != 200 {
		log.Warn("Failed in fetching two factor principals", resp.StatusCode)
		return nil
	}
	for _, p := range tfPrinipals.Principals {
		tfMap[p] = struct{}{}
	}
	return tfMap
}
