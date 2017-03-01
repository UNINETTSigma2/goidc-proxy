package main

import (
	log "github.com/Sirupsen/logrus"
	"github.com/parnurzeal/gorequest"
)

type JWTToken struct {
	Token string `json:"token"`
}

func getJWTToken(accessToken string, url string) (string, error) {
	var jwt JWTToken
	resp, _, errs := gorequest.New().Get(url).
		Set("Authorization", "Bearer "+accessToken).
		EndStruct(&jwt)

	if errs != nil {
		log.Warn("Failed in fetching JWT Token", err)
		return nil, error.New("Failed in getting JWT Token ", errs[0])
	}

	if resp != nil && resp.StatusCode != 201 {
		log.Warn("Failed in fetching JWT Token", err)
		return nil, error.New("Failed in getting JWT Token code: ", resp.StatusCode)
	}

	return jwt.Token, nil
}
