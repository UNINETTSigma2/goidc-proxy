package main

import (
	"errors"
	"strconv"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/parnurzeal/gorequest"
)

type JWTToken struct {
	Token string `json:"token"`
}

func getJWTToken(accessToken string, url string) (string, error) {
	t1 := time.Now()
	defer func() {
		t2 := time.Now()
		log.WithFields(log.Fields{
			"took_ns": t2.Sub(t1),
		}).Debug("getJWTToken returned")
	}()

	var jwt JWTToken
	resp, _, errs := gorequest.New().Get(url).
		Set("Authorization", "Bearer "+accessToken).
		EndStruct(&jwt)

	if errs != nil {
		log.Warn("Failed in fetching JWT Token", errs[0].Error())
		return "", errors.New("Failed in getting JWT Token " + errs[0].Error())
	}

	if resp != nil && resp.StatusCode != 201 {
		log.Warn("Failed in fetching JWT Token", errs[0].Error())
		return "", errors.New("Failed in getting JWT Token code: " + strconv.Itoa(resp.StatusCode))
	}

	return jwt.Token, nil
}
