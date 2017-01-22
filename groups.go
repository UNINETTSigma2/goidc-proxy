package main

import (
	log "github.com/Sirupsen/logrus"
	"github.com/davecgh/go-spew/spew"
	"github.com/parnurzeal/gorequest"
)

type Group struct {
	ID string `json:id`
}

func getGroups(token string, url string) ([]string, []error) {
	var groups []string
	var groupBody []Group

	resp, _, err := gorequest.New().Get(url).
		Set("Authorization", "Bearer "+token).
		EndStruct(&groupBody)

	if err != nil || resp.StatusCode != 200 {
		log.Warn("Failed in fetching groups", err)
		return nil, err
	}
	spew.Dump(groupBody)
	return groups, nil
}
