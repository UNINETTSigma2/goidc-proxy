package main

import (
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/parnurzeal/gorequest"
)

type Group struct {
	ID string `json:id`
}

func getGroups(token string, url string) ([]string, []error) {
	t1 := time.Now()
	defer func() {
		t2 := time.Now()
		log.WithFields(log.Fields{
			"took_ns": t2.Sub(t1),
		}).Debug("getGroups returned")
	}()

	var groups []string
	var groupBody []Group

	resp, _, err := gorequest.New().Get(url).
		Set("Authorization", "Bearer "+token).
		EndStruct(&groupBody)

	if err != nil || resp.StatusCode != 200 {
		log.Warn("Failed in fetching groups", err)
		return nil, err
	}
	for _, grp := range groupBody {
		groups = append(groups, grp.ID)
	}
	return groups, nil
}
