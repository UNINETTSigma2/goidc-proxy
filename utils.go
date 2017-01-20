package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	log "github.com/Sirupsen/logrus"
	"github.com/uninett/goidc-proxy/conf"
	"hash"
)

type Signer struct {
	mac hash.Hash
	key []byte
}

func NewSigner() *Signer {
	s := new(Signer)
	s.key = []byte(conf.GetStringValue("server.signkey"))
	s.mac = hmac.New(sha256.New, s.key)
	return s
}

func encodeToString(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

func (s *Signer) getHMAC(data string) []byte {
	s.mac.Reset() // Reset to initial state
	pdata := []byte(data)
	if _, err := s.mac.Write(pdata); err != nil {
		log.Warn("Failed in getting HMAC", err)
		return nil
	}
	return s.mac.Sum(nil)
}

func (s *Signer) checkHMAC(data string, recHMAC string) bool {
	receivedHMAC, err := base64.URLEncoding.DecodeString(recHMAC)
	if err != nil {
		log.Warn("Failed in decoding signature data", err)
		return false
	}
	gotHMAC := s.getHMAC(data)
	return hmac.Equal(gotHMAC, receivedHMAC)
}
