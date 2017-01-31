package main

import (
	"bytes"
	"encoding/json"
	log "github.com/Sirupsen/logrus"
	"github.com/uninett/goidc-proxy/conf"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

type transport struct {
	http.RoundTripper
}

type ACRValues struct {
	Values string `json:"required_acr_values"`
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func (t *transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	resp, err = t.RoundTripper.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusForbidden &&
		conf.GetBoolValue("engine.twofactor.rediect_on_response") {
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Warn("Failed in reading response body ", err)
			return resp, err
		}
		err = resp.Body.Close()
		if err != nil {
			log.Warn("Failed in closing response body ", err)
		}
		var acr ACRValues
		err = json.Unmarshal(b, &acr)
		if err != nil {
			log.Warn("Failed in parsing response body ", err)
		}
		if acr.Values != "" {
			var state string
			for _, c := range req.Cookies() {
				if strings.HasPrefix(c.Name, "state.") {
					state = strings.Split(c.Name, ".")[1]
				}
			}
			acrVal := oauth2.SetAuthURLParam("acr_values", acr.Values)
			resp.Body = ioutil.NopCloser(bytes.NewReader([]byte("{}")))
			resp.StatusCode = http.StatusFound
			resp.Header.Add("Location", oauthConfig.AuthCodeURL(state, acrVal))
			return resp, nil
		}
		resp.Body = ioutil.NopCloser(bytes.NewReader(b))
	}
	return resp, nil
}

// NewReverseProxy prvoides reverse proxy functionality towards target
func NewReverseProxy(target *url.URL) *httputil.ReverseProxy {
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
	}

	// These are copied from the DefaultTrasport RoundTripper of Go 1.7.1
	// The only change is the Dialer Timeout and KeepAlive that have been
	// upped from 30 to 120 seconds.
	proxyTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   120 * time.Second,
			KeepAlive: 120 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &httputil.ReverseProxy{Director: director, Transport: &transport{proxyTransport}}
}
