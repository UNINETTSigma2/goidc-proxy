package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/uninett/goidc-proxy/conf"
)

var version = "none"
var startTime time.Time
var xhrEndpoints []string

func init() {
	// Log as JSON to stderr
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stderr)

	// Set up a version option, until we get a /healthz endpoint or
	// something similar
	showVersion := flag.Bool("version", false, "Prints version information and exits")
	configFile := flag.String("c", "goidc.json", "Use the specified `configfile`")
	flag.Parse()

	if *showVersion {
		fmt.Println("goidc-proxy version", version)
		os.Exit(0)
	}

	// Find config file
	err := conf.ReadConfig(*configFile)
	if err != nil {
		log.WithFields(log.Fields{
			"detail": err,
		}).Fatal("Could not read configuration")
	}

	// Set up correct log level
	lvl, err := log.ParseLevel(conf.GetStringValue("engine.logging.level"))
	if err != nil {
		log.WithFields(log.Fields{
			"detail": err,
		}).Warn("Could not parse log level, using default")
		log.SetLevel(log.WarnLevel)
	} else {
		log.SetLevel(lvl)
	}
}

func listenHTTP(ssl bool, port int) {
	srv := &http.Server{
		ReadTimeout:  time.Duration(conf.GetIntValue("server.readtimeout")) * time.Second,
		WriteTimeout: time.Duration(conf.GetIntValue("server.writetimeout")) * time.Second,
		IdleTimeout:  time.Duration(conf.GetIntValue("server.idletimeout")) * time.Second,
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      nil,
	}
	if ssl {
		// Taken from https://blog.gopheracademy.com/advent-2016/exposing-go-on-the-internet/
		tlsConfig := &tls.Config{
			// Causes servers to use Go's default ciphersuite preferences,
			// which are tuned to avoid attacks. Does nothing on clients.
			PreferServerCipherSuites: true,
			// Only use curves which have assembly implementations
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519, // Go 1.8 only
			},
		}
		srv.TLSConfig = tlsConfig
		log.Fatal(srv.ListenAndServeTLS(
			conf.GetStringValue("server.cert"),
			conf.GetStringValue("server.key")))
	} else {
		log.Fatal(srv.ListenAndServe())
	}
}

func handleAuth(upstream http.Handler, authenticators map[string]*Authenticator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		authn, found := authenticators[host]

		if found {
			authn.authHandler(upstream).ServeHTTP(w, r)
		} else {
			log.Errorf("Found no authenticator matching the host: %s. Maybe a redirect URL for this host is missing?", host)
			http.Error(w, "Failed to find authenicator for the requested host.", http.StatusInternalServerError)
		}
	})
}

func handleCallback(authenticators map[string]*Authenticator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		authn, found := authenticators[host]

		if found {
			authn.callbackHandler().ServeHTTP(w, r)
		} else {
			log.Errorf("Found no authenticator matching the host: %s. Maybe a redirect URL for this host is missing?", host)
			http.Error(w, "Failed to find authenicator for the requested host.", http.StatusInternalServerError)
		}
	})
}

func handleLogout(authenticators map[string]*Authenticator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		authn, found := authenticators[host]

		if found {
			authn.logoutHandler().ServeHTTP(w, r)
		} else {
			log.Errorf("Found no authenticator matching the host: %s. Maybe a redirect URL for this host is missing?", host)
			http.Error(w, "Failed to find authenicator for the requested host.", http.StatusInternalServerError)
		}
	})
}

func main() {
	// Get target/backend URL
	targetURL, err := url.Parse(conf.GetStringValue("proxy.target"))
	if err != nil {
		log.WithFields(log.Fields{
			"detail": err,
		}).Fatal("proxy.target is not a valid URL")
	}

	// Create a separate authenticator for each redirect URL, as this allows us to
	// use the same proxy for different hosts.
	authenticators := make(map[string]*Authenticator)
	for _, ru := range strings.Split(conf.GetStringValue("engine.redirect_url"), ",") {
		parsedRedirURL, err := url.Parse(ru)
		if err != nil {
			log.Fatalf("Invalid redirect URL: %s. Err: %s", ru, err)
			os.Exit(1)
		}

		authn, err := newAuthenticator(
			conf.GetStringValue("engine.client_id"),
			conf.GetStringValue("engine.client_secret"),
			ru,
			conf.GetStringValue("engine.issuer_url"))

		if err != nil {
			log.Fatalf("Failed in getting authenticator: %s", err)
			os.Exit(1)
		}

		authenticators[parsedRedirURL.Host] = authn
	}

	useReqHost := conf.GetBoolValue("engine.use_request_host") // Use the Host header of the original request
	upstream := NewUpstreamProxy(targetURL, authenticators, useReqHost)

	// Configure routes
	http.Handle("/healthz", healthzHandler(targetURL.String()))

	http.Handle("/oauth2/logout", handleLogout(authenticators))
	http.Handle("/oauth2/callback", handleCallback(authenticators))
	http.Handle("/", handleAuth(upstream, authenticators))

	// Get XHR Endpoints where we don't need to redirect
	// Let application handles the error itself
	if conf.GetStringValue("engine.xhr_endpoints") != "" {
		xhrEndpoints = strings.Split(conf.GetStringValue("engine.xhr_endpoints"), ",")
	}

	// Start proxying
	log.Println("Proxy initialized and listening on port", conf.GetIntValue("server.port"))
	startTime = time.Now()
	port := conf.GetIntValue("server.port")
	ssl := conf.GetBoolValue("server.ssl")
	go listenHTTP(ssl, port)

	// Start TCP server for health checks
	healthPort := conf.GetIntValue("server.health_port")
	server, err := net.Listen("tcp", fmt.Sprintf(":%d", healthPort))
	if server == nil {
		panic("couldn't set up tcp socket: " + err.Error())
	}
	conns := clientTCPConns(server)
	for {
		go handleTCPConn(<-conns, targetURL.String())
	}
}
