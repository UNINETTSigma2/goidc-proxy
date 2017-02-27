package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/uninett/goidc-proxy/conf"
)

var version = "none"
var startTime time.Time

func init() {
	// Log as JSON to stderr
	log.SetFormatter(&log.JSONFormatter{"2006-01-02T15:04:05.000Z07:00"})
	log.SetOutput(os.Stderr)

	// Find config file
	err := conf.ReadConfig("goidc")
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

func main() {

	// Set up a version option, until we get a /healthz endpoint or
	// something similar
	showVersion := flag.Bool("version", false, "Prints version information and exits")
	flag.Parse()
	if *showVersion {
		fmt.Println("goidc-proxy version", version)
		os.Exit(0)
	}

	// Get target/backend URL
	targetURL, err := url.Parse(conf.GetStringValue("proxy.target"))
	if err != nil {
		log.WithFields(log.Fields{
			"detail": err,
		}).Fatal("proxy.target is not a valid URL")
	}

	// Create proxy and middleware
	target := NewReverseProxy(targetURL)
	authn, err := newAuthenticator(
		conf.GetStringValue("engine.client_id"),
		conf.GetStringValue("engine.client_secret"),
		conf.GetStringValue("engine.redirect_url"),
		conf.GetStringValue("engine.issuer_url"))
	if err != nil {
		log.Fatal("Failed in getting authenticator", err)
		os.Exit(1)
	}

	// Configure routes
	http.Handle("/healthz", healthzHandler(targetURL.String()))
	http.Handle("/oauth2/callback", authn.callbackHandler())
	http.Handle("/", authn.authHandler(target))

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
