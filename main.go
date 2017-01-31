package main

import (
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/uninett/goidc-proxy/conf"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
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
	if ssl {
		log.Fatal(http.ListenAndServeTLS(
			fmt.Sprintf(":%d", port),
			conf.GetStringValue("server.cert"),
			conf.GetStringValue("server.key"),
			nil))
	} else {
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
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
